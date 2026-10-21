"""Unit tests for /usr/libexec/nexus/nexus-update with fake bootc/nft/systemctl.

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

import datetime as dt
import importlib.machinery
import importlib.util
import json
import os
import sys

sys.dont_write_bytecode = True  # never leave __pycache__ in os/greenboot/usr (COPYed into the image)
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-update"
REPO = "ghcr.io/undone37/nexusbackup"

FAKE_BOOTC = r'''#!PYTHON
# Fake bootc: state in $FAKE_DIR/state.json, calls logged to $FAKE_DIR/calls.
import json, os, sys
d = os.environ["FAKE_DIR"]
open(os.path.join(d, "calls"), "a").write("bootc " + " ".join(sys.argv[1:]) + "\n")
st = json.load(open(os.path.join(d, "state.json")))
a = sys.argv[1:]
nxt = os.path.join(d, "next.json")  # what the registry would serve
def entry(img, sig, digest, version, download_only=False):
    return {"image": {"image": {"image": img, "transport": "registry", "signature": sig},
                      "imageDigest": digest, "version": version, "architecture": "amd64"},
            "downloadOnly": download_only}
if os.path.exists(os.path.join(d, "fail")):
    sys.exit("bootc: simulated failure")
if a[0] in ("switch", "upgrade") and os.path.exists(os.path.join(d, "fail-fetch")):
    sys.exit(open(os.path.join(d, "fail-fetch")).read())
af = os.environ.get("NEXUS_UPDATE_AUTHFILE", "")
if a[0] in ("switch", "upgrade") and af and os.path.exists(af):  # what a fetch would log in with
    open(os.path.join(d, "seen-auth.json"), "w").write(open(af).read())
if a[:2] == ["status", "--json"]:
    print(json.dumps(st)); sys.exit(0)
if a[0] == "switch":
    target = a[-1]
    st["spec"]["image"] = {"image": target, "transport": "registry",
                           "signature": "containerPolicy" if "--enforce-container-sigpolicy" in a else "insecure"}
    n = json.load(open(nxt)) if os.path.exists(nxt) else {"digest": st["status"]["booted"]["image"]["imageDigest"], "version": "1.0.0"}
    st["status"]["staged"] = entry(target, st["spec"]["image"]["signature"], n["digest"], n["version"])
elif a[0] == "upgrade" and "--download-only" in a:
    if os.path.exists(nxt):
        n = json.load(open(nxt)); sp = st["spec"]["image"]
        st["status"]["staged"] = entry(sp["image"], sp["signature"], n["digest"], n["version"], True)
elif a[0] == "upgrade" and "--from-downloaded" in a:
    pass  # would reboot
elif a[0] == "upgrade":  # plain upgrade: fetch and stage a normal deployment
    if os.path.exists(nxt):
        n = json.load(open(nxt)); sp = st["spec"]["image"]
        st["status"]["staged"] = entry(sp["image"], sp["signature"], n["digest"], n["version"])
elif a[0] == "rollback":
    st["status"]["rollbackQueued"] = True
json.dump(st, open(os.path.join(d, "state.json"), "w"))
'''

LOGGER = '#!/bin/sh\necho "$(basename "$0") $*" >> "$FAKE_DIR/calls"\n'

# Fake nexus-diag: prints $FAKE_DIR/checks.json (default: no checks), counts its runs.
FAKE_DIAG = r'''#!/bin/sh
echo "$*" >> "$FAKE_DIR/diag-calls"
[ -e "$FAKE_DIR/diag-crash" ] && { echo "Traceback: boom" >&2; exit 1; }
if [ -e "$FAKE_DIR/checks.json" ]; then cat "$FAKE_DIR/checks.json"; else echo "[]"; fi
'''


def load():
    loader = importlib.machinery.SourceFileLoader("nexus_update", str(SCRIPT))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


def utc(*a):
    return dt.datetime(*a, tzinfo=dt.timezone.utc)


class Window(unittest.TestCase):
    def setUp(self):
        self.u = load()

    def test_parse(self):
        self.assertEqual(self.u.parse_window("Sun 03:00 120"), ({6}, 180, 120))
        self.assertEqual(self.u.parse_window("mon,Thu 01:30 60"), ({0, 3}, 90, 60))
        self.assertEqual(self.u.parse_window("daily 23:00 90")[0], set(range(7)))
        self.assertIsNone(self.u.parse_window("off"))
        for bad in ("Sun 3 120", "Sun 25:00 10", "Xyz 03:00 10", "Sun 03:00 0", "Sun 03:00", "Sun 03:00 2000"):
            with self.assertRaises(self.u.Error, msg=bad):
                self.u.parse_window(bad)

    def test_in_window(self):
        w = self.u.parse_window("Sun 03:00 120")  # 2026-10-11 is a Sunday
        self.assertFalse(self.u.in_window(w, utc(2026, 10, 11, 2, 59)))
        self.assertTrue(self.u.in_window(w, utc(2026, 10, 11, 3, 0)))
        self.assertTrue(self.u.in_window(w, utc(2026, 10, 11, 4, 59)))
        self.assertFalse(self.u.in_window(w, utc(2026, 10, 11, 5, 0)))
        self.assertFalse(self.u.in_window(w, utc(2026, 10, 12, 3, 30)))
        self.assertFalse(self.u.in_window(None, utc(2026, 10, 11, 3, 30)))

    def test_window_across_midnight(self):
        w = self.u.parse_window("Sat 23:00 120")
        self.assertTrue(self.u.in_window(w, utc(2026, 10, 10, 23, 30)))
        self.assertTrue(self.u.in_window(w, utc(2026, 10, 11, 0, 59)))  # Sunday, started Saturday
        self.assertFalse(self.u.in_window(w, utc(2026, 10, 11, 1, 0)))

    def test_versions(self):
        p = self.u.parse_version
        self.assertLess(p("v1.2.3"), p("1.10.0"))
        self.assertEqual(p("1.2.3-rc1"), (1, 2, 3))
        self.assertIsNone(p("latest"))
        self.assertIsNone(p(None))


class Agent(unittest.TestCase):
    """tick() against a fake host."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        (self.d / "ctl").mkdir()
        bootc = self.d / "bootc"
        bootc.write_text(FAKE_BOOTC.replace("PYTHON", sys.executable))
        bootc.chmod(0o755)
        for t in ("nft", "systemctl"):
            (self.d / t).write_text(LOGGER)
            (self.d / t).chmod(0o755)
        (self.d / "nexus-diag").write_text(FAKE_DIAG)
        (self.d / "nexus-diag").chmod(0o755)
        self.env = {
            "FAKE_DIR": str(self.d),
            "NEXUS_UPDATE_CONF": str(self.d / "none.conf"),
            "NEXUS_UPDATE_BOOTC": str(bootc),
            "NEXUS_UPDATE_NFT": str(self.d / "nft"),
            "NEXUS_UPDATE_SYSTEMCTL": str(self.d / "systemctl"),
            "NEXUS_UPDATE_DIR": str(self.d / "ctl"),
            "NEXUS_UPDATE_LOCK": str(self.d / "lock"),
            "NEXUS_UPDATE_EGRESS": "none",
            "NEXUS_UPDATE_DIAG": str(self.d / "nexus-diag"),
            "NEXUS_UPDATE_AUTHFILE": str(self.d / "run-ostree/auth.json"),
            # only the first tick checks, unless a test says otherwise
            "NEXUS_UPDATE_CHECK_HOURS": "1000",
        }
        self._old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.u = load()
        self.host(signature="containerPolicy")

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def host(self, image=f"{REPO}:stable", signature="containerPolicy", digest="sha256:aaa", version="1.0.0"):
        booted = {"image": {"image": {"image": image, "transport": "registry", "signature": signature},
                            "imageDigest": digest, "version": version, "architecture": "amd64"}}
        st = {"spec": {"image": {"image": image, "transport": "registry", "signature": signature}},
              "status": {"booted": booted, "staged": None, "rollback": None, "rollbackQueued": False}}
        (self.d / "state.json").write_text(json.dumps(st))

    def registry_serves(self, digest, version):
        (self.d / "next.json").write_text(json.dumps({"digest": digest, "version": version}))

    def calls(self):
        p = self.d / "calls"
        lines = p.read_text().splitlines() if p.exists() else []
        p.unlink(missing_ok=True)
        return [l for l in lines if l != "bootc status --json"]

    def status(self):
        return json.loads((self.d / "ctl/status.json").read_text())

    def reboot_into(self, digest):
        st = json.loads((self.d / "state.json").read_text())
        st["status"]["booted"]["image"]["imageDigest"] = digest
        st["status"]["staged"] = None
        (self.d / "state.json").write_text(json.dumps(st))

    def tick(self, when=utc(2026, 10, 9, 12, 0)):  # a Friday, outside the default window
        c = self.u.load_conf()
        return self.u.tick(c, when)

    def test_unsigned_origin_is_switched_to_enforced_policy(self):
        self.host(signature="insecure")
        self.assertEqual(self.tick(), 0)
        self.assertEqual(self.calls(), [f"bootc switch --quiet --enforce-container-sigpolicy {REPO}:stable"])
        self.assertEqual(self.status()["spec_signature"], "containerPolicy")

    def test_foreign_origin_is_switched_to_configured_repo(self):
        self.host(image="quay.io/someone/else:latest")
        self.tick()
        self.assertIn(f"--enforce-container-sigpolicy {REPO}:stable", self.calls()[0])

    def test_enforced_origin_upgrades_download_only_and_does_not_reboot(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick()
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])
        s = self.status()
        self.assertEqual(s["staged"]["digest"], "sha256:bbb")
        self.assertTrue(s["staged"]["download_only"])
        self.assertIn("staged sha256:bbb", s["last_result"]["result"])

    def test_staged_update_lost_on_power_cut_is_staged_again(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick(utc(2026, 10, 9, 12, 0))
        self.calls()
        # power cut: the runtime-only staged deployment is gone, booted is unchanged
        st = json.loads((self.d / "state.json").read_text())
        st["status"]["staged"] = None
        (self.d / "state.json").write_text(json.dumps(st))
        self.tick(utc(2026, 10, 9, 12, 15))  # check interval (1000 h) not due
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])
        self.assertEqual(self.status()["staged"]["digest"], "sha256:bbb")
        self.tick(utc(2026, 10, 9, 12, 30))
        self.assertEqual(self.calls(), [], "nothing lost any more: no extra fetch")

    def test_private_registry_login_only_during_the_fetch(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick()
        self.assertFalse((self.d / "seen-auth.json").exists(), "no credential configured: no auth file")
        (self.d / "ctl/pull-auth.json").write_text(json.dumps({"username": "bot", "token": "ghp_x"}))
        self.registry_serves("sha256:ccc", "1.2.0")
        (self.d / "ctl/request").write_text("stage\n")
        self.tick()
        seen = json.loads((self.d / "seen-auth.json").read_text())
        self.assertEqual(seen, {"auths": {"ghcr.io": {"auth": "Ym90OmdocF94"}}})  # base64("bot:ghp_x")
        self.assertFalse((self.d / "run-ostree/auth.json").exists(), "removed after the fetch")

    def test_check_interval(self):
        os.environ["NEXUS_UPDATE_CHECK_HOURS"] = "24"
        self.tick(utc(2026, 10, 9, 12, 0))
        self.calls()
        self.tick(utc(2026, 10, 9, 12, 15))
        self.assertEqual(self.calls(), [])  # not due
        self.tick(utc(2026, 10, 10, 12, 0))
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])

    def test_applies_only_in_window(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick(utc(2026, 10, 9, 12, 0))
        self.calls()
        self.tick(utc(2026, 10, 11, 3, 30))  # Sunday 03:30
        self.assertEqual(self.calls(), ["bootc upgrade --from-downloaded --apply"])
        self.assertEqual(self.status()["applying"], "sha256:bbb")

    def test_window_override_and_off(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        (self.d / "ctl/window").write_text("off\n")
        self.tick(utc(2026, 10, 11, 3, 30))
        self.assertNotIn("bootc upgrade --from-downloaded --apply", self.calls())
        self.assertIsNone(self.status()["window"])
        (self.d / "ctl/window").write_text("Fri 12:00 30")
        self.tick(utc(2026, 10, 16, 12, 10))
        self.assertIn("bootc upgrade --from-downloaded --apply", self.calls())

    def test_broken_window_override_falls_back_to_default(self):
        (self.d / "ctl/window").write_text("garbage")
        self.tick()
        self.assertEqual(self.status()["window"]["days"], ["sun"])

    def test_inhibit_postpones_window_but_not_admin(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick()
        self.calls()
        (self.d / "ctl/inhibit").touch()
        t = utc(2026, 10, 11, 3, 0).timestamp()  # touched by the scheduler 30 min before the tick
        os.utime(self.d / "ctl/inhibit", (t, t))
        self.tick(utc(2026, 10, 11, 3, 30))
        self.assertEqual(self.calls(), [])
        self.assertTrue(self.status()["inhibited"])
        (self.d / "ctl/request").write_text("apply\n")
        self.tick(utc(2026, 10, 11, 3, 45))
        self.assertEqual(self.calls(), ["bootc upgrade --from-downloaded --apply"])
        self.assertFalse((self.d / "ctl/request").exists())

    def test_stale_inhibit_is_ignored(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick()
        self.calls()
        (self.d / "ctl/inhibit").touch()
        old = utc(2026, 10, 11, 3, 30).timestamp() - 7 * 3600
        os.utime(self.d / "ctl/inhibit", (old, old))
        self.tick(utc(2026, 10, 11, 3, 30))
        self.assertIn("bootc upgrade --from-downloaded --apply", self.calls())

    def test_request_stage_and_rollback(self):
        self.tick()
        self.calls()
        (self.d / "ctl/request").write_text("stage")
        self.tick(utc(2026, 10, 9, 12, 15))
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])
        (self.d / "ctl/request").write_text("rollback")
        self.tick(utc(2026, 10, 9, 12, 30))
        self.assertEqual(self.calls(), ["bootc rollback", "systemctl reboot"])

    def test_unknown_or_symlinked_request_ignored(self):
        self.tick()
        self.calls()
        (self.d / "ctl/request").write_text("rm -rf /")
        self.tick(utc(2026, 10, 9, 12, 15))
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.d / "ctl/request").exists())
        (self.d / "target").write_text("apply")
        (self.d / "ctl/request").symlink_to(self.d / "target")
        self.tick(utc(2026, 10, 9, 12, 30))
        self.assertEqual(self.calls(), [])

    def test_apply_request_stages_and_installs_now(self):
        self.tick()  # up to date
        self.calls()
        self.registry_serves("sha256:bbb", "1.1.0")
        (self.d / "ctl/request").write_text("apply\n")
        self.tick(utc(2026, 10, 9, 13, 0))  # outside the window, check interval not due
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only", "bootc upgrade --from-downloaded --apply"])
        self.assertEqual(self.status()["applying"], "sha256:bbb")

    def test_nothing_staged_apply_is_noop(self):
        (self.d / "ctl/request").write_text("apply")
        self.tick()
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])
        self.assertEqual(self.status()["last_result"]["result"], "nothing staged")

    def test_rolled_back_update_is_not_applied_again(self):
        self.registry_serves("sha256:bad", "1.1.0")
        self.tick()
        self.tick(utc(2026, 10, 11, 3, 30))  # applied, "reboots"
        self.calls()
        # greenboot rolled back: we are still on aaa after the reboot
        self.reboot_into("sha256:aaa")
        self.tick(utc(2026, 10, 11, 4, 0))
        s = self.status()
        self.assertIn("sha256:bad", s["failed_digests"])
        self.assertEqual(s["last_result"]["result"], "rolled back from sha256:bad")
        # the next check stages the same digest again (tag unchanged); window still open
        (self.d / "ctl/request").write_text("stage")
        self.tick(utc(2026, 10, 11, 4, 15))
        self.assertNotIn("bootc upgrade --from-downloaded --apply", self.calls())
        self.assertIn("rolled back before", self.status()["last_result"]["result"])
        # an admin can still force it
        (self.d / "ctl/request").write_text("apply")
        self.tick(utc(2026, 10, 11, 4, 15))
        self.assertIn("bootc upgrade --from-downloaded --apply", self.calls())

    def test_successful_update_clears_applying(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick()
        self.tick(utc(2026, 10, 11, 3, 30))
        self.reboot_into("sha256:bbb")
        (self.d / "next.json").unlink()
        self.tick(utc(2026, 10, 11, 3, 45))
        s = self.status()
        self.assertIsNone(s["applying"])
        self.assertEqual(s["failed_digests"], [])

    def test_older_version_not_applied_automatically(self):
        self.registry_serves("sha256:old", "0.9.0")
        self.tick()
        self.tick(utc(2026, 10, 11, 3, 30))
        self.assertNotIn("bootc upgrade --from-downloaded --apply", self.calls())
        self.assertIn("older", self.status()["last_result"]["result"])

    def test_wrong_key_on_the_registry_is_explained(self):
        pol = {"transports": {"docker": {REPO: [{"type": "sigstoreSigned", "keyPaths": ["/etc/pki/nexus/cosign/TEST-KEY-DO-NOT-SHIP.pub"]}]}}}
        (self.d / "policy.json").write_text(json.dumps(pol))
        os.environ["NEXUS_UPDATE_POLICY"] = str(self.d / "policy.json")
        try:
            (self.d / "fail-fetch").write_text("error: Fetching manifest: failed to invoke method OpenImage: cryptographic "
                                         "signature verification failed: invalid signature when validating ASN.1 encoded signature")
            (self.d / "ctl/request").write_text("stage")
            self.tick()
            err = self.status()["api"]["error"]
            self.assertIn("is not signed with a key this appliance trusts (pinned: TEST-KEY-DO-NOT-SHIP.pub)", err)
        finally:
            os.environ.pop("NEXUS_UPDATE_POLICY", None)

    def test_bootc_failure_is_reported_not_raised(self):
        (self.d / "fail").touch()
        self.assertEqual(self.tick(), 0, "reported in status.json, not a failed unit")
        self.assertIn("simulated failure", json.loads((self.d / "ctl/status.json").read_text())["last_result"]["result"])

    def test_egress_opened_and_closed(self):
        os.environ["NEXUS_UPDATE_EGRESS"] = "nft"
        os.environ["NEXUS_UPDATE_HOSTS"] = "localhost"
        try:
            self.tick()
        finally:
            os.environ["NEXUS_UPDATE_EGRESS"] = "none"
            os.environ.pop("NEXUS_UPDATE_HOSTS")
        c = self.calls()
        adds = [l for l in c if l.startswith("nft create element")]
        dels = [l for l in c if l.startswith("nft delete element")]
        self.assertTrue(adds)
        self.assertEqual([a.split(" ", 3)[3] for a in adds], [d.split(" ", 3)[3] for d in dels])
        self.assertTrue(any("127.0.0.1 . tcp . 443" in a for a in adds))
        i = c.index("bootc upgrade --quiet --download-only")
        self.assertTrue(c.index(adds[0]) < i < c.index(dels[0]))

    def test_api_view_for_the_web_ui(self):
        self.tick()
        a = self.status()["api"]
        self.assertEqual(a["status"], "idle")
        self.assertEqual(a["booted"]["digest"], "sha256:aaa")
        self.assertEqual(a["booted"]["version"], "1.0.0")
        self.assertIsNone(a["staged"])
        self.assertIsNone(a["available"])
        self.assertEqual(a["channel"], "stable")
        self.assertEqual(a["window"], "Sun 03:00 120")
        self.assertIsInstance(a["last_check"], int)
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick(utc(2026, 10, 9, 12, 0) + dt.timedelta(days=50))
        a = self.status()["api"]
        self.assertEqual(a["status"], "staged")
        self.assertEqual(a["staged"]["digest"], "sha256:bbb")
        self.assertEqual(a["available"], {"version": "1.1.0", "digest": "sha256:bbb"})
        (self.d / "fail").touch()
        self.tick(utc(2026, 10, 9, 12, 0) + dt.timedelta(days=100))
        a = self.status()["api"]
        self.assertEqual(a["status"], "error")
        self.assertIn("simulated failure", a["error"])

    def test_status_json_command(self):
        import contextlib
        import io

        self.tick()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.u.main(["nexus-update", "status", "--json"]), 0)
        a = json.loads(out.getvalue())
        self.assertEqual(a["status"], "idle")
        self.assertEqual(a["window"], "Sun 03:00 120")
        self.assertEqual(a["channel"], "stable")
        self.assertEqual(self.u.main(["nexus-update", "tick", "--json"]), 2)
        self.assertEqual(self.u.window_text({"days": ["mon", "thu"], "start_utc": "01:30", "minutes": 60}), "Mon,Thu 01:30 60")
        self.assertEqual(self.u.epoch("2026-10-11T00:00:00Z"), 1791676800)
        self.assertIsNone(self.u.epoch("garbage"))

    # ------------------------------------------------------------ pre-update checks (14b)

    def checks(self, *failing, severity=3):
        cs = [{"id": "selinux", "title": "SELinux mode", "status": "pass", "severity": 1, "detail": "enforcing",
               "manual": "15-troubleshooting-faq.md#check-selinux"}]
        cs += [{"id": i, "title": i, "status": "fail", "severity": severity, "detail": f"{i} is broken",
                "manual": f"15-troubleshooting-faq.md#check-{i.replace('.', '-')}"} for i in failing]
        (self.d / "checks.json").write_text(json.dumps(cs))

    def diag_runs(self):
        p = self.d / "diag-calls"
        n = len(p.read_text().splitlines()) if p.exists() else 0
        p.unlink(missing_ok=True)
        return n

    def test_failing_check_refuses_staging(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.checks("disk.var", "time.sync")
        self.assertEqual(self.tick(), 0, "a refusal is not a failed unit (that would block the next check)")
        self.assertEqual(self.calls(), [])
        s = self.status()
        self.assertTrue(s["last_result"]["result"].startswith("refused: pre-update checks failed: disk.var: disk.var is broken"))
        a = s["api"]
        self.assertEqual((a["status"], a["error"]), ("blocked", None))
        self.assertEqual([b["id"] for b in a["blocked"]], ["disk.var", "time.sync"])
        self.assertEqual(a["blocked"][0]["manual"], "15-troubleshooting-faq.md#check-disk-var")
        # fixed: the next check stages, the block is gone
        self.checks()
        (self.d / "ctl/request").write_text("stage")
        self.tick(utc(2026, 10, 9, 12, 15))
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])
        a = self.status()["api"]
        self.assertEqual((a["status"], a["blocked"]), ("staged", []))

    def test_warnings_do_not_block(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.checks("tls.cert", severity=2)
        self.tick()
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])

    def test_failing_check_refuses_apply_in_window_and_on_request(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.tick()
        self.calls()
        self.checks("catalog.integrity", severity=4)
        self.tick(utc(2026, 10, 11, 3, 30))  # window open, staged
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.status()["api"]["status"], "blocked")
        self.assertIsNone(self.status()["applying"])
        (self.d / "ctl/request").write_text("apply")
        self.tick(utc(2026, 10, 11, 3, 45))
        self.assertEqual(self.calls(), [])
        # rollback is recovery: never gated
        (self.d / "ctl/request").write_text("rollback")
        self.tick(utc(2026, 10, 11, 4, 0))
        self.assertEqual(self.calls(), ["bootc rollback", "systemctl reboot"])

    def test_checks_run_once_per_tick_and_only_when_needed(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        (self.d / "ctl/request").write_text("apply")
        self.tick()  # stage + apply in one tick
        self.assertEqual(self.diag_runs(), 1)
        self.reboot_into("sha256:bbb")
        (self.d / "next.json").unlink()
        self.tick(utc(2026, 10, 9, 12, 15))  # nothing due
        self.assertEqual(self.diag_runs(), 0)

    def test_broken_checker_fails_open(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        (self.d / "diag-crash").touch()
        self.tick()
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])
        self.assertIn("boom", self.status()["checks"]["error"])
        os.environ["NEXUS_UPDATE_DIAG"] = str(self.d / "missing")
        try:
            (self.d / "ctl/request").write_text("stage")
            self.tick(utc(2026, 10, 9, 12, 15))
            self.assertEqual(self.status()["checks"]["blocking"], [])
        finally:
            os.environ["NEXUS_UPDATE_DIAG"] = str(self.d / "nexus-diag")

    def test_checks_off(self):
        self.registry_serves("sha256:bbb", "1.1.0")
        self.checks("selinux.x")
        os.environ["NEXUS_UPDATE_DIAG"] = "off"
        try:
            self.tick()
        finally:
            os.environ["NEXUS_UPDATE_DIAG"] = str(self.d / "nexus-diag")
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])
        self.assertEqual(self.diag_runs(), 0)

    def test_console_commands_run_the_checks(self):
        import contextlib
        import io

        self.registry_serves("sha256:bbb", "1.1.0")
        self.checks("disk.root")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.u.main(["nexus-update", "stage"]), 1)
        self.assertIn("pre-update checks failed: disk.root", err.getvalue())
        self.assertEqual(self.calls(), [])
        self.checks()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.u.main(["nexus-update", "stage"]), 0)
        self.assertEqual(self.calls(), ["bootc upgrade --quiet --download-only"])

    def test_status_file_is_not_world_readable(self):
        self.tick()
        self.assertEqual((self.d / "ctl/status.json").stat().st_mode & 0o007, 0)



class Offline(Agent):
    """The uploaded bundle (request "import"): signature, digest, identity, version, refusals."""

    def setUp(self):
        super().setUp()
        import subprocess
        self.sp = subprocess
        self.key = self.d / "key.pem"
        self.pub = self.d / "pub.pem"
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.key)], check=True)
        subprocess.run(["openssl", "ec", "-in", str(self.key), "-pubout", "-out", str(self.pub)], check=True, capture_output=True)
        pol = {"default": [{"type": "reject"}], "transports": {"docker": {REPO: [
            {"type": "sigstoreSigned", "keyPaths": [str(self.pub)], "signedIdentity": {"type": "matchRepository"}}]}}}
        (self.d / "policy.json").write_text(json.dumps(pol))
        os.environ["NEXUS_UPDATE_POLICY"] = str(self.d / "policy.json")
        os.environ["NEXUS_UPDATE_OFFLINE_DIR"] = str(self.d / "offline")
        self.env.update({"NEXUS_UPDATE_POLICY": "", "NEXUS_UPDATE_OFFLINE_DIR": ""})  # restored by tearDown

    def tearDown(self):
        for k in ("NEXUS_UPDATE_POLICY", "NEXUS_UPDATE_OFFLINE_DIR"):
            os.environ.pop(k, None)
        super().tearDown()

    def bundle(self, version="1.1.0", identity=REPO, key=None, mutate=None):
        """Writes ctl/bundle.tar; returns the image's manifest digest."""
        import hashlib, io, tarfile
        files = {}
        def blob(b):
            h = hashlib.sha256(b).hexdigest()
            files[f"image/blobs/sha256/{h}"] = b
            return "sha256:" + h
        cfg = blob(json.dumps({"config": {"Labels": {"org.opencontainers.image.version": version}}}).encode())
        layer = blob(b"layer")
        man = blob(json.dumps({"schemaVersion": 2, "config": {"digest": cfg}, "layers": [{"digest": layer}]}).encode())
        files["image/oci-layout"] = b'{"imageLayoutVersion": "1.0.0"}'
        files["image/index.json"] = json.dumps({"schemaVersion": 2, "manifests": [
            {"digest": man, "annotations": {"org.opencontainers.image.ref.name": "nexus"}}]}).encode()
        payload = json.dumps({"critical": {"identity": {"docker-reference": identity}, "image": {"docker-manifest-digest": man},
                                           "type": "cosign container image signature"}, "optional": None}).encode()
        files["signature/payload.json"] = payload
        (self.d / "payload").write_bytes(payload)
        der = self.sp.run(["openssl", "dgst", "-sha256", "-sign", str(key or self.key), str(self.d / "payload")],
                          check=True, capture_output=True).stdout
        import base64
        files["signature/payload.sig"] = base64.b64encode(der)
        files["bundle.json"] = json.dumps({"format": 1, "repository": REPO, "version": version, "digest": man}).encode()
        if mutate:
            mutate(files)
        sums = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in sorted(files.items()) if n != "SHA256SUMS")
        files.setdefault("SHA256SUMS", sums.encode())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for n, b in files.items():
                ti = tarfile.TarInfo(n)
                ti.size = len(b)
                t.addfile(ti, io.BytesIO(b))
        (self.d / "ctl/bundle.tar").write_bytes(buf.getvalue())
        self.registry_serves(man, version)  # what the fake bootc reports as staged after the switch
        return man

    def imp(self):
        (self.d / "ctl/request").write_text("import")
        self.tick()
        return self.status()["last_result"]["result"]

    def test_valid_bundle_is_verified_and_staged_from_the_offline_dir(self):
        man = self.bundle()
        self.assertIn("from the uploaded bundle", self.imp())
        calls = self.calls()
        self.assertEqual(calls, [f"bootc switch --quiet --transport oci {self.d}/offline/current/image:nexus"])
        st = self.status()
        self.assertEqual((st["offline"]["version"], st["offline"]["digest"]), ("1.1.0", man))
        self.assertEqual(st["api"]["offline"]["key"], "pub.pem")
        self.assertFalse((self.d / "ctl/bundle.tar").exists(), "the upload is moved out of the web-api's directory")
        self.assertFalse((self.d / "offline/bundle.tar").exists(), "the tar is deleted after unpacking")
        self.assertEqual((self.d / "offline").stat().st_mode & 0o077, 0)

    def test_apply_leaves_a_web_view_for_the_time_after_the_reboot(self):
        self.bundle()
        self.imp()
        (self.d / "ctl/request").write_text("apply")
        c = self.u.load_conf()
        st = self.u.read_status(c)
        self.u.apply(c, st, force=True)  # reboots (fake systemctl): no tick writes status.json afterwards
        api = json.loads((self.d / "ctl/status.json").read_text())["api"]
        self.assertEqual((api["booted"]["version"], api["applying"]), ("1.0.0", api["staged"]["digest"]))

    def test_second_bundle_upgrades_from_the_same_offline_origin(self):
        self.host(image=f"{self.d}/offline/current/image:nexus", signature="insecure")
        self.bundle(version="1.2.0")
        self.assertIn("from the uploaded bundle", self.imp())
        self.assertEqual(self.calls(), ["bootc upgrade --quiet"], "switch to the same origin would do nothing")

    def test_offline_mode_skips_automatic_online_checks_until_check_now(self):
        self.bundle()
        self.imp()
        self.calls()
        os.environ["NEXUS_UPDATE_CHECK_HOURS"] = "0"  # a check would be due every tick
        self.tick()
        self.assertEqual(self.calls(), [], "no online check while the appliance is updated offline")
        (self.d / "ctl/request").write_text("stage")  # Check now
        self.tick()
        self.assertTrue(any("--enforce-container-sigpolicy" in c or "upgrade" in c for c in self.calls()))
        self.assertIsNone(self.status()["offline"])

    def refused(self, why):
        r = self.imp()
        self.assertTrue(r.startswith("refused:"), r)
        self.assertIn(why, r)
        self.assertEqual(self.status()["api"]["status"], "refused")
        self.assertEqual(self.calls(), [], "nothing staged")
        self.assertFalse((self.d / "offline/current").exists())

    def test_import_refused_by_the_checks_discards_the_upload(self):
        self.bundle()
        (self.d / "checks.json").write_text(json.dumps([{"id": "time.sync", "title": "t", "status": "fail", "severity": 3,
                                                          "detail": "clock not synchronised", "manual": "x"}]))
        self.assertIn("pre-update checks failed", self.imp())
        self.assertFalse((self.d / "ctl/bundle.tar").exists(), "a new upload must be possible")
        self.assertEqual(self.calls(), [])
        (self.d / "checks.json").unlink()
        self.bundle()
        self.assertIn("from the uploaded bundle", self.imp())

    def test_wrong_key_refused(self):
        other = self.d / "other.pem"
        self.sp.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(other)], check=True)
        self.bundle(key=other)
        self.refused("does not verify with any pinned release key")

    def test_other_repository_signed_refused(self):
        self.bundle(identity="ghcr.io/evil/nexusbackup")
        self.refused("not an image signature for")

    def test_tag_in_the_signed_identity_is_fine(self):
        self.bundle(identity=f"{REPO}:0.2.0")
        self.assertIn("from the uploaded bundle", self.imp())

    def test_swapped_image_refused(self):
        def swap(files):  # another manifest behind the same signature
            idx = json.loads(files["image/index.json"])
            idx["manifests"][0]["digest"] = "sha256:" + "0" * 64
            files["image/index.json"] = json.dumps(idx).encode()
        self.bundle(mutate=swap)
        self.refused("the signed digest is not the bundle's image")

    def test_truncated_or_modified_file_refused(self):
        def cut(files):
            n = next(k for k in files if k.startswith("image/blobs/"))
            sums = "".join(f"{__import__('hashlib').sha256(b).hexdigest()}  {k}\n" for k, b in sorted(files.items()))
            files["SHA256SUMS"] = sums.encode()
            files[n] = files[n][:-1]  # changed after the checksums were taken
        self.bundle(mutate=cut)
        self.refused("checksum mismatch")

    def test_older_version_refused(self):
        self.bundle(version="0.9.0")
        self.refused("older than the booted 1.0.0")

    def test_not_a_tar_refused(self):
        (self.d / "ctl/bundle.tar").write_bytes(b"garbage")
        self.refused("cannot unpack the bundle")

    def test_symlinked_upload_refused(self):
        target = self.d / "elsewhere"
        target.write_bytes(b"x")
        (self.d / "ctl/bundle.tar").symlink_to(target)
        r = self.imp()
        self.assertTrue(r.startswith("error: no uploaded bundle"), r)


if __name__ == "__main__":
    unittest.main()
