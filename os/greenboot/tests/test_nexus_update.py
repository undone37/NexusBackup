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
REPO = "ghcr.io/nexusbackup/appliance"

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
elif a[0] == "rollback":
    st["status"]["rollbackQueued"] = True
json.dump(st, open(os.path.join(d, "state.json"), "w"))
'''

LOGGER = '#!/bin/sh\necho "$(basename "$0") $*" >> "$FAKE_DIR/calls"\n'


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
        self.env = {
            "FAKE_DIR": str(self.d),
            "NEXUS_UPDATE_CONF": str(self.d / "none.conf"),
            "NEXUS_UPDATE_BOOTC": str(bootc),
            "NEXUS_UPDATE_NFT": str(self.d / "nft"),
            "NEXUS_UPDATE_SYSTEMCTL": str(self.d / "systemctl"),
            "NEXUS_UPDATE_DIR": str(self.d / "ctl"),
            "NEXUS_UPDATE_LOCK": str(self.d / "lock"),
            "NEXUS_UPDATE_EGRESS": "none",
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

    def test_bootc_failure_is_reported_not_raised(self):
        (self.d / "fail").touch()
        self.assertEqual(self.tick(), 1)
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

    def test_status_file_is_not_world_readable(self):
        self.tick()
        self.assertEqual((self.d / "ctl/status.json").stat().st_mode & 0o007, 0)


if __name__ == "__main__":
    unittest.main()
