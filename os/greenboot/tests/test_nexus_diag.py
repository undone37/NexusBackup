"""Unit tests for /usr/libexec/nexus/nexus-diag: redaction, checks against fake tools,
the request / result protocol with the web-api and the support bundle.

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

import importlib.machinery
import importlib.util
import json
import os
import sqlite3
import sys

sys.dont_write_bytecode = True  # never leave __pycache__ in os/greenboot/usr (COPYed into the image)
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-diag"
HEALTH = HERE.parent / "usr/libexec/nexus/nexus-health"

# Fake tool: answers from $FAKE_DIR/answers.json {"<tool> <args...>": [exit, stdout]}, longest
# matching prefix wins; unknown calls exit 0 with no output. Calls are logged.
FAKE = r'''#!PYTHON
import json, os, sys
d = os.environ["FAKE_DIR"]
tool = os.path.basename(sys.argv[0])
line = " ".join([tool] + sys.argv[1:])
open(os.path.join(d, "calls"), "a").write(line + "\n")
answers = json.load(open(os.path.join(d, "answers.json")))
best = max((k for k in answers if line == k or line.startswith(k + " ")), key=len, default=None)
rc, out = answers[best] if best else (0, "")
sys.stdout.write(out)
sys.exit(rc)
'''

TRACKING_OK = "C0A80001,192.168.0.1,2,1760000000.0,0.000012,0.000001,0.000010,1.0,0.0,0.1,0.01,0.001,64.0,Normal\n"
TRACKING_BAD = "00000000,0.0.0.0,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,1.0,0.0,Not synchronised\n"
AUTH_OK = "time.cloudflare.com,162.159.200.1,NTS,1,15,256,33,0,0,0\nptbtime1.ptb.de,192.53.103.108,NTS,1,15,256,33,0,0,0\n"


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


def self_signed(path, days):
    """A certificate with notAfter = now + days (openssl; skipped if missing)."""
    import shutil
    import subprocess

    if not shutil.which("openssl"):
        raise unittest.SkipTest("openssl not installed")
    key = str(path) + ".key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", key, "-out", str(path), "-subj", "/CN=nexus", "-days", str(days)],
        check=True, capture_output=True,
    )


class Redact(unittest.TestCase):
    def setUp(self):
        self.r = load("nexus_diag", SCRIPT).redact

    def test_pem_blocks(self):
        t = "a\n-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----\nb\n-----BEGIN CERTIFICATE-----\nMIIB\n"
        out = self.r(t)
        self.assertNotIn("MIGH", out)
        self.assertNotIn("MIIB", out)  # unterminated block: redacted to the end
        self.assertIn("[REDACTED PEM PRIVATE KEY]", out)
        self.assertTrue(out.startswith("a\n") and "\nb\n" in out)

    def test_headers_and_tokens(self):
        cases = [
            ("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abc.def", "eyJhbGci"),
            ("curl -H 'authorization: Basic dXNlcjpwYXNzd29yZA=='", "dXNlcjpw"),
            ("Cookie: nx_session=0123456789abcdef; other=1", "0123456789abcdef"),
            ("token nxt_AbCdEf0123456789xyz used", "nxt_AbCdEf"),
            ("GET /api/v1/downloads/" + "ab" * 32 + " 200", "ab" * 32),
            ("otpauth://totp/nexus:alice?secret=JBSWY3DPEHPK3PXP&issuer=nexus", "JBSWY3DPEHPK3PXP"),
            ("remote sftp://backup:s3cr3t-pw@box.example.com/x", "s3cr3t-pw"),
        ]
        for text, secret in cases:
            out = self.r(text)
            self.assertNotIn(secret, out, text)
            self.assertIn("REDACTED", out, text)

    def test_key_value_and_json(self):
        cases = [
            ('{"password": "hunter2", "name": "alice"}', "hunter2"),
            ('{"smtp": {"password_hash": "$argon2id$v=19$abc"}}', "argon2id"),
            ('{"totp_secret": "JBSWY3DP", "x": 1}', "JBSWY3DP"),
            ('{"client_secret":"abc def","n":1}', "abc def"),
            ('"api_token": 12345678', "12345678"),
            ("connect password=hunter2 user=x", "hunter2"),
            ("S3 access_key=AKIAIOSFODNN7EXAMPLE secret_key='wJalrXUtnFEMI/K7MDENG'", "wJalrXUtnFEMI"),
            ("--password hunter2 --verbose", "hunter2"),
            ("x-amz-security-token: FQoGZXIvYXdzEJr", "FQoGZXIv"),
        ]
        for text, secret in cases:
            out = self.r(text)
            self.assertNotIn(secret, out, text)

    def test_keeps_what_support_needs(self):
        keep = [
            "nexus-out-drop: IN= OUT=eth0 SRC=192.168.10.5 DST=203.0.113.7 PROTO=TCP DPT=443",
            "fe80::1 2001:db8::5 pve1.example.com",
            "staged sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "nexus-audit seq=12 actor=alice action=auth.login target=- hash=" + "ab" * 32,
            '{"spec_signature": "containerPolicy", "keyd_pub": "00ff"}',
            "user alice signed in from 10.0.0.8",
            "auth: login failed for bob (bad code), tokens issued: 3",
        ]
        for text in keep:
            self.assertEqual(self.r(text), text)

    def test_idempotent(self):
        t = 'Authorization: Bearer abcdefgh12345\n{"password": "x"} password=y\n-----BEGIN RSA PRIVATE KEY-----\nQ\n-----END RSA PRIVATE KEY-----'
        once = self.r(t)
        self.assertEqual(self.r(once), once)


class Host(unittest.TestCase):
    """A fake appliance: tools, files, catalog."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        (self.d / "diag").mkdir()
        (self.d / "store").mkdir()
        bin_ = self.d / "bin"
        bin_.mkdir()
        for t in ("chronyc", "nft", "systemctl", "journalctl", "ausearch"):
            (bin_ / t).write_text(FAKE.replace("PYTHON", sys.executable))
            (bin_ / t).chmod(0o755)
        self.answers = {
            "chronyc -c -n tracking": [0, TRACKING_OK],
            "chronyc -c -n authdata": [0, AUTH_OK],
            "systemctl list-units --failed": [0, ""],
            "journalctl": [0, "2026-10-12T10:00:00.000000+00:00 nexus nexus-web-api[1]: login password=hunter2\n"],
        }
        self.save()
        sock = self.d / "keyd.sock"
        import socket

        self._sock = socket.socket(socket.AF_UNIX)
        self._sock.bind(str(sock))
        (self.d / "setup-done").write_text("")
        (self.d / "enforce").write_text("1")
        (self.d / "update.json").write_text(json.dumps({
            "booted": {"version": "1.0.0", "digest": "sha256:aaa"}, "staged": None,
            "rollback": {"version": "0.9.0", "digest": "sha256:999"}, "spec_signature": "containerPolicy",
        }))
        self.catalog()
        self.env = {
            "FAKE_DIR": str(self.d),
            "NEXUS_DIAG_DIR": str(self.d / "diag"),
            "NEXUS_DIAG_SETUP_DONE": str(self.d / "setup-done"),
            "NEXUS_DIAG_CATALOG": str(self.d / "catalog.db"),
            "NEXUS_DIAG_UPDATE_STATUS": str(self.d / "update.json"),
            "NEXUS_DIAG_KEYD_SOCKET": str(sock),
            "NEXUS_DIAG_TLS_CERT": str(self.d / "cert.pem"),
            "NEXUS_DIAG_SELINUX_ENFORCE": str(self.d / "enforce"),
            "NEXUS_DIAG_DISKS": f"store={self.d / 'store'} var={self.d}",
            "NEXUS_DIAG_HEALTH": str(HEALTH),
            "NEXUS_DIAG_DISKS_STATUS": str(self.d / "disks.json"),
            # the temp dirs live on the build host's disk (a CI runner may be > 90 % full)
            "NEXUS_DIAG_DISK_WARN_PCT": "101",
            "NEXUS_DIAG_DISK_FAIL_PCT": "101",
            **{f"NEXUS_DIAG_{t.upper()}": str(bin_ / t) for t in ("chronyc", "nft", "systemctl", "journalctl", "ausearch")},
        }
        self._old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.m = load("nexus_diag", SCRIPT)

    def tearDown(self):
        self._sock.close()
        if getattr(self, "_db", None):
            self._db.close()
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def save(self):
        (self.d / "answers.json").write_text(json.dumps(self.answers))

    def catalog(self):
        """WAL catalog with an intact audit chain, held open like the web-api does."""
        h = load("nexus_health", HEALTH)
        self._db = db = sqlite3.connect(self.d / "catalog.db")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE audit (seq INTEGER PRIMARY KEY, ts INTEGER, actor TEXT, action TEXT, target TEXT, details TEXT, prev_hash TEXT, hash TEXT)")
        db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password_hash TEXT)")
        db.execute("INSERT INTO users (name, password_hash) VALUES ('alice', '$argon2id$secret')")
        prev = "0" * 64
        for seq, action in enumerate(["setup.init", "auth.login", "auth.login"], 1):
            hsh = h.chain_hash(prev, seq, 1000 + seq, "alice", action, "-", "{}")
            db.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?,?)", (seq, 1000 + seq, "alice", action, "-", "{}", prev, hsh))
            prev = hsh
        db.commit()

    def by_id(self, cs):
        return {c["id"]: c for c in cs}

    def calls(self):
        p = self.d / "calls"
        return p.read_text().splitlines() if p.exists() else []


class Checks(Host):
    def test_healthy_host(self):
        self_signed(self.d / "cert.pem", 365)
        cs = self.by_id(self.m.checks())
        self.assertEqual(
            sorted(cs),
            sorted(["disk.store", "disk.var", "time.sync", "time.nts", "egress", "keyd", "tls.cert", "audit.chain",
                    "catalog.integrity", "selinux", "systemd.failed", "bootc", "smart"]),
        )
        for cid, c in cs.items():
            want = "skip" if cid == "smart" else "pass"
            self.assertEqual(c["status"], want, c)
            self.assertEqual(c["severity"], 1)
            self.assertEqual(c["manual"], "15-troubleshooting-faq.md#check-" + cid.replace(".", "-"))
        self.assertIn("3 entries", cs["audit.chain"]["detail"])
        self.assertIn("rollback 0.9.0", cs["bootc"]["detail"])
        self.assertEqual(self.m.blocking(list(cs.values())), [])
        # the catalog is never written: no new rows, the open writer still works
        self._db.execute("INSERT INTO users (name) VALUES ('bob')")
        self._db.commit()

    def test_failures_and_severities(self):
        self_signed(self.d / "cert.pem", 10)
        self.answers.update({
            "chronyc -c -n tracking": [0, TRACKING_BAD],
            "chronyc -c -n authdata": [0, "pool.example,1.2.3.4,-,0,0,0,0,0,0,0\n"],
            "nft list set inet nexus allowed_out_v6": [1, ""],
            "systemctl is-active --quiet nexus-keyd.service": [3, ""],
            "systemctl list-units --failed": [0, "nexus-scheduler.service loaded failed failed NexusBackup scheduler\n"],
        })
        self.save()
        (self.d / "enforce").write_text("0")
        self._db.execute("UPDATE audit SET actor = 'mallory' WHERE seq = 2")
        self._db.commit()
        cs = self.by_id(self.m.checks())
        expect = {
            "time.sync": ("fail", 3),
            "time.nts": ("warn", 2),
            "egress": ("fail", 3),
            "keyd": ("fail", 4),
            "tls.cert": ("warn", 2),
            "audit.chain": ("fail", 4),
            "selinux": ("fail", 4),
            "systemd.failed": ("fail", 3),
        }
        for cid, (status, sev) in expect.items():
            self.assertEqual((cs[cid]["status"], cs[cid]["severity"]), (status, sev), cs[cid])
        self.assertIn("seq 2", cs["audit.chain"]["detail"])
        self.assertIn("allowed_out_v6", cs["egress"]["detail"])
        self.assertEqual(
            sorted(c["id"] for c in self.m.blocking(list(cs.values()))),
            ["audit.chain", "egress", "keyd", "selinux", "systemd.failed", "time.sync"],
        )

    def test_disk_thresholds(self):
        os.environ["NEXUS_DIAG_DISK_WARN_PCT"] = "0"
        try:
            self.assertEqual(self.by_id(self.m.checks())["disk.var"]["status"], "warn")
            os.environ["NEXUS_DIAG_DISK_FAIL_PCT"] = "0"
            c = self.by_id(self.m.checks())["disk.var"]
            self.assertEqual((c["status"], c["severity"]), ("fail", 3))
        finally:
            os.environ["NEXUS_DIAG_DISK_WARN_PCT"] = os.environ["NEXUS_DIAG_DISK_FAIL_PCT"] = "101"

    def test_disk_health_from_nexus_disks(self):
        ok = {"scanned": int(time.time()), "disks": [
            {"name": "sda", "smart": {"available": True, "health": "passed", "pending": 0}},
            {"name": "vdb", "smart": {"available": False}}],
            "arrays": [{"name": "md127", "state": "clean", "degraded": False}]}
        (self.d / "disks.json").write_text(json.dumps(ok))
        c = self.by_id(self.m.checks())["smart"]
        self.assertEqual((c["status"], c["detail"]), ("pass", "2 disk(s), 1 with SMART, 1 array(s) healthy"))
        ok["disks"][0]["smart"]["pending"] = 8
        ok["arrays"][0].update(state="recovering", degraded=True)
        (self.d / "disks.json").write_text(json.dumps(ok))
        c = self.by_id(self.m.checks())["smart"]
        self.assertEqual((c["status"], c["severity"]), ("warn", 2))
        self.assertIn("degraded array(s): md127", c["detail"])
        self.assertIn("bad sectors or media errors on: sda", c["detail"])
        ok["disks"][0]["smart"]["health"] = "failed"
        (self.d / "disks.json").write_text(json.dumps(ok))
        c = self.by_id(self.m.checks())["smart"]
        self.assertEqual((c["status"], c["severity"]), ("fail", 3))
        ok["scanned"] = 0
        (self.d / "disks.json").write_text(json.dumps(ok))
        self.assertIn("nexus-disks.timer", self.by_id(self.m.checks())["smart"]["detail"])

    def test_missing_tools_and_files_skip(self):
        for k in ("NEXUS_DIAG_CHRONYC", "NEXUS_DIAG_NFT"):
            os.environ[k] = str(self.d / "missing")
        (self.d / "update.json").unlink()
        self._db.close()
        self._db = None
        for f in ("catalog.db", "catalog.db-wal", "catalog.db-shm"):
            (self.d / f).unlink(missing_ok=True)
        (self.d / "setup-done").unlink()
        cs = self.by_id(self.m.checks())
        for cid in ("time.sync", "time.nts", "egress", "keyd", "tls.cert", "audit.chain", "catalog.integrity", "bootc", "smart"):
            self.assertEqual(cs[cid]["status"], "skip", cs[cid])

    def test_closed_catalog_is_read_immutable(self):
        self._db.close()
        self._db = None
        self.assertFalse((self.d / "catalog.db-wal").exists())
        cs = self.by_id(self.m.checks())
        self.assertEqual(cs["catalog.integrity"]["status"], "pass")
        self.assertEqual(cs["audit.chain"]["status"], "pass")
        self.assertFalse((self.d / "catalog.db-wal").exists())

    def test_crashing_check_warns(self):
        self.answers["chronyc -c -n tracking"] = [0, "a,b,x,d,e,f,g,h,i,j,k,l,m,Normal\n"]  # stratum not a number
        self.save()
        c = self.by_id(self.m.checks())["time.sync"]
        self.assertEqual((c["status"], c["severity"]), ("warn", 2))
        self.assertIn("could not run", c["detail"])

    def test_cli_prints_json(self):
        import subprocess

        p = subprocess.run([sys.executable, "-I", str(SCRIPT), "checks"], capture_output=True, text=True, env=os.environ)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("selinux", {c["id"] for c in json.loads(p.stdout)})


class Requests(Host):
    ID = "0123456789abcdef0123456789abcdef"

    def request(self, **kw):
        r = {"id": self.ID, "kind": "checks", "by": "alice", **kw}
        (self.d / "diag/request.json").write_text(json.dumps(r))

    def result(self, rid=ID):
        return json.loads((self.d / "diag" / rid / "status.json").read_text())

    def test_checks_request(self):
        self.request()
        self.assertEqual(self.m.tick(), 0)
        self.assertFalse((self.d / "diag/request.json").exists())
        st = self.result()
        self.assertEqual((st["state"], st["kind"], st["by"], st["error"]), ("done", "checks", "alice", None))
        self.assertIn("checks.json", st["files"])
        self.assertNotIn("bundle.tar.gz", st["files"])
        cs = json.loads((self.d / "diag" / self.ID / "checks.json").read_text())
        self.assertIn("audit.chain", {c["id"] for c in cs})

    def test_bundle_request(self):
        now = int(time.time())
        self.request(kind="bundle", since=now - 3600, until=now)
        self.m.tick()
        st = self.result()
        self.assertEqual(st["state"], "done", st)
        p = self.d / "diag" / self.ID / "bundle.tar.gz"
        self.assertEqual(st["files"]["bundle.tar.gz"], p.stat().st_size)
        with tarfile.open(p) as tar:
            names = {n.split("/", 1)[1]: n for n in tar.getnames()}
            for f in ("manifest.json", "checks.json", "journal-nexus.txt", "avc.txt", "nft-drops.txt", "chrony.txt",
                      "systemd-failed.txt", "update-status.json", "catalog-stats.json", "disks.json"):
                self.assertIn(f, names)
            text = {k: tar.extractfile(v).read().decode() for k, v in names.items()}
        self.assertTrue(all(n.startswith("nexus-support-") for n in names.values()))
        self.assertIn("login password=[REDACTED]", text["journal-nexus.txt"])
        self.assertNotIn("hunter2", "".join(text.values()))
        stats = json.loads(text["catalog-stats.json"])
        self.assertEqual(stats["rows"], {"audit": 3, "users": 1})
        self.assertEqual(stats["audit_actions"], {"auth.login": 2, "setup.init": 1})
        self.assertNotIn("argon2id", "".join(text.values()))
        m = json.loads(text["manifest.json"])
        self.assertEqual((m["since"], m["until"], m["requested_by"]), (now - 3600, now, "alice"))
        calls = self.calls()
        self.assertTrue(any(c.startswith(f"journalctl --no-pager -o short-iso-precise --utc --since @{now - 3600} --until @{now} -u nexus-*") for c in calls), calls)
        self.assertTrue(any(c.startswith("ausearch -m AVC,USER_AVC,SELINUX_ERR") for c in calls), calls)

    def test_bad_requests_are_dropped(self):
        now = int(time.time())
        for bad in (
            {"id": "../../etc", "kind": "checks", "by": "alice"},
            {"id": self.ID, "kind": "shell", "by": "alice"},
            {"id": self.ID, "kind": "checks", "by": "a b"},
            {"id": self.ID, "kind": "bundle", "by": "alice", "since": now, "until": now - 1},
            {"id": self.ID, "kind": "bundle", "by": "alice", "since": now - 40 * 86400, "until": now},
            {"id": self.ID, "kind": "bundle", "by": "alice", "since": "yesterday", "until": now},
        ):
            (self.d / "diag/request.json").write_text(json.dumps(bad))
            self.m.tick()
            self.assertFalse((self.d / "diag/request.json").exists())
            self.assertEqual(os.listdir(self.d / "diag"), [], bad)
        (self.d / "diag/request.json").write_text("not json")
        self.m.tick()
        self.assertEqual(os.listdir(self.d / "diag"), [])

    def test_symlinked_request_is_ignored(self):
        (self.d / "elsewhere.json").write_text(json.dumps({"id": self.ID, "kind": "checks", "by": "alice"}))
        (self.d / "diag/request.json").symlink_to(self.d / "elsewhere.json")
        self.m.tick()
        self.assertFalse((self.d / "diag" / self.ID).exists())

    def test_id_is_used_once(self):
        self.request()
        self.m.tick()
        first = self.result()["created"]
        self.request(kind="bundle")
        self.m.tick()
        st = self.result()
        self.assertEqual((st["kind"], st["created"]), ("checks", first))

    def test_prune(self):
        old = self.d / "diag" / ("a" * 32)
        old.mkdir()
        (old / "status.json").write_text("{}")
        t = time.time() - 25 * 3600
        os.utime(old, (t, t))
        keep = self.d / "diag" / ("b" * 32)
        keep.mkdir()
        other = self.d / "diag" / "not-a-result"
        other.mkdir()
        self.m.tick()
        self.assertFalse(old.exists())
        self.assertTrue(keep.exists() and other.exists())


if __name__ == "__main__":
    unittest.main()
