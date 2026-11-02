"""Unit tests for /usr/libexec/nexus/nexus-power (issue #179): the request protocol with the web-api
(crates/web-api/src/power.rs), what is scheduled and cancelled through a fake systemctl, the refusals, and the
units that run it.

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

import fcntl
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
ROOT = HERE.parents[2]
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-power"
UNITS = HERE.parent / "usr/lib/systemd/system"

# Fake systemctl: logs its arguments, exits with $FAKE_RC (default 0).
FAKE = """#!/bin/sh
echo "$*" >> "$FAKE_DIR/calls"
exit "${FAKE_RC:-0}"
"""


def load():
    loader = importlib.machinery.SourceFileLoader("nexus_power", str(SCRIPT))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


class Power(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.dir = t / "power"
        self.dir.mkdir()
        (t / "systemctl").write_text(FAKE)
        (t / "systemctl").chmod(0o755)
        (t / "boot_id").write_text("boot-1\n")
        self.lock = t / "update.lock"
        self.env = {
            "NEXUS_POWER_DIR": str(self.dir),
            "NEXUS_POWER_SYSTEMCTL": str(t / "systemctl"),
            "NEXUS_POWER_BOOT_ID": str(t / "boot_id"),
            "NEXUS_POWER_UPDATE_LOCK": str(self.lock),
            "NEXUS_POWER_LOCK_WAIT": "0",
            "FAKE_DIR": str(t),
        }
        self.old = {k: os.environ.get(k) for k in [*self.env, "FAKE_RC"]}
        os.environ.update(self.env)
        os.environ.pop("FAKE_RC", None)
        self.m = load()
        self.t = t

    def tearDown(self):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def request(self, **kw):
        r = {"id": "a" * 32, "action": "reboot", "delay_s": 60, "reason": "kernel update", "requested_by": "alice",
             "approved_by": "bob", "force": False, "running_jobs": 2, "time": 1}
        r.update(kw)
        (self.dir / "request.json").write_text(json.dumps(r))

    def calls(self):
        p = self.t / "calls"
        return p.read_text().splitlines() if p.exists() else []

    def status(self):
        return json.loads((self.dir / "status.json").read_text())

    def test_schedule_then_cancel(self):
        self.request()
        self.assertEqual(self.m.tick(now=1000), 0)
        self.assertFalse((self.dir / "request.json").exists(), "consumed")
        self.assertEqual(self.calls(), ["reboot --when=@1060"])
        s = self.status()
        self.assertEqual(s["boot_id"], "boot-1")
        self.assertEqual(s["pending"], {"id": "a" * 32, "action": "reboot", "at": 1060, "reason": "kernel update",
                                        "requested_by": "alice", "approved_by": "bob"})
        self.assertEqual(s["last"]["result"], "scheduled")
        self.assertEqual(oct((self.dir / "status.json").stat().st_mode & 0o777), "0o640")
        # a second action while one is scheduled: refused, nothing run
        self.request(id="b" * 32, action="poweroff")
        self.m.tick(now=1010)
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.status()["last"]["result"], "refused")
        self.assertEqual(self.status()["pending"]["action"], "reboot")
        # cancel
        self.request(id="c" * 32, action="cancel")
        self.m.tick(now=1020)
        self.assertEqual(self.calls()[-1], "reboot --when=cancel")
        s = self.status()
        self.assertIsNone(s["pending"])
        self.assertEqual((s["last"]["result"], s["last"]["action"]), ("cancelled", "reboot"))

    def test_now_and_poweroff(self):
        self.request(action="poweroff", delay_s=0)
        self.m.tick(now=1000)
        self.assertEqual(self.calls(), ["poweroff"])
        self.assertEqual(self.status()["last"]["result"], "executing")
        self.assertIsNone(self.status().get("pending"))

    def test_after_a_reboot_nothing_is_pending(self):
        self.request()
        self.m.tick(now=1000)
        (self.t / "boot_id").write_text("boot-2\n")
        self.m.tick(now=2000)  # the path unit's start at boot without a request
        s = self.status()
        self.assertEqual((s["boot_id"], s["pending"], s["last"]["result"]), ("boot-2", None, "scheduled"))
        self.request(id="d" * 32, action="cancel")
        self.m.tick(now=2001)
        self.assertEqual(self.calls(), ["reboot --when=@1060"], "nothing to cancel")

    def test_refused_while_nexus_update_holds_its_lock(self):
        with open(self.lock, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            self.request()
            self.m.tick(now=1000)
            self.assertEqual(self.calls(), [])
            self.assertIn("nexus-update", self.status()["last"]["detail"])
            self.request(force=True)
            self.m.tick(now=1001)
            self.assertEqual(self.calls(), ["reboot --when=@1061"])

    def test_systemctl_failure_is_reported(self):
        os.environ["FAKE_RC"] = "1"
        self.request()
        self.m.tick(now=1000)
        s = self.status()
        self.assertEqual((s["last"]["result"], s["pending"]), ("error", None))

    def test_bad_requests_are_ignored(self):
        for bad in ({"action": "halt"}, {"delay_s": 301}, {"delay_s": "5"}, {"id": "x"}, {"delay_s": True}):
            self.request(**bad)
            self.m.tick(now=1000)
            self.assertFalse((self.dir / "request.json").exists())
        (self.dir / "request.json").write_text("not json")
        self.m.tick(now=1000)
        # a symlink is never followed, and removed (the path unit would start the service again and again)
        target = self.t / "elsewhere.json"
        target.write_text(json.dumps({"id": "e" * 32, "action": "reboot", "delay_s": 0}))
        (self.dir / "request.json").symlink_to(target)
        self.m.tick(now=1000)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.dir / "request.json").is_symlink())
        self.assertTrue(target.exists())


class Units(unittest.TestCase):
    def test_path_service_and_dirs(self):
        path = (UNITS / "nexus-power.path").read_text()
        self.assertIn("PathExists=/var/lib/nexus/power/request.json\n", path)
        self.assertIn("Unit=nexus-power.service\n", path)
        svc = (UNITS / "nexus-power.service").read_text()
        self.assertIn("ExecStart=/usr/libexec/nexus/nexus-power tick\n", svc)
        self.assertIn("ProtectSystem=strict\n", svc)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_BOOT\n", svc)
        rw = {p for line in svc.splitlines() if line.startswith("ReadWritePaths=") for p in line.split("=", 1)[1].split()}
        self.assertEqual(rw, {"/var/lib/nexus/power"})
        self.assertIn("IPAddressDeny=any\n", svc)
        tmp = (ROOT / "os/etc/tmpfiles.d/nexus-power.conf").read_text()
        self.assertIn("d /var/lib/nexus/power 2770 root nexus-webapi -", tmp)
        preset = (ROOT / "os/etc/systemd/system-preset/05-nexus-update.preset").read_text()
        self.assertIn("enable nexus-power.path", preset)
        self.assertIn("nexus-power.path", (ROOT / "os/Containerfile").read_text())
        self.assertIn("ReadWritePaths=-/var/lib/nexus/power\n", (ROOT / "os/systemd/nexus-web-api.service").read_text())
        self.assertIn("nexus_power_var_lib_t", (ROOT / "os/selinux/nexus.fc").read_text())
        lib = (ROOT / "crates/web-api/src/power.rs").read_text()
        self.assertIn('pub const DIR: &str = "/var/lib/nexus/power";', lib)
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
