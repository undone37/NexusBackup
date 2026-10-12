"""Unit tests for /usr/libexec/nexus/nexus-grub-password (Phase 18): validation of the
hash line, idempotence, remount of a read-only /boot around the copy.

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-grub-password"
HASH = "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000." + "AB" * 64 + "." + "CD" * 64 + "\n"

FAKE_MOUNT = """#!/bin/sh
echo "mount $*" >> "$FAKE_DIR/calls"
"""


class GrubPassword(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        (self.d / "boot/grub2").mkdir(parents=True)
        (self.d / "mount").write_text(FAKE_MOUNT)
        (self.d / "mount").chmod(0o755)
        self.mountinfo("rw")
        self.env = {
            **os.environ,
            "FAKE_DIR": str(self.d),
            "NEXUS_GRUB_SRC": str(self.d / "grub-user.cfg"),
            "NEXUS_GRUB_BOOT": str(self.d / "boot"),
            "NEXUS_GRUB_MOUNTINFO": str(self.d / "mountinfo"),
            "NEXUS_GRUB_MOUNT": str(self.d / "mount"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def mountinfo(self, opts):
        (self.d / "mountinfo").write_text(
            f"22 1 0:21 / / rw,relatime - overlay overlay rw\n"
            f"40 22 252:2 / {self.d / 'boot'} {opts},relatime shared:5 - ext4 /dev/vda2 rw\n"
        )

    def run_it(self):
        return subprocess.run([sys.executable, str(SCRIPT)], env=self.env, capture_output=True, text=True)

    def calls(self):
        p = self.d / "calls"
        return p.read_text().splitlines() if p.exists() else []

    def test_nothing_before_setup(self):
        r = self.run_it()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.d / "boot/grub2/user.cfg").exists())

    def test_installs_once_and_keeps_mode(self):
        (self.d / "grub-user.cfg").write_text(HASH)
        r = self.run_it()
        self.assertEqual(r.returncode, 0, r.stderr)
        dst = self.d / "boot/grub2/user.cfg"
        self.assertEqual(dst.read_text(), HASH)
        self.assertEqual(dst.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.calls(), [], "rw /boot: no remount")
        self.assertIn("installed", r.stderr)
        r = self.run_it()
        self.assertEqual((r.returncode, r.stderr), (0, ""), "unchanged: silent no-op")

    def test_read_only_boot_is_remounted_around_the_copy(self):
        (self.d / "grub-user.cfg").write_text(HASH)
        (self.d / "boot/grub2/user.cfg").write_text("GRUB2_PASSWORD=old\n")
        self.mountinfo("ro")
        r = self.run_it()
        self.assertEqual(r.returncode, 0, r.stderr)
        boot = str(self.d / "boot")
        self.assertEqual(self.calls(), [f"mount -o remount,rw {boot}", f"mount -o remount,ro {boot}"])
        self.assertEqual((self.d / "boot/grub2/user.cfg").read_text(), HASH)

    def test_refuses_anything_but_the_hash_line(self):
        for bad in [
            HASH + "insmod shell\n",
            "GRUB2_PASSWORD=plain\n",
            HASH.replace("\n", "; echo x\n"),
            HASH.rstrip("\n"),
            "set superusers=\"\"\n",
        ]:
            (self.d / "grub-user.cfg").write_text(bad)
            r = self.run_it()
            self.assertEqual(r.returncode, 1, bad)
            self.assertFalse((self.d / "boot/grub2/user.cfg").exists(), bad)

    def test_symlinked_source_is_ignored(self):
        (self.d / "real").write_text(HASH)
        (self.d / "grub-user.cfg").symlink_to(self.d / "real")
        self.assertNotEqual(self.run_it().returncode, 0)
        self.assertFalse((self.d / "boot/grub2/user.cfg").exists())

    def test_not_a_grub_system(self):
        (self.d / "grub-user.cfg").write_text(HASH)
        (self.d / "boot/grub2").rmdir()
        r = self.run_it()
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not exist", r.stderr)


if __name__ == "__main__":
    unittest.main()
