"""Unit tests for /usr/libexec/nexus/nexus-luks-recovery (#22 M3): request handling, the calls to
systemd-cryptenroll and that the recovery key only travels in its environment.

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-luks-recovery"
WORDS = " ".join(["abandon"] * 23 + ["art"])

# records argv and the passphrase variables it got
FAKE = """#!/bin/sh
echo "$* NEW=${NEWPASSWORD:-} OLD=${PASSWORD:-}" >> "$FAKE_DIR/calls"
[ -z "$FAKE_FAIL" ]
"""


class LuksRecovery(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        (self.d / "cryptenroll").write_text(FAKE)
        (self.d / "cryptenroll").chmod(0o755)
        (self.d / "crypttab").write_text("# anaconda\nluks-a UUID=1a2b-3c none discard\nluks-b /dev/sda4 none\n")
        self.env = {
            **os.environ,
            "FAKE_DIR": str(self.d),
            "NEXUS_LUKS_REQUEST": str(self.d / "req"),
            "NEXUS_LUKS_CRYPTTAB": str(self.d / "crypttab"),
            "NEXUS_LUKS_CRYPTENROLL": str(self.d / "cryptenroll"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def request(self, op, words=WORDS, mode=0o600):
        p = self.d / "req"
        p.write_text(json.dumps({"op": op, "words": words}))
        p.chmod(mode)

    def run_(self, **env):
        return subprocess.run([sys.executable, str(SCRIPT)], env={**self.env, **env}, capture_output=True, text=True)

    def calls(self):
        p = self.d / "calls"
        return p.read_text().splitlines() if p.exists() else []

    def test_slot_on_every_device_words_only_in_the_environment(self):
        self.request("slot")
        r = self.run_()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [
            f"--unlock-tpm2-device=auto --password --wipe-slot=password /dev/disk/by-uuid/1a2b-3c NEW={WORDS} OLD=",
            f"--unlock-tpm2-device=auto --password --wipe-slot=password /dev/sda4 NEW={WORDS} OLD=",
        ])
        self.assertFalse((self.d / "req").exists())
        self.assertNotIn("abandon", r.stderr)

    def test_reenroll_wipes_then_enrols(self):
        self.request("reenroll")
        self.assertEqual(self.run_().returncode, 0)
        self.assertEqual(self.calls()[:2], [
            f"--wipe-slot=tpm2 /dev/disk/by-uuid/1a2b-3c NEW= OLD={WORDS}",
            f"--tpm2-device=auto --tpm2-pcrs=7 /dev/disk/by-uuid/1a2b-3c NEW= OLD={WORDS}",
        ])

    def test_refused_requests_are_removed_and_change_nothing(self):
        for op, words, mode in (("slot", WORDS, 0o644), ("format", WORDS, 0o600), ("slot", "a b c", 0o600)):
            self.request(op, words, mode)
            r = self.run_()
            self.assertEqual(r.returncode, 1, (op, mode))
            self.assertFalse((self.d / "req").exists())
        self.assertEqual(self.calls(), [])

    def test_failure_and_nothing_to_do(self):
        self.request("slot")
        r = self.run_(FAKE_FAIL="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("systemd-cryptenroll", r.stderr)
        self.assertNotIn("abandon", r.stderr)
        self.assertEqual(self.run_().returncode, 0)  # no request
        (self.d / "crypttab").unlink()
        self.request("slot")
        r = self.run_()
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing to do", r.stderr)


if __name__ == "__main__":
    unittest.main()
