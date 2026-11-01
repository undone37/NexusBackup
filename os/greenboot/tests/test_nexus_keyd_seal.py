"""nexus-keyd-seal (#22): the plain KEK becomes a credential sealed to the TPM and is removed; without a TPM (an
appliance installed before the requirement) a host-key credential and status "host"; a TPM appearing later re-seals;
a credential that does not decrypt back to the KEK leaves the plain file in place."""
import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HELPER = Path(__file__).resolve().parents[1] / "usr/libexec/nexus/nexus-keyd-seal"

# systemd-creds stand-in: has-tpm2 by $FAKE_TPM, encrypt -> "CRED:<mode>:<pcrs>:<base64>", decrypt back (or a
# wrong key with $FAKE_CORRUPT), every call logged
FAKE = r'''#!PYTHON
import base64, os, sys
a = sys.argv[1:]
open(os.environ["FAKE_LOG"], "a").write(" ".join(a) + "\n")
if a[0] == "has-tpm2":
    sys.exit(0 if os.environ.get("FAKE_TPM") == "1" else 1)
src = a[-2]
data = sys.stdin.buffer.read() if src == "-" else open(src, "rb").read()
if a[0] == "encrypt":
    mode = "tpm2" if "--with-key=tpm2" in a else "host"
    pcrs = next((x.split("=", 1)[1] for x in a if x.startswith("--tpm2-pcrs=")), "")
    sys.stdout.buffer.write(b"CRED:" + mode.encode() + b":" + pcrs.encode() + b":" + base64.b64encode(data))
elif a[0] == "decrypt":
    if not data.startswith(b"CRED:"):
        sys.exit(1)
    plain = base64.b64decode(data.split(b":", 3)[3])
    sys.stdout.buffer.write(b"\x00" * 32 if os.environ.get("FAKE_CORRUPT") else plain)
'''


class Seal(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        (self.d / "keyd").mkdir()
        fake = self.d / "systemd-creds"
        fake.write_text(FAKE.replace("PYTHON", sys.executable))
        fake.chmod(0o755)
        self.env = {**os.environ, "NEXUS_KEYDSEAL_DIR": str(self.d / "keyd"),
                    "NEXUS_KEYDSEAL_STATUS": str(self.d / "keyd-seal.json"),
                    "NEXUS_KEYDSEAL_SYSTEMD_CREDS": str(fake), "FAKE_LOG": str(self.d / "calls"),
                    "NEXUS_KEYDSEAL_RESTORECON": "true"}
        self.kek = bytes(range(32))

    def tearDown(self):
        self._tmp.cleanup()

    def run_helper(self, *args, **env):
        return subprocess.run([sys.executable, str(HELPER), *args], env={**self.env, **env},
                              capture_output=True, text=True)

    def plain(self):
        (self.d / "keyd/kek.local").write_bytes(self.kek)

    def cred(self):
        return (self.d / "keyd/kek.cred").read_bytes()

    def status(self):
        return json.loads((self.d / "keyd-seal.json").read_text())

    def test_sealed_to_the_tpm_and_plain_removed(self):
        self.plain()
        r = self.run_helper("migrate", FAKE_TPM="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.d / "keyd/kek.local").exists())
        self.assertTrue(self.cred().startswith(b"CRED:tpm2:7:"))
        self.assertEqual(base64.b64decode(self.cred().split(b":", 3)[3]), self.kek)
        self.assertEqual(stat.S_IMODE((self.d / "keyd/kek.cred").stat().st_mode), 0o600)
        self.assertEqual((self.status()["mode"], self.status()["pcrs"]), ("tpm2", [7]))
        self.assertIn("encrypt --name=kek --with-key=tpm2 --tpm2-pcrs=7 - -", (self.d / "calls").read_text())

    def test_no_tpm_host_key_then_resealed_when_a_tpm_appears(self):
        self.plain()
        r = self.run_helper("migrate", FAKE_TPM="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NO TPM", r.stderr)
        self.assertTrue(self.cred().startswith(b"CRED:host::"))
        self.assertEqual(self.status()["mode"], "host")
        r = self.run_helper("migrate", FAKE_TPM="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.cred().startswith(b"CRED:tpm2:7:"))
        self.assertEqual(self.status()["mode"], "tpm2")
        # nothing to do the next time
        before = self.cred()
        self.assertEqual(self.run_helper("migrate", FAKE_TPM="1").returncode, 0)
        self.assertEqual(self.cred(), before)

    def test_a_credential_that_does_not_decrypt_keeps_the_plain_kek(self):
        self.plain()
        r = self.run_helper("migrate", FAKE_TPM="1", FAKE_CORRUPT="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not decrypt", r.stderr)
        self.assertEqual((self.d / "keyd/kek.local").read_bytes(), self.kek)
        self.assertFalse((self.d / "keyd/kek.cred").exists())

    def test_the_credential_must_get_its_selinux_label(self):
        # lab: with keyd's directory label systemd could not read it and keyd failed at step CREDENTIALS
        self.plain()
        r = self.run_helper("migrate", FAKE_TPM="1", NEXUS_KEYDSEAL_RESTORECON="false")
        self.assertEqual(r.returncode, 1)
        self.assertIn("restorecon", r.stderr)
        self.assertEqual((self.d / "keyd/kek.local").read_bytes(), self.kek, "the plain KEK stays until it is usable")

    def test_nothing_before_setup(self):
        r = self.run_helper("migrate", FAKE_TPM="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.d / "keyd/kek.cred").exists())
        self.assertFalse((self.d / "keyd-seal.json").exists())


if __name__ == "__main__":
    unittest.main()
