"""release/iso/config.toml: the installer kickstart encrypts the system disk and needs a TPM (#22 M3)."""

import os
import re
import tomllib
import unittest

with open(os.path.join(os.path.dirname(__file__), "..", "iso", "config.toml"), "rb") as f:
    KS = tomllib.load(f)["customizations"]["installer"]["kickstart"]["contents"]


def section(name):
    m = re.search(rf"^%{name}\b[^\n]*\n(.*?)^%end$", KS, re.S | re.M)
    assert m, f"no %{name} section"
    return m.group(0).splitlines()[0], m.group(1)


class Kickstart(unittest.TestCase):
    def test_pre_refuses_without_tpm_and_writes_encrypted_autopart(self):
        head, body = section("pre")
        self.assertIn("--erroronfail", head)
        self.assertIn("/dev/tpmrm0", body)
        self.assertRegex(body, r"exit 1\nfi")
        self.assertIn("--encrypted --luks-version=luks2", body)
        # the installer has no base64; 24 random bytes as hex, checked before use
        self.assertIn("od -An -tx1 -N24 /dev/urandom", body)
        self.assertIn("[ ${#p} -eq 48 ] || exit 1", body)
        self.assertIn("%include /tmp/nexus-part.ks", KS)
        # no unencrypted partitioning outside the generated include, no disk wiped without the user's choice
        outside = KS.replace(body, "")
        self.assertNotRegex(outside, r"(?m)^(autopart|part|clearpart|zerombr)\b")

    def test_initrd_tries_the_tpm_and_post_enrols_pcr7(self):
        self.assertIn('bootloader --append="rd.luks.options=tpm2-device=auto"', KS)
        head, body = section("post")
        self.assertIn("--erroronfail", head)
        self.assertIn("--nochroot", head)
        self.assertIn("systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7", body)
        self.assertIn("--unlock-key-file=/tmp/nexus-install-pass", body)


if __name__ == "__main__":
    unittest.main()
