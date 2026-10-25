"""The service users and groups have fixed ids (os/sysusers.d/nexus.conf, os/edge/sysusers.conf): a bootc
update replaces /etc/passwd with the image's, so a dynamically numbered entry renumbers the others when one
is added and every state file keeps a foreign owner (lab 2026-10-25, #51)."""

import unittest
from pathlib import Path

OS = Path(__file__).resolve().parents[2]


def entries(path):
    for line in path.read_text().splitlines():
        f = line.split()
        if f and f[0] in ("u", "g"):
            yield f[0], f[1], f[2]


class FixedIds(unittest.TestCase):
    def test_every_user_and_group_has_a_fixed_unique_id(self):
        for conf in (OS / "sysusers.d/nexus.conf", OS / "edge/sysusers.conf"):
            ids = {"u": {}, "g": {}}
            for kind, name, spec in entries(conf):
                num = spec.split(":")[0]
                self.assertTrue(num.isdigit(), f"{conf.name}: {kind} {name} has no fixed id ({spec})")
                # `u name N` also creates group N unless the group is declared separately
                kinds = ("u", "g") if kind == "u" and ":" not in spec else (kind,)
                for k in kinds:
                    other = ids[k].setdefault(int(num), name)
                    self.assertEqual(other, name, f"{conf.name}: id {num} used by {other} and {name}")


if __name__ == "__main__":
    unittest.main()
