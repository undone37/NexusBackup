"""release/cve-exceptions.py: version and review-date rules of the CVE gate exceptions."""

import importlib.util
import json
import os
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "cve_exceptions", os.path.join(os.path.dirname(__file__), "..", "cve-exceptions.py")
)
ce = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ce)


def match(cve, version):
    return {
        "vulnerability": {"id": cve, "severity": "Critical", "fix": {"state": "fixed", "versions": ["7.0.1"]}},
        "artifact": {"name": "linux-kernel", "version": version},
    }


class Gate(unittest.TestCase):
    def test_upstream_version(self):
        self.assertEqual(ce.upstream("6.12.111+deb13-amd64"), (6, 12, 111))
        self.assertEqual(ce.upstream("6.12.105-1"), (6, 12, 105))
        self.assertGreater(ce.upstream("6.12.113"), ce.upstream("6.12.99-1"))

    def test_apply(self):
        exc = {"exceptions": [
            {"id": "CVE-1", "package": "linux-kernel", "evidence": "e", "fixed_in": "6.12.105-1",
             "url": "u", "checked": "2026-10-20", "review_by": "2999-01-01"},
            {"id": "CVE-2", "package": "linux-kernel", "evidence": "e", "fixed_in": None,
             "url": "u", "checked": "2026-10-20", "review_by": "2999-01-01"},
            {"id": "CVE-3", "package": "linux-kernel", "evidence": "e", "fixed_in": "6.12.200-1",
             "url": "u", "checked": "2026-10-20", "review_by": "2999-01-01"},
            {"id": "CVE-4", "package": "linux-kernel", "evidence": "e", "fixed_in": None,
             "url": "u", "checked": "2000-01-01", "review_by": "2000-04-01"},
        ]}
        grype = {"matches": [match(c, "6.12.111+deb13-amd64") for c in ("CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5")]}
        with tempfile.TemporaryDirectory() as d:
            for name, doc in (("g.json", grype), ("e.json", exc)):
                with open(os.path.join(d, name), "w") as f:
                    json.dump(doc, f)
            self.assertEqual(ce.apply(f"{d}/g.json", f"{d}/e.json", d), 1)
            blocking = open(f"{d}/grype-blocking.txt").read()
            excepted = open(f"{d}/grype-excepted.txt").read()
        # CVE-3: kernel older than the fix; CVE-4: review date passed; CVE-5: no exception
        self.assertEqual([l.split()[0] for l in blocking.splitlines()], ["CVE-3", "CVE-4", "CVE-5"])
        self.assertEqual([l.split()[0] for l in excepted.splitlines()], ["CVE-1", "CVE-2"])


if __name__ == "__main__":
    unittest.main()
