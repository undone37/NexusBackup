"""Unit tests for /usr/libexec/nexus/nexus-time: validation, the sources file it writes (NTS only vs.
plain NTP allowed), the request protocol (applied, unchanged, refused), and the status it reads from
a fake chronyc (chrony 4.8 output from the lab).

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

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
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-time"

# chronyc -c -N sources / authdata / -n tracking on lab VM 201 (pve-test, 2026-10-21)
SOURCES = """^,+,time.cloudflare.com,3,10,377,866,0.000453657,0.000453657,0.007774438
^,*,ptbtime2.ptb.de,1,10,377,879,0.000317886,0.000390053,0.006783520
^,?,nts.netnod.se,0,6,0,4294967295,0.000000000,0.000000000,0.000000000
^,+,ntp.internal,2,6,17,30,0.000100000,0.000100000,0.001000000
"""
AUTHDATA = """time.cloudflare.com,NTS,2,30,128,16891,0,0,8,64
ptbtime2.ptb.de,NTS,1,15,256,490042,0,0,8,100
nts.netnod.se,NTS,2,15,256,129,2,0,0,0
ntp.internal,-,0,0,0,0,0,0,0,0
"""
TRACKING = ("C0356768,192.53.103.104,2,1792542272.581475099,-0.000060943,0.000072167,0.000102886,-16.699,"
            "0.004,0.044,0.013536338,0.001000352,1024.1,Normal\n")

FAKE = r'''#!PYTHON
import json, os, sys
d = os.environ["FAKE_DIR"]
line = " ".join(["chronyc"] + sys.argv[1:])
answers = json.load(open(os.path.join(d, "answers.json")))
rc, out = answers.get(line, (1, ""))
sys.stdout.write(out)
sys.exit(rc)
'''


def load():
    loader = importlib.machinery.SourceFileLoader("nexus_time", str(SCRIPT))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "ctl").mkdir()
        (self.d / "fake").mkdir()
        tool = self.d / "fake/chronyc"
        tool.write_text(FAKE.replace("PYTHON", sys.executable))
        tool.chmod(0o755)
        self.answer({"chronyc -c -N sources": [0, SOURCES], "chronyc -c -N authdata": [0, AUTHDATA],
                     "chronyc -c -n tracking": [0, TRACKING]})
        self.env = {"NEXUS_TIME_DIR": str(self.d / "ctl"), "NEXUS_TIME_CONF": str(self.d / "chrony.conf"),
                    "NEXUS_TIME_RUN": str(self.d / "run"), "NEXUS_TIME_CHRONYC": str(tool),
                    "FAKE_DIR": str(self.d / "fake"), "NEXUS_TIME_SETTLE": "0"}
        self.old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.m = load()

    def tearDown(self):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def answer(self, a):
        (self.d / "fake/answers.json").write_text(json.dumps(a))

    def request(self, servers, allow_ntp=False, rid="a" * 32):
        (self.d / "ctl/request.json").write_text(json.dumps(
            {"id": rid, "by": "admin", "quorum_id": 7, "servers": servers, "allow_ntp": allow_ntp}))

    def tick(self):
        self.assertEqual(self.m.main(["nexus-time", "tick"]), 0)
        return json.loads((self.d / "ctl/status.json").read_text())


class Validation(Base):
    def test_hosts(self):
        for h in ("time.cloudflare.com", "ntp1", "10.0.0.5", "2001:db8::1", "a-b.example.", "x" * 63 + ".de"):
            self.assertTrue(self.m.valid_host(h), h)
        for h in ("", "-a.example", "a_b.example", "a..b", "1.2.3.400", "x" * 64 + ".de", "a b", "host;rm",
                  "a.123", 5, None):
            self.assertFalse(self.m.valid_host(h), h)

    def test_requests(self):
        v = self.m.validate
        self.assertEqual(v({"servers": [{"host": "a.example", "nts": True}]}), [("a.example", True)])
        bad = [
            {"servers": []},
            {"servers": [{"host": f"s{i}.example", "nts": True} for i in range(9)]},
            {"servers": [{"host": "a.example", "nts": True}, {"host": "A.example", "nts": True}]},
            {"servers": [{"host": "a.example", "nts": "yes"}]},
            {"servers": [{"host": "a.example", "nts": True, "port": 123}]},
            # plain NTP needs the explicit opt-in
            {"servers": [{"host": "ntp.internal", "nts": False}]},
            {"servers": [{"host": "ntp.internal", "nts": False}], "allow_ntp": "true"},
        ]
        for r in bad:
            with self.assertRaises(self.m.Refused, msg=r):
                v(r)
        self.assertEqual(v({"servers": [{"host": "ntp.internal", "nts": False}], "allow_ntp": True}),
                         [("ntp.internal", False)])

    def test_render(self):
        nts = self.m.render([("a.example", True), ("b.example", True)])
        self.assertIn("server a.example iburst nts\n", nts)
        self.assertIn("authselectmode require\n", nts)
        self.assertIn("minsources 2\n", nts)
        mixed = self.m.render([("a.example", True), ("ntp.internal", False)])
        self.assertIn("server ntp.internal iburst\n", mixed)
        self.assertIn("authselectmode prefer\n", mixed)
        # prefer ignores the NTP server while the NTS one works: one source must be enough
        self.assertIn("minsources 1\n", mixed)
        two = self.m.render([("a.example", True), ("b.example", True), ("ntp.internal", False)])
        self.assertIn("minsources 2\n", two)
        self.assertIn("minsources 2\n", self.m.render([("ntp1.internal", False), ("ntp2.internal", False)]))
        one = self.m.render([("ntp.internal", False)])
        self.assertIn("minsources 1\n", one)
        self.assertEqual(self.m.configured(mixed), [("a.example", True), ("ntp.internal", False)])


class Requests(Base):
    def test_apply_unchanged_and_refused(self):
        self.request([{"host": "nts.example", "nts": True}, {"host": "ntp.internal", "nts": False}], allow_ntp=True)
        s = self.tick()
        self.assertFalse((self.d / "ctl/request.json").exists())
        self.assertEqual(s["last"]["result"], "applied")
        self.assertEqual((s["last"]["by"], s["last"]["quorum_id"]), ("admin", 7))
        self.assertTrue((self.d / "run/restart").exists())
        conf = (self.d / "chrony.conf").read_text()
        self.assertIn("server ntp.internal iburst\n", conf)
        self.assertEqual(s["servers"], [{"host": "nts.example", "nts": True}, {"host": "ntp.internal", "nts": False}])
        self.assertTrue(s["allow_ntp"])

        (self.d / "run/restart").unlink()
        self.request([{"host": "nts.example", "nts": True}, {"host": "ntp.internal", "nts": False}], allow_ntp=True)
        self.assertEqual(self.tick()["last"]["result"], "unchanged")
        self.assertFalse((self.d / "run/restart").exists())

        self.request([{"host": "ntp.other", "nts": False}])
        s = self.tick()
        self.assertEqual(s["last"]["result"], "refused")
        self.assertIn("allow_ntp", s["last"]["error"])
        self.assertEqual((self.d / "chrony.conf").read_text(), conf)
        self.assertFalse((self.d / "run/restart").exists())

        # a timer tick without a request keeps the last outcome
        self.assertEqual(self.tick()["last"]["result"], "refused")

    def test_settle_refreshes_only_after_a_restart(self):
        self.assertEqual(self.m.main(["nexus-time", "settle"]), 0)
        self.assertFalse((self.d / "ctl/status.json").exists(), "no restart: nothing to do")
        (self.d / "run").mkdir()
        (self.d / "run/restarted").touch()
        self.assertEqual(self.m.main(["nexus-time", "settle"]), 0)
        self.assertFalse((self.d / "run/restarted").exists())
        self.assertEqual(json.loads((self.d / "ctl/status.json").read_text())["sources"][1]["state"], "selected")

    def test_unreadable_request(self):
        (self.d / "ctl/request.json").write_text("{nope")
        self.assertEqual(self.tick()["last"]["result"], "refused")
        self.assertFalse((self.d / "chrony.conf").exists())


class Status(Base):
    def test_sources_and_tracking(self):
        (self.d / "chrony.conf").write_text(self.m.render([("time.cloudflare.com", True), ("ntp.internal", False)]))
        s = self.tick()
        by = {r["name"]: r for r in s["sources"]}
        self.assertEqual(by["ptbtime2.ptb.de"]["state"], "selected")
        self.assertEqual(by["time.cloudflare.com"]["state"], "combined")
        self.assertEqual(by["nts.netnod.se"]["state"], "unreachable")
        self.assertIsNone(by["nts.netnod.se"]["last_rx"])
        self.assertEqual(by["ptbtime2.ptb.de"]["reach"], 0o377)
        self.assertTrue(by["ptbtime2.ptb.de"]["nts"])
        self.assertFalse(by["ntp.internal"]["nts"])
        self.assertAlmostEqual(by["time.cloudflare.com"]["offset"], 0.000453657)
        self.assertTrue(s["tracking"]["synced"])
        self.assertEqual(s["tracking"]["stratum"], 2)
        self.assertIsNone(s["chrony_error"])

    def test_chronyd_down(self):
        self.answer({"chronyc -c -N sources": [1, "506 Cannot talk to daemon\n"]})
        s = self.tick()
        self.assertEqual(s["sources"], [])
        self.assertIn("Cannot talk", s["chrony_error"])
        self.assertIsNone(s["tracking"])


if __name__ == "__main__":
    unittest.main()
