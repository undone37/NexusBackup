"""Tests of the PegaProx plugin's core (no PegaProx, no Flask): python3 integrations/pegaprox/test_core.py"""
import hashlib
import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "nexusbackup"))
import core  # noqa: E402

NOW = 1_800_000_000
GROUPS = [
    {"id": 1, "tenant": "lab", "source_id": 1, "policy_id": 7, "name": "prod", "guests": [100, 101, 103],
     "last_backup": {"state": "ok"}, "next_backup": NOW + 3600},
    {"id": 2, "tenant": "lab", "source_id": 2, "policy_id": 7, "name": "other-cluster", "guests": [102]},
    {"id": 3, "tenant": "other", "source_id": 3, "policy_id": 7, "name": "foreign", "guests": [104]},
]
POLICIES = [{"id": 7, "name": "daily", "schedule": "daily 22:00"}]
SNAPS = [
    {"tenant": "lab", "source": "vm-100", "time": NOW - 3600, "lock_until": NOW + 86400},
    {"tenant": "lab", "source": "vm-100", "time": NOW - 90000},
    {"tenant": "lab", "source": "ct-101", "time": NOW - 3 * 86400},
    {"tenant": "other", "source": "vm-104", "time": NOW},
]
TESTS = [{"tenant": "lab", "source": "vm-100", "state": "passed", "finished": NOW - 100}]
ALERTS = [{"tenant": "lab", "key": "restore_test:lab/ct-101", "message": "boot failed"}]


class Rows(unittest.TestCase):
    def test_periods(self):
        self.assertEqual(core.schedule_period("daily 22:00"), 86400)
        self.assertEqual(core.schedule_period("every 15m"), 900)
        self.assertEqual(core.schedule_period("every 4h"), 14400)
        self.assertEqual(core.schedule_period("weekly sun 03:00"), 7 * 86400)
        self.assertIsNone(core.schedule_period("whenever"))

    def test_states(self):
        vms = [{"vmid": 100, "name": "erp", "type": "qemu"}, {"vmid": 101, "name": "proxy", "type": "lxc"},
               {"vmid": 102, "name": "x"}, {"vmid": 103, "name": "new"}, {"vmid": 104, "name": "foreign"}]
        rows = {r["vmid"]: r for r in core.guest_rows(vms, "lab", GROUPS, POLICIES, SNAPS, TESTS, ALERTS, NOW, 1)}
        self.assertEqual(rows[100]["state"], "ok")
        self.assertEqual(rows[100]["last_backup"]["time"], NOW - 3600, "the newest snapshot")
        self.assertEqual(rows[100]["restore_test"]["state"], "passed")
        self.assertEqual(rows[100]["group"]["next_backup"], NOW + 3600)
        self.assertEqual(rows[101]["source"], "ct-101")
        self.assertEqual(rows[101]["state"], "late", "3 days old on a daily schedule")
        self.assertEqual(rows[101]["alerts"], ["boot failed"])
        self.assertEqual(rows[102]["state"], "unprotected", "its group belongs to another NexusBackup source")
        self.assertEqual(rows[103]["state"], "never")
        self.assertEqual(rows[104]["state"], "unprotected", "another tenant's group and snapshots never count")
        self.assertEqual(core.summary(list(rows.values())), {"total": 5, "ok": 1, "late": 1, "unprotected": 2, "never": 1})

    def test_failed_last_job_is_late(self):
        g = [dict(GROUPS[0], last_backup={"state": "failed"})]
        r = core.guest_rows([{"vmid": 100}], "lab", g, POLICIES, SNAPS, [], [], NOW)[0]
        self.assertEqual(r["state"], "late")


class Pin(unittest.TestCase):
    """The appliance certificate is pinned before the token leaves: a wrong pin sends nothing."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        key, crt = os.path.join(cls.d, "k.pem"), os.path.join(cls.d, "c.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=nexus-test"],
                       check=True, capture_output=True)
        cls.seen = []
        seen = cls.seen

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                body = json.dumps([{"id": 1}]).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        cls.srv.socket = ctx.wrap_socket(cls.srv.socket, server_side=True)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        with open(crt) as f:
            der = ssl.PEM_cert_to_DER_cert(f.read())
        cls.pin = hashlib.sha256(der).hexdigest()
        cls.url = f"https://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_right_pin(self):
        a = core.Appliance(self.url, "nxt_abcdef12_secret", ":".join(self.pin[i:i + 2] for i in range(0, 64, 2)))
        self.assertEqual(a.call("GET", "/groups"), [{"id": 1}])
        self.assertEqual(self.seen[-1], "Bearer nxt_abcdef12_secret")

    def test_wrong_pin_sends_nothing(self):
        n = len(self.seen)
        a = core.Appliance(self.url, "nxt_abcdef12_secret", "0" * 64)
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            a.call("GET", "/groups")
        self.assertEqual(len(self.seen), n)

    def test_config_checks(self):
        for url, tok, pin in (("http://x", "nxt_a", "0" * 64), ("https://x", "secret", "0" * 64),
                              ("https://x", "nxt_a", "short")):
            with self.assertRaises(ValueError):
                core.Appliance(url, tok, pin)


if __name__ == "__main__":
    unittest.main()
