"""Unit tests for /usr/libexec/nexus/nexus-health (no root, no services needed).

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

import http.server
import importlib.machinery
import importlib.util
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys

sys.dont_write_bytecode = True  # never leave __pycache__ in os/greenboot/usr (COPYed into the image)
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-health"


def load():
    loader = importlib.machinery.SourceFileLoader("nexus_health", str(SCRIPT))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


# First three audit entries of a catalog written by the Rust catalog crate
# (lab/e2e/m5.sh run): the Python chain must reproduce these hashes bit for bit.
RUST_AUDIT = [
    (1, 1791545742, "setup", "setup.run", "appliance",
     '{"dry_run":true,"force_reconfigure_network":false,"mode":"script"}',
     "0" * 64, "9a888c7bc0e100a6c346bbb39041d1d19f8a183edb521b59ec4b6d44498de8bc"),
    (2, 1791545742, "setup", "setup.network", "nic/eth0",
     '{"addresses":["192.0.2.10"],"dns":[],"dry_run":true,"gateway":null,"hostname":"nexus-m5","method":"static","nic":"eth0"}',
     "9a888c7bc0e100a6c346bbb39041d1d19f8a183edb521b59ec4b6d44498de8bc",
     "a49df89c95842765a3d0cc0387e1b8fe302d3bbae4a9519b776cef52c1905cac"),
    (3, 1791545742, "setup", "setup.user.create", "user/admin", '{"role":"admin"}',
     "a49df89c95842765a3d0cc0387e1b8fe302d3bbae4a9519b776cef52c1905cac",
     "4d107453f7da720af30f27e90b9910898e31e27a5421d23fab715aab18fb1d99"),
]


def make_catalog(path, rows=RUST_AUDIT):
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE audit (seq INTEGER PRIMARY KEY, ts INTEGER, actor TEXT, action TEXT,"
              " target TEXT, details TEXT, prev_hash TEXT, hash TEXT)")
    c.executemany("INSERT INTO audit VALUES (?,?,?,?,?,?,?,?)", rows)
    c.commit()
    c.close()


class Env:
    """A fake appliance: temp paths + a fake systemctl driven by files."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.units = self.tmp / "units"  # units/<name>.enabled / .active
        self.units.mkdir()
        sc = self.tmp / "systemctl"
        sc.write_text(
            "#!/bin/sh\n"
            f'U="{self.units}"\n'
            'case "$1" in is-enabled) test -e "$U/$3.enabled";; is-active) test -e "$U/$3.active";; *) exit 2;; esac\n'
        )
        sc.chmod(0o755)
        self.vars = {
            "NEXUS_HEALTH_SETUP_DONE": str(self.tmp / "setup-done"),
            "NEXUS_HEALTH_CATALOG": str(self.tmp / "catalog.db"),
            "NEXUS_HEALTH_KEYD_SOCKET": str(self.tmp / "keyd.sock"),
            "NEXUS_HEALTH_TLS_CERT": str(self.tmp / "cert.pem"),
            "NEXUS_HEALTH_URL": "https://127.0.0.1:1/health",
            "NEXUS_HEALTH_DISK_PATHS": str(self.tmp),
            "NEXUS_HEALTH_MIN_FREE_MB": "1",
            "NEXUS_HEALTH_MIN_FREE_PCT": "0",
            "NEXUS_HEALTH_TIMEOUT": "0",
            "NEXUS_HEALTH_INTERVAL": "0",
            "NEXUS_HEALTH_SYSTEMCTL": str(sc),
        }

    def unit(self, name, enabled=True, active=True):
        for suffix, on in ((".enabled", enabled), (".active", active)):
            p = self.units / (name + suffix)
            p.touch() if on else p.unlink(missing_ok=True)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.env = Env(self._tmp.name)
        self._old = {k: os.environ.get(k) for k in self.env.vars}
        os.environ.update(self.env.vars)
        self.h = load()

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()


class AuditChain(Base):
    def test_matches_rust_catalog_hashes(self):
        for seq, ts, actor, action, target, details, prev, h in RUST_AUDIT:
            self.assertEqual(self.h.chain_hash(prev, seq, ts, actor, action, target, details), h)

    def test_verify_counts(self):
        make_catalog(self.env.vars["NEXUS_HEALTH_CATALOG"])
        c = sqlite3.connect(self.env.vars["NEXUS_HEALTH_CATALOG"])
        self.assertEqual(self.h.verify_audit(c), 3)

    def test_tampered_details_detected(self):
        rows = [list(r) for r in RUST_AUDIT]
        rows[1][5] = rows[1][5].replace("192.0.2.10", "192.0.2.11")
        make_catalog(self.env.vars["NEXUS_HEALTH_CATALOG"], rows)
        with self.assertRaisesRegex(self.h.Fail, "seq 2"):
            self.h.check_catalog()

    def test_deleted_entry_detected(self):
        make_catalog(self.env.vars["NEXUS_HEALTH_CATALOG"], [RUST_AUDIT[0], RUST_AUDIT[2]])
        with self.assertRaisesRegex(self.h.Fail, "seq 3"):
            self.h.check_catalog()

    def test_corrupt_file_detected(self):
        p = Path(self.env.vars["NEXUS_HEALTH_CATALOG"])
        make_catalog(p)
        sqlite3.connect(p).execute("PRAGMA wal_checkpoint(TRUNCATE)").close()
        data = bytearray(p.read_bytes())
        data[100:4096] = b"\xff" * (4096 - 100)  # smash the schema page
        p.write_bytes(bytes(data))
        with self.assertRaises(self.h.Fail):
            self.h.check_catalog()

    def test_missing_catalog(self):
        with self.assertRaisesRegex(self.h.Fail, "missing"):
            self.h.check_catalog()

    def test_check_is_read_only(self):
        p = self.env.vars["NEXUS_HEALTH_CATALOG"]
        make_catalog(p)
        before = Path(p).read_bytes()
        self.h.check_catalog()
        self.assertEqual(Path(p).read_bytes(), before)


class Disk(Base):
    def test_ok(self):
        self.h.check_disk()

    def test_absolute_floor(self):
        os.environ["NEXUS_HEALTH_MIN_FREE_MB"] = str(2**40)  # 1 EiB
        with self.assertRaisesRegex(self.h.Fail, "free"):
            self.h.check_disk()

    def test_percentage(self):
        os.environ["NEXUS_HEALTH_MIN_FREE_PCT"] = "100.1"
        with self.assertRaises(self.h.Fail):
            self.h.check_disk()

    def test_missing_paths_skipped(self):
        os.environ["NEXUS_HEALTH_DISK_PATHS"] = "/nonexistent/x"
        self.h.check_disk()


class Units(Base):
    def test_only_enabled_units_are_required(self):
        self.env.unit("nexus-keyd.service")
        self.env.unit("nexus-web-api.service", enabled=False, active=False)
        self.assertEqual(self.h.enabled_units(), ["nexus-keyd.service"])
        self.h.check_units(self.h.enabled_units())

    def test_inactive_enabled_unit_fails(self):
        self.env.unit("nexus-scheduler.service", active=False)
        with self.assertRaisesRegex(self.h.Fail, "nexus-scheduler"):
            self.h.check_units(self.h.enabled_units())

    def test_retry_waits_for_start(self):
        os.environ["NEXUS_HEALTH_TIMEOUT"] = "5"
        os.environ["NEXUS_HEALTH_INTERVAL"] = "0.05"
        self.env.unit("nexus-keyd.service", active=False)
        threading.Timer(0.2, self.env.unit, ("nexus-keyd.service",)).start()
        self.h.retry(self.h.check_units, ["nexus-keyd.service"])


class Keyd(Base):
    def test_socket(self):
        with self.assertRaises(self.h.Fail):
            self.h.check_keyd()
        s = socket.socket(socket.AF_UNIX)
        s.bind(self.env.vars["NEXUS_HEALTH_KEYD_SOCKET"])
        s.listen(1)
        try:
            self.h.check_keyd()
        finally:
            s.close()


def self_signed(tmp):
    key, cert = Path(tmp) / "key.pem", Path(tmp) / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=nexus-test",
         "-addext", "subjectAltName=DNS:nexus-test"],
        check=True, capture_output=True,
    )
    return cert, key


@unittest.skipUnless(subprocess.run(["which", "openssl"], capture_output=True).returncode == 0, "openssl")
class WebApi(Base):
    def serve(self, status, body, cert, key):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                b = json.dumps(body).encode()
                self.send_response(status if self.path == "/health" else 404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        os.environ["NEXUS_HEALTH_URL"] = f"https://127.0.0.1:{srv.server_port}/health"

    def test_healthy(self):
        cert, key = self_signed(self._tmp.name)
        os.environ["NEXUS_HEALTH_TLS_CERT"] = str(cert)
        self.serve(200, {"ok": True}, cert, key)
        self.h.check_web_api()

    def test_503(self):
        cert, key = self_signed(self._tmp.name)
        os.environ["NEXUS_HEALTH_TLS_CERT"] = str(cert)
        self.serve(503, {"ok": False}, cert, key)
        with self.assertRaisesRegex(self.h.Fail, "503"):
            self.h.check_web_api()

    def test_other_certificate_rejected(self):
        cert, key = self_signed(self._tmp.name)
        self.serve(200, {"ok": True}, cert, key)
        other = Path(self._tmp.name) / "other"
        other.mkdir()
        os.environ["NEXUS_HEALTH_TLS_CERT"] = str(self_signed(other)[0])
        with self.assertRaisesRegex(self.h.Fail, "CERTIFICATE_VERIFY_FAILED|certificate verify failed"):
            self.h.check_web_api()

    def test_nothing_listening(self):
        cert, _ = self_signed(self._tmp.name)
        os.environ["NEXUS_HEALTH_TLS_CERT"] = str(cert)
        with self.assertRaises(self.h.Fail):
            self.h.check_web_api()


class Run(Base):
    def test_before_setup_only_disk(self):
        self.env.unit("nexus-keyd.service", active=False)  # would fail if checked
        self.assertEqual(self.h.run(), [])

    def test_after_setup_reports_each_failure(self):
        Path(self.env.vars["NEXUS_HEALTH_SETUP_DONE"]).touch()
        self.env.unit("nexus-keyd.service")
        self.env.unit("nexus-web-api.service", active=False)
        self.assertEqual(self.h.run(), ["units", "keyd", "web-api", "catalog"])

    def test_exit_code(self):
        p = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("GREEN", p.stdout)
        Path(self.env.vars["NEXUS_HEALTH_SETUP_DONE"]).touch()
        p = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("RED (catalog)", p.stderr)


if __name__ == "__main__":
    unittest.main()
