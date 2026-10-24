#!/usr/bin/env python3
"""Lab syslog receiver over TLS (RFC 5425, octet-counted frames `LEN SP MSG`) in plain Python, for a lab VM
without rsyslog's TLS module (lab/forwarding/vm.sh): every message (RFC 5424, as the appliance sends it) is
appended as one line to $OUT_DIR/syslog.log. CERT_DIR (tls.crt, tls.key), PORT (16514)."""
import os
import socketserver
import ssl
import threading

OUT = os.path.join(os.environ.get("OUT_DIR", "out"), "syslog.log")
CERT_DIR = os.environ.get("CERT_DIR", "certs")
LOCK = threading.Lock()


class Frames(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            n = b""
            while (c := self.rfile.read(1)) not in (b" ", b""):
                n += c
                if len(n) > 8 or not c.isdigit():
                    return  # not octet-counted framing: drop the connection
            if not n:
                return
            msg = self.rfile.read(int(n))
            with LOCK, open(OUT, "ab") as f:
                f.write(msg.rstrip(b"\n").replace(b"\n", b" ") + b"\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(CERT_DIR, "tls.crt"), os.path.join(CERT_DIR, "tls.key"))
srv = Server(("0.0.0.0", int(os.environ.get("PORT", "16514"))), Frames)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
