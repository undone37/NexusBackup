#!/usr/bin/env python3
"""Lab HTTPS JSON sink: POST /ingest with `Authorization: Bearer $TOKEN` and a JSON array body;
each accepted body is appended as one line to /out/https.jsonl. Answers 401 for a wrong token,
503 while /out/https.fail exists (to test the appliance's retries)."""
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("TOKEN", "")
OUT = "/out/https.jsonl"


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path != "/ingest" or self.headers.get("Authorization") != f"Bearer {TOKEN}":
            code = 401
        elif os.path.exists("/out/https.fail"):
            code = 503
        else:
            try:
                assert isinstance(json.loads(body), list)
                with open(OUT, "ab") as f:
                    f.write(body.replace(b"\n", b" ") + b"\n")
                code = 200
            except (ValueError, AssertionError):
                code = 400
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/tls.crt", "/certs/tls.key")
srv = ThreadingHTTPServer(("0.0.0.0", 8443), Sink)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
