"""A local stub of the appliance API: canned answers per method and path, every request recorded. No network
beyond 127.0.0.1."""

from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest

Answer = tuple[int, Any] | tuple[int, Any, dict[str, str]]


@dataclass
class Seen:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: Any


@dataclass
class Stub:
    url: str = ""
    routes: dict[tuple[str, str], list[Answer] | Callable[[Seen], Answer]] = field(default_factory=dict)
    seen: list[Seen] = field(default_factory=list)

    def on(self, method: str, path: str, *answers: Answer) -> None:
        """Answer `method path` (below /api/v1) with these, in turn; the last one repeats."""
        self.routes[(method, "/api/v1" + path)] = list(answers)

    def on_call(self, method: str, path: str, fn: Callable[[Seen], Answer]) -> None:
        self.routes[(method, "/api/v1" + path)] = fn

    def requests(self, method: str | None = None, path: str | None = None) -> list[Seen]:
        return [
            s
            for s in self.seen
            if (method is None or s.method == method) and (path is None or s.path == "/api/v1" + path)
        ]


def _handler(stub: Stub) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _any(self) -> None:
            u = urlsplit(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            body = json.loads(raw) if raw else None
            seen = Seen(self.command, u.path, dict(parse_qsl(u.query)), dict(self.headers.items()), body)
            stub.seen.append(seen)
            route = stub.routes.get((self.command, u.path))
            if route is None:
                answer: Answer = (404, {"error": f"no route {self.command} {u.path}"})
            elif callable(route):
                answer = route(seen)
            else:
                answer = route.pop(0) if len(route) > 1 else route[0]
            status, payload = answer[0], answer[1]
            headers = answer[2] if len(answer) > 2 else {}  # type: ignore[misc]
            if isinstance(payload, bytes):
                data, ctype = payload, "application/octet-stream"
            elif isinstance(payload, str):
                data, ctype = payload.encode(), "text/csv; charset=utf-8"
            else:
                data, ctype = json.dumps(payload).encode(), "application/json"
            self.send_response(status)
            self.send_header("Content-Type", headers.pop("Content-Type", ctype))
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = _any

    return H


def _serve(stub: Stub, context: ssl.SSLContext | None, host: str) -> Iterator[Stub]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(stub))
    server.handle_error = lambda *a: None  # type: ignore[method-assign]  # clients that hang up (wrong pin)
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    stub.url = f"{'https' if context else 'http'}://{host}:{port}"
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    try:
        yield stub
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def stub() -> Iterator[Stub]:
    """A plain-HTTP stub on localhost (the SDK allows http:// only for localhost)."""
    yield from _serve(Stub(), None, "localhost")


@pytest.fixture(scope="session")
def cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A self-signed certificate naming only localhost (not the address used): (cert.pem, key.pem)."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    d = tmp_path_factory.mktemp("tls")
    crt, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return crt, key


@pytest.fixture
def tls_stub(cert: tuple[Path, Path]) -> Iterator[Stub]:
    """An HTTPS stub with the self-signed certificate, addressed by IP (the name does not match)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert[0]), str(cert[1]))
    yield from _serve(Stub(), ctx, "127.0.0.1")
