"""HTTP(S) to the appliance with the standard library: TLS against the system store, a private CA, or a pinned
SHA-256 certificate fingerprint (appliances start with a self-signed certificate whose name may not match the
address used)."""

from __future__ import annotations

import hashlib
import http.client
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import NexusBackupError, TlsError

LOOPBACK = ("localhost", "127.0.0.1", "::1")


def normalize_fingerprint(fp: str) -> str:
    """`AB:CD:...` (as the web UI and browsers show it) or plain hex -> 64 lower-case hex digits."""
    hexits = re.sub(r"[\s:]", "", fp).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", hexits):
        raise ValueError("fingerprint: the SHA-256 of the certificate, 64 hex digits (colons allowed)")
    return hexits


def format_fingerprint(der: bytes) -> str:
    """SHA-256 of a DER certificate as upper-case hex with colons (the appliance's `sha256` format)."""
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i : i + 2] for i in range(0, 64, 2))


@dataclass
class Response:
    status: int
    content_type: str
    headers: list[tuple[str, str]]
    data: bytes


class Transport:
    """One connection per request (admin scripts, not throughput); no redirects are followed."""

    def __init__(
        self,
        url: str,
        *,
        verify: bool = True,
        ca_file: str | None = None,
        ca_data: str | None = None,
        fingerprint: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        u = urlsplit(url)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise ValueError(f"url: https://host[:port], not {url!r}")
        if u.scheme == "http" and u.hostname not in LOOPBACK:
            raise ValueError("url: https:// (http:// only for localhost)")
        self.https = u.scheme == "https"
        self.host = u.hostname
        self.port = u.port or (443 if self.https else 80)
        self.base = u.path.rstrip("/")
        self.timeout = timeout
        self.fingerprint = normalize_fingerprint(fingerprint) if fingerprint else None
        self.context: ssl.SSLContext | None = None
        if self.https:
            if self.fingerprint or not verify:
                # the pin replaces the chain and name checks (the certificate itself is compared after the
                # handshake, before anything is sent); verify=False checks nothing at all
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                ctx = ssl.create_default_context(cafile=ca_file, cadata=ca_data)
            self.context = ctx

    def send(
        self, method: str, target: str, headers: dict[str, str], body: bytes | None, timeout: float | None
    ) -> Response:
        t = self.timeout if timeout is None else timeout
        conn: http.client.HTTPConnection
        if self.https:
            conn = http.client.HTTPSConnection(self.host, self.port, timeout=t, context=self.context)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=t)
        try:
            try:
                conn.connect()
            except ssl.SSLCertVerificationError as e:
                raise TlsError(
                    f"{self.host}:{self.port}: certificate not trusted ({e.verify_message}); pass ca_file= with the "
                    "appliance's CA or certificate, or fingerprint= with its SHA-256 (Settings -> Certificate)"
                ) from e
            except OSError as e:
                raise NexusBackupError(f"{self.host}:{self.port}: {e}") from e
            if self.fingerprint:
                der = conn.sock.getpeercert(binary_form=True) if conn.sock else None  # type: ignore[union-attr]
                got = hashlib.sha256(der or b"").hexdigest()
                if got != self.fingerprint:
                    raise TlsError(
                        f"{self.host}:{self.port}: certificate fingerprint {format_fingerprint(der or b'')} "
                        "does not match the pinned one"
                    )
            conn.request(method, self.base + target, body=body, headers=headers)
            r = conn.getresponse()
            data = r.read()
            return Response(r.status, r.getheader("Content-Type", "") or "", r.getheaders(), data)
        finally:
            conn.close()


def get_server_fingerprint(url: str, timeout: float = 10.0) -> str:
    """The SHA-256 fingerprint of the certificate the appliance presents, without checking it (`AB:CD:...`).

    For trust on first use: compare it with the one on the appliance (web UI: Settings -> Certificate, or the
    console) before passing it as `fingerprint=`; on its own this proves nothing.
    """
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise ValueError("url: https://host[:port]")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((u.hostname, u.port or 443), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=u.hostname) as s,
    ):
        der = s.getpeercert(binary_form=True)
    return format_fingerprint(der or b"")
