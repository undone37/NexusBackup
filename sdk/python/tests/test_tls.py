"""TLS against a stub with a self-signed certificate that names only localhost (as a new appliance's)."""

from __future__ import annotations

import hashlib
import ssl

import pytest

from nexusbackup import Client, TlsError, get_server_fingerprint
from nexusbackup.__main__ import main

TOKEN = "nxt_0123abcd_" + "0" * 64


def fingerprint(cert_pem) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_pem.read_text())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i : i + 2] for i in range(0, 64, 2))


def test_pinned_fingerprint_accepts_the_certificate_by_ip(tls_stub, cert):
    tls_stub.on("GET", "/hardware", (200, {"host": "backup1"}))
    fp = fingerprint(cert[0])
    assert Client(tls_stub.url, token=TOKEN, fingerprint=fp).api.get_hardware() == {"host": "backup1"}
    # plain hex, lower case
    plain = fp.replace(":", "").lower()
    assert Client(tls_stub.url, token=TOKEN, fingerprint=plain).api.get_hardware()["host"] == "backup1"


def test_wrong_fingerprint_sends_nothing(tls_stub):
    tls_stub.on("GET", "/hardware", (200, {"host": "backup1"}))
    with pytest.raises(TlsError, match="does not match the pinned one"):
        Client(tls_stub.url, token=TOKEN, fingerprint="00" * 32).api.get_hardware()
    assert tls_stub.seen == []


def test_untrusted_certificate_is_refused_by_default(tls_stub):
    with pytest.raises(TlsError, match="not trusted"):
        Client(tls_stub.url, token=TOKEN).api.get_hardware()


def test_ca_file_checks_chain_and_name(tls_stub, cert):
    tls_stub.on("GET", "/hardware", (200, {"host": "backup1"}))
    by_name = tls_stub.url.replace("127.0.0.1", "localhost")
    assert Client(by_name, token=TOKEN, ca_file=str(cert[0])).api.get_hardware()["host"] == "backup1"
    # the certificate does not name the IP address: the CA alone is not enough
    with pytest.raises(TlsError):
        Client(tls_stub.url, token=TOKEN, ca_file=str(cert[0])).api.get_hardware()
    unchecked = Client(tls_stub.url, token=TOKEN, ca_data=cert[0].read_text(), fingerprint=None, verify=False)
    assert unchecked.api.get_hardware()


def test_get_server_fingerprint(tls_stub, cert, capsys):
    assert get_server_fingerprint(tls_stub.url) == fingerprint(cert[0])
    assert main(["fingerprint", tls_stub.url]) == 0
    assert capsys.readouterr().out.strip() == fingerprint(cert[0])
