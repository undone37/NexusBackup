//! Interoperability of X25519MLKEM768 with an independent implementation: OpenSSL 3.5 (Debian 13,
//! AlmaLinux 10) as client against a rustls server with [`tls_pq::provider`], and as server
//! against a rustls client. Skipped when `openssl` is missing or does not offer the group.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

fn openssl_has_group() -> bool {
    Command::new("openssl")
        .args(["list", "-tls-groups"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("X25519MLKEM768"))
}

fn cert() -> (rcgen::CertifiedKey, tempfile::TempDir) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(d.path().join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
    (ck, d)
}

#[test]
fn openssl_client_negotiates_the_hybrid_group() {
    if !openssl_has_group() {
        eprintln!("skipped: openssl without X25519MLKEM768");
        return;
    }
    let (ck, d) = cert();
    let server = ServerConfig::builder_with_provider(tls_pq::provider_arc())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(ck.cert.der().to_vec())],
            PrivateKeyDer::try_from(ck.key_pair.serialize_der()).unwrap(),
        )
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (sock, _) = l.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(server)).unwrap(), sock);
        let mut b = [0u8; 5];
        tls.read_exact(&mut b).unwrap();
        tls.write_all(b"pong\n").unwrap();
        tls.flush().unwrap();
        let g = tls.conn.negotiated_key_exchange_group().unwrap().name();
        (b, g)
    });
    let mut c = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-groups",
            "X25519MLKEM768",
            "-tls1_3",
        ])
        .arg("-CAfile")
        .arg(d.path().join("cert.pem"))
        .args(["-servername", "localhost", "-quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(b"ping\n").unwrap();
    let out = c.wait_with_output().unwrap();
    let (got, group) = srv.join().unwrap();
    assert_eq!(&got, b"ping\n", "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(group, rustls::NamedGroup::X25519MLKEM768);
    assert!(String::from_utf8_lossy(&out.stdout).contains("pong"));
}

#[test]
fn rustls_client_against_openssl_server() {
    if !openssl_has_group() {
        eprintln!("skipped: openssl without X25519MLKEM768");
        return;
    }
    let (ck, d) = cert();
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut s = Command::new("openssl")
        .args([
            "s_server",
            "-accept",
            &port.to_string(),
            "-groups",
            "X25519MLKEM768",
            "-tls1_3",
            "-www",
        ])
        .arg("-cert")
        .arg(d.path().join("cert.pem"))
        .arg("-key")
        .arg(d.path().join("key.pem"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut sock = None;
    for _ in 0..50 {
        if let Ok(t) = TcpStream::connect(("127.0.0.1", port)) {
            sock = Some(t);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let sock = sock.expect("openssl s_server did not listen");
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ck.cert.der().to_vec())).unwrap();
    let client = ClientConfig::builder_with_provider(tls_pq::provider_arc())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap()).unwrap();
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut page = String::new();
    let _ = tls.read_to_string(&mut page);
    let group = tls
        .conn
        .negotiated_key_exchange_group()
        .map(rustls::crypto::SupportedKxGroup::name);
    let _ = s.kill();
    let _ = s.wait();
    assert_eq!(group, Some(rustls::NamedGroup::X25519MLKEM768));
    // -www answers with its status page, which names the group
    assert!(page.contains("X25519MLKEM768"), "{page}");
}
