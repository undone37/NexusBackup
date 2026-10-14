//! The edge proxy end to end, in process: the real Linux agent (`server::Agent`)
//! behind a real `nexus-edge`, driven by the real appliance library `agent-conn`
//! (edge enrollment, configuration, a backup through the edge with the direct path
//! closed, a "back up now" request pushed through the edge, the `SetEdge` push).
//! Also: pairing, unknown certificates refused, rate limits, and that the edge only
//! ever relays TLS records. No root needed.

use agent_conn::backup::{self, Spec};
use agent_conn::ca::Ca;
use agent_conn::edge::{EdgeTarget, LinkSpec};
use agent_conn::map::MapDb;
use agent_conn::poll::{poll_one, SetEdge, Target};
use agent_conn::tls::{session_config, Route, Session};
use agent_proto::edge::{EdgeAgent, EdgeLimits, EdgeMsg};
use chunkstore::{Keyring, Options, Store};
use nexus_agent::config::{Paths, Settings};
use nexus_agent::server::Agent;
use nexus_edge::{Edge, Files};
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const ID: &str = "0123456789abcdef";
const AGENT_TOKEN: &str = "MFRGGZDFMZTWQ2LKNNWG23TPOA";
const EDGE_TOKEN: &str = "ONSWG4TFORQXGZLDOJSXIZLE";
const T: Duration = Duration::from_secs(30);
const MARKER: &[u8] = b"EDGE-MUST-NOT-SEE-THIS-PAYLOAD";

struct Running {
    edge: Arc<Edge>,
    public: SocketAddr,
    control: SocketAddr,
}

/// An edge on two ephemeral ports, its runtime on a background thread.
fn start_edge(dir: &Path, limits_tap: bool) -> Running {
    let files = Files { dir: dir.join("edge") };
    nexus_edge::init(&files, EDGE_TOKEN).unwrap();
    let mut edge = Edge::open(files, dir.join("no-release-keys")).unwrap();
    edge.exit_on_update = false;
    if limits_tap {
        edge.tap = Some(Arc::new(Mutex::new(Vec::new())));
    }
    let edge = Arc::new(edge);
    let p = TcpListener::bind("127.0.0.1:0").unwrap();
    let c = TcpListener::bind("127.0.0.1:0").unwrap();
    let (public, control) = (p.local_addr().unwrap(), c.local_addr().unwrap());
    let e = edge.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            p.set_nonblocking(true).unwrap();
            c.set_nonblocking(true).unwrap();
            let p = tokio::net::TcpListener::from_std(p).unwrap();
            let c = tokio::net::TcpListener::from_std(c).unwrap();
            e.run(p, c).await
        })
    });
    Running { edge, public, control }
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Every relayed direction is a sequence of TLS records (the tap may cut the last one).
fn assert_tls_records(buf: &[u8]) {
    assert!(buf.len() >= 5, "nothing relayed");
    let mut off = 0;
    let mut n = 0;
    while off + 5 <= buf.len() {
        let (ty, ver, len) = (
            buf[off],
            [buf[off + 1], buf[off + 2]],
            u16::from_be_bytes([buf[off + 3], buf[off + 4]]),
        );
        assert!(matches!(ty, 20..=23), "record type {ty} at {off}");
        assert!(ver == [3, 3] || ver == [3, 1], "record version {ver:?} at {off}");
        assert!(len as usize <= 16384 + 256, "record length {len}");
        off += 5 + len as usize;
        n += 1;
    }
    assert!(n > 0);
}

fn edge_target(r: &Running, pin: &str) -> EdgeTarget {
    EdgeTarget {
        host: "127.0.0.1".into(),
        port: r.control.port(),
        cert_sha256: Some(pin.into()),
    }
}

fn link_once(ca: &Ca, e: &EdgeTarget, agents: Vec<EdgeAgent>, limits: EdgeLimits) -> Vec<String> {
    let spec = LinkSpec {
        agents,
        limits,
        update_dir: None,
        max_secs: 0,
        wait_secs: 0,
    };
    let mut lines = Vec::new();
    agent_conn::edge::link(ca, e, &spec, &mut |l| lines.push(l)).unwrap();
    lines
}

#[test]
fn backup_and_request_through_the_edge() {
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let data = d.path().join("host/srv");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("secret.txt"), MARKER.repeat(1000)).unwrap();
    fs::write(data.join("other"), b"hello\n").unwrap();

    // the agent, enrolled directly (enrollment never goes through the edge)
    let paths = Paths {
        config: d.path().join("agent/etc"),
        state: d.path().join("agent/state"),
        run: d.path().join("agent/run"),
    };
    nexus_agent::init(&paths, AGENT_TOKEN, None).unwrap();
    let settings = Settings {
        hook_owner: nexus_agent::sys::geteuid(),
        ..Default::default()
    };
    let mut agent = Agent::new(paths.clone(), settings).unwrap();
    agent.exit_on_update = false;
    let agent = Arc::new(agent);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let a = agent.clone();
    std::thread::spawn(move || a.serve(l));
    let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
    let enrolled =
        agent_conn::enroll::enroll(&ca, "127.0.0.1", port, &agent_proto::token_digest(AGENT_TOKEN), ID, T).unwrap();
    let pin = enrolled.cert_sha256.clone();

    // the edge: a wrong token is refused, the right one pins both sides
    let r = start_edge(d.path(), true);
    let bad = agent_conn::edge::enroll(
        &ca,
        "127.0.0.1",
        r.control.port(),
        &agent_proto::token_digest("WRONGWRONGWRONGWRONG"),
        T,
    );
    assert!(bad.is_err());
    let e = agent_conn::edge::enroll(
        &ca,
        "127.0.0.1",
        r.control.port(),
        &agent_proto::token_digest(EDGE_TOKEN),
        T,
    )
    .unwrap();
    assert_eq!(e.cert_sha256, r.edge.cert_sha256);
    assert!(
        agent_conn::edge::enroll(
            &ca,
            "127.0.0.1",
            r.control.port(),
            &agent_proto::token_digest(EDGE_TOKEN),
            T
        )
        .is_err(),
        "the token is single use"
    );
    let target = edge_target(&r, &e.cert_sha256);
    let lines = link_once(
        &ca,
        &target,
        vec![EdgeAgent {
            id: ID.into(),
            pins: vec![pin.clone()],
        }],
        EdgeLimits::default(),
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("edge-health ") && l.contains("\"configured\":true")),
        "{lines:?}"
    );

    // the appliance pushes the edge to the agent over a direct poll (v1.7 SetEdge)
    let poll_target = |edge: Option<EdgeTarget>, set_edge: Option<SetEdge>, host_port: u16| Target {
        id: ID.into(),
        host: "127.0.0.1".into(),
        port: host_port,
        pins: vec![pin.clone()],
        status: Default::default(),
        ack: vec![],
        summaries: vec![],
        edge,
        set_edge,
    };
    let v = poll_one(
        &ca,
        &poll_target(
            None,
            Some(SetEdge {
                addr: r.public.to_string(),
                cert_sha256: r.edge.cert_sha256.clone(),
            }),
            port,
        ),
        T,
    );
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["edge_set"], r.public.to_string());
    assert_eq!(v["info"]["via"], "direct");
    wait_for("the agent's rendezvous", 30, || {
        r.edge.health().agents_online == vec![ID.to_string()]
    });

    // the direct path is closed (a port nobody listens on): the session goes via the edge
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let route = Route {
        host: "127.0.0.1",
        port: closed,
        edge: Some(&target),
    };
    let mut s = Session::connect_route(&route, &ca, ID, session_config(&ca, ID, Some(&pin)).unwrap(), T).unwrap();
    assert_eq!(s.via, "edge");
    assert_eq!(s.hello(ID).unwrap().via, "edge");
    let store_dir = d.path().join("store");
    let store = Store::open(
        &store_dir,
        Keyring::new("acme", &[(1, [9; 32])]),
        Options {
            min_lock_secs: 0,
            gc_grace_secs: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let mut map = MapDb::open(&store_dir).unwrap();
    let spec = Spec {
        job: 1,
        paths: vec![data.to_string_lossy().into_owned()],
        excludes: vec![],
        hooks: false,
        filters: Default::default(),
        limits: Default::default(),
        file_hashes: false,
        full_read: None,
    };
    let rep = backup::backup(&store, &mut map, &mut s, ID, &spec, &mut |l| eprintln!("{l}")).unwrap();
    s.close();
    assert_eq!(rep.files, 2);
    assert!(rep.wanted_chunks > 0);

    // the edge saw only TLS records, never the payload
    {
        let tap = r.edge.tap.as_ref().unwrap().lock().unwrap();
        assert!(tap.len() >= 2);
        for dir in tap.iter().filter(|t| !t.is_empty()) {
            assert_tls_records(dir);
            assert!(
                !dir.windows(MARKER.len()).any(|w| w == MARKER),
                "payload visible to the edge"
            );
        }
    }

    // "back up now" on the laptop: the link hears it within seconds
    let (tx, rx) = mpsc::channel();
    let (ca2, t2) = (Ca::load_or_create(&d.path().join("ca")).unwrap(), target.clone());
    std::thread::spawn(move || {
        let spec = LinkSpec {
            agents: vec![EdgeAgent {
                id: ID.into(),
                pins: vec![enrolled.cert_sha256.clone()],
            }],
            limits: EdgeLimits::default(),
            update_dir: None,
            max_secs: 20,
            wait_secs: 10,
        };
        let _ = agent_conn::edge::link(&ca2, &t2, &spec, &mut |l| {
            let _ = tx.send(l);
        });
    });
    let t0 = Instant::now();
    let req = agent.ui.request_backup(agent_core::ui::now()).unwrap();
    let wake = loop {
        let l = rx.recv_timeout(Duration::from_secs(10)).expect("edge-wake line");
        if l.starts_with("edge-wake ") {
            break l;
        }
    };
    assert!(wake.contains(ID));
    assert!(t0.elapsed() < Duration::from_secs(5), "wake took {:?}", t0.elapsed());
    // ... and the poll through the edge fetches the request
    let v = poll_one(&ca, &poll_target(Some(target.clone()), None, closed), T);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["info"]["via"], "edge");
    assert_eq!(v["requests"][0]["id"], req.request_id.as_str());

    // removing the edge from the agent (direct path again) ends the rendezvous
    let v = poll_one(
        &ca,
        &poll_target(
            None,
            Some(SetEdge {
                addr: String::new(),
                cert_sha256: String::new(),
            }),
            port,
        ),
        T,
    );
    assert_eq!(v["edge_set"], "");
    assert!(!paths.edge().exists());
}

/// A rustls client with `cert`/`key` against the edge public port.
fn try_public(addr: SocketAddr, cert_pem: &str, key_pem: &str) -> std::io::Result<EdgeMsg> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    #[derive(Debug)]
    struct Any;
    impl rustls::client::danger::ServerCertVerifier for Any {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            nexus_edge::provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
    let certs: Vec<_> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(nexus_edge::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Any))
        .with_client_auth_cert(certs, key)
        .unwrap();
    cfg.alpn_protocols = vec![agent_proto::edge::ALPN.to_vec()];
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), ServerName::try_from("nexus-edge").unwrap()).unwrap();
    let mut s = rustls::StreamOwned::new(conn, tcp);
    agent_proto::edge::write(&mut s, &EdgeMsg::Wake, 4096)?;
    agent_proto::edge::read(&mut s, 4096)
}

/// (cert PEM, key PEM) for `CN=nexus-agent:<id>` signed by `ca`'s CA key, as at enrollment.
fn agent_cert(ca: &Ca, id: &str) -> (String, String) {
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, "x");
    let csr = p.serialize_request(&kp).unwrap().pem().unwrap();
    let (cert, _) = ca.sign_agent(&csr, id).unwrap();
    (cert, kp.serialize_pem())
}

#[test]
fn unknown_certificates_rate_limits_and_pairing() {
    let d = tempfile::tempdir().unwrap();
    let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
    let other = Ca::load_or_create(&d.path().join("other-ca")).unwrap();
    let r = start_edge(d.path(), false);

    // before enrollment and configuration nobody gets in on the public port
    let (cert, key) = agent_cert(&ca, ID);
    assert!(try_public(r.public, &cert, &key).is_err());

    let e = agent_conn::edge::enroll(
        &ca,
        "127.0.0.1",
        r.control.port(),
        &agent_proto::token_digest(EDGE_TOKEN),
        T,
    )
    .unwrap();
    let target = edge_target(&r, &e.cert_sha256);
    // another appliance (different client certificate) cannot use the control port
    let foreign = agent_conn::edge::link(&other, &target, &LinkSpec::default(), &mut |_| {});
    assert!(
        foreign.is_err(),
        "control port must refuse an unpinned appliance certificate"
    );

    let pin = agent_proto::edge::EdgeAgent {
        id: ID.into(),
        pins: vec![agent_conn::ca::sha256_hex(&agent_conn::ca::pem_to_der(&cert).unwrap())],
    };
    link_once(&ca, &target, vec![pin.clone()], EdgeLimits::default());
    // the pinned agent certificate is let in (a Wake is answered)
    assert_eq!(try_public(r.public, &cert, &key).unwrap(), EdgeMsg::Ok);
    // same CA, not pinned (another agent / a revoked certificate): refused in the handshake
    let (c2, k2) = agent_cert(&ca, "fedcba9876543210");
    assert!(try_public(r.public, &c2, &k2).is_err());
    // a certificate of another CA claiming the pinned id: refused
    let (c3, k3) = agent_cert(&other, ID);
    assert!(try_public(r.public, &c3, &k3).is_err());
    let refused = r.edge.health().refused;
    assert!(refused >= 2, "refused {refused}");

    // pairing: no rendezvous → 404; an unknown stream nonce is refused
    let err = match agent_conn::edge::open(&ca, &target, ID, T) {
        Err(e) => format!("{e:#}"),
        Ok(_) => panic!("open without rendezvous"),
    };
    assert!(err.contains("404"), "{err}");

    // rate limit per source IP: 6/min → a burst of 5, then dropped before TLS
    link_once(
        &ca,
        &target,
        vec![pin],
        EdgeLimits {
            per_ip_per_min: 6,
            ..Default::default()
        },
    );
    let before = r.edge.health().rate_limited;
    let ok = (0..10).filter(|_| try_public(r.public, &cert, &key).is_ok()).count();
    assert!(ok <= 5, "{ok} connections got through");
    assert!(r.edge.health().rate_limited >= before + 5);
}
