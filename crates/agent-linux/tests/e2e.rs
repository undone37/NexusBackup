//! End-to-end: an in-process fake appliance (rustls client, test CA) enrolls the agent,
//! backs up a directory twice (fallback mode, second run incremental against the
//! metadata cache) and restores it into a fresh directory. Also: MITM on enrollment,
//! enrollment lock-out, and client-certificate checks in mTLS mode. No root needed.

use agent_proto::*;
use nexus_agent::config::{Paths, Settings};
use nexus_agent::server::{Agent, E_AUTH, E_CHUNKS_GONE, E_LOCKED};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned};
use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type Client = StreamOwned<ClientConnection, TcpStream>;
const TOKEN: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ca {
        cert: p.self_signed(&key).unwrap(),
        key,
    }
}

/// (cert PEM, key PEM) for an appliance client certificate.
fn client_cert(ca: &Ca, cn: &str, client_auth: bool) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.extended_key_usages = if client_auth {
        vec![ExtendedKeyUsagePurpose::ClientAuth]
    } else {
        vec![ExtendedKeyUsagePurpose::ServerAuth]
    };
    let c = p.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (c.pem(), key.serialize_pem())
}

fn handshake(addr: SocketAddr, cfg: Arc<ClientConfig>, name: &str) -> std::io::Result<Client> {
    let tcp = TcpStream::connect(addr)?;
    let conn =
        ClientConnection::new(cfg, ServerName::try_from(name.to_string()).unwrap()).map_err(std::io::Error::other)?;
    let mut s = StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    Ok(s)
}

fn enroll_client() -> Arc<ClientConfig> {
    let mut c = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    c.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(c)
}

fn mtls_client(ca: &Ca, client: Option<(String, String)>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert.der().clone()).unwrap();
    let b = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    let mut c = match client {
        Some((cert, key)) => b
            .with_client_auth_cert(
                CertificateDer::pem_slice_iter(cert.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
            )
            .unwrap(),
        None => b.with_no_client_auth(),
    };
    c.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(c)
}

fn exporter(s: &Client) -> [u8; 32] {
    let mut ex = [0u8; 32];
    s.conn.export_keying_material(&mut ex, EXPORTER_LABEL, None).unwrap();
    ex
}

fn start_agent(dir: &Path) -> (Paths, SocketAddr) {
    let paths = Paths {
        config: dir.join("etc"),
        state: dir.join("state"),
        run: dir.join("run"),
    };
    nexus_agent::init(&paths, TOKEN, None).unwrap();
    let settings = Settings {
        hook_owner: nexus_agent::sys::geteuid(),
        hook_timeout_secs: 30,
        ..Default::default()
    };
    let mut agent = Agent::new(paths.clone(), settings).unwrap();
    agent.exit_on_update = false;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let agent = Arc::new(agent);
    std::thread::spawn(move || agent.serve(l));
    (paths, addr)
}

/// Full appliance-side enrollment. Returns the CA used.
fn enroll(addr: SocketAddr, agent_id: &str) -> Ca {
    let ca = ca("nexus test appliance CA");
    let mut s = handshake(addr, enroll_client(), "agent.invalid").unwrap();
    let ex = exporter(&s);
    let key = token_digest(TOKEN);
    write_msg(
        &mut s,
        &Message::Enroll {
            proof: enroll_proof(&key, "appliance", &ex),
        },
    )
    .unwrap();
    let Message::EnrollReply { proof, csr_pem } = read_msg(&mut s).unwrap() else {
        panic!("no EnrollReply")
    };
    assert!(
        proof_eq(&proof, &enroll_proof(&key, "agent", &ex)),
        "agent proves the token too"
    );
    let mut csr = rcgen::CertificateSigningRequestParams::from_pem(&csr_pem).unwrap();
    csr.params.distinguished_name = rcgen::DistinguishedName::new();
    csr.params
        .distinguished_name
        .push(DnType::CommonName, format!("nexus-agent:{agent_id}"));
    csr.params.subject_alt_names = vec![rcgen::SanType::DnsName(
        format!("{agent_id}.agent.nexus").try_into().unwrap(),
    )];
    csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = csr.signed_by(&ca.cert, &ca.key).unwrap();
    write_msg(
        &mut s,
        &Message::EnrollDone {
            cert_pem: cert.pem(),
            ca_pem: ca.cert.pem(),
            agent_id: agent_id.into(),
        },
    )
    .unwrap();
    // the agent closes the enrollment connection
    assert!(read_msg(&mut s).is_err());
    ca
}

fn session(addr: SocketAddr, ca: &Ca, agent_id: &str) -> Client {
    let client = client_cert(ca, "nexus-appliance:appl-1", true);
    let mut s = handshake(addr, mtls_client(ca, Some(client)), &format!("{agent_id}.agent.nexus")).unwrap();
    write_msg(&mut s, &Message::Hello { version: VERSION }).unwrap();
    match read_msg(&mut s).unwrap() {
        Message::HelloReply {
            version,
            agent_id: id,
            agent_version,
            caps,
            ..
        } => {
            assert_eq!(version, VERSION);
            assert_eq!(id, agent_id);
            assert_eq!(agent_version, env!("CARGO_PKG_VERSION"));
            assert!(caps.iter().any(|c| c == "fallback"));
        }
        m => panic!("unexpected {m:?}"),
    }
    s
}

struct Backup {
    entries: Vec<Entry>,
    stats: ScanStats,
    consistent: bool,
    hook_log: String,
}

/// Prepare → Scan → Want (everything not yet in `store`) → Release.
fn backup(
    s: &mut Client,
    job: u64,
    data: &Path,
    base: Option<u64>,
    store: &mut HashMap<Hash, Vec<u8>>,
    success: bool,
) -> Backup {
    write_msg(
        s,
        &Message::Prepare {
            job,
            paths: vec![data.to_string_lossy().into_owned()],
            excludes: vec!["*.skip".into()],
            hooks: true,
        },
    )
    .unwrap();
    let (consistent, mut hook_log) = match read_msg(s).unwrap() {
        Message::Prepared {
            job: j,
            snapshots,
            consistent,
            hook_log,
        } => {
            assert_eq!(j, job);
            assert!(snapshots.is_empty());
            (consistent, hook_log)
        }
        m => panic!("unexpected {m:?}"),
    };
    write_msg(
        s,
        &Message::Scan {
            job,
            base: base.map(|time| BaseRef { time }),
        },
    )
    .unwrap();
    let mut entries = vec![];
    let stats = loop {
        match read_msg(s).unwrap() {
            Message::Entries { batch } => entries.extend(batch),
            Message::ScanDone { stats } => break stats,
            m => panic!("unexpected {m:?}"),
        }
    };
    let mut want: Vec<Hash> = entries
        .iter()
        .flat_map(|e| e.chunks.iter().map(|c| c.0))
        .filter(|h| !store.contains_key(h))
        .collect();
    want.sort();
    want.dedup();
    write_msg(
        s,
        &Message::Want {
            job,
            hashes: want.clone(),
        },
    )
    .unwrap();
    let mut got = 0;
    loop {
        match read_msg(s).unwrap() {
            Message::Chunk { hash, data } => {
                assert_eq!(blake3::hash(&data).as_bytes(), &hash, "appliance verifies every chunk");
                store.insert(hash, data);
                got += 1;
            }
            Message::WantDone => break,
            m => panic!("unexpected {m:?}"),
        }
    }
    assert_eq!(got, want.len());
    write_msg(s, &Message::Release { job, success }).unwrap();
    match read_msg(s).unwrap() {
        Message::Released { job: j, hook_log: l } => {
            assert_eq!(j, job);
            hook_log.push_str(&l);
        }
        m => panic!("unexpected {m:?}"),
    }
    Backup {
        entries,
        stats,
        consistent,
        hook_log,
    }
}

fn write_hook(paths: &Paths, phase: &str, name: &str, body: &str) {
    let d = paths.hooks().join(phase);
    fs::create_dir_all(&d).unwrap();
    for p in [paths.hooks(), d.clone()] {
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let f = d.join(name);
    fs::write(&f, format!("#!/bin/sh\nset -e\n{body}\n")).unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o700)).unwrap();
}

fn rel(e: &Entry) -> PathBuf {
    PathBuf::from(String::from_utf8(e.path.clone()).unwrap())
}

#[test]
fn enroll_backup_incremental_restore() {
    // a data file system (not tmpfs: volumes on tmpfs are refused like /proc)
    let t = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let (paths, addr) = start_agent(&t.path().join("agent"));
    let data = t.path().join("data");
    fs::create_dir_all(data.join("sub/deeper")).unwrap();
    let mut x = 0x2545F4914F6CDD1Du64;
    let big: Vec<u8> = (0..6_000_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    fs::write(data.join("big.bin"), &big).unwrap();
    fs::write(data.join("small.txt"), b"hello world\n").unwrap();
    fs::write(data.join("sub/deeper/c"), b"c").unwrap();
    fs::write(data.join("empty"), b"").unwrap();
    fs::write(data.join("ignored.skip"), b"x").unwrap();
    fs::set_permissions(data.join("small.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(data.join("sub"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::hard_link(data.join("small.txt"), data.join("sub/hard")).unwrap();
    std::os::unix::fs::symlink("../small.txt", data.join("sub/sym")).unwrap();
    let mkfifo = std::ffi::CString::new(data.join("fifo").to_str().unwrap()).unwrap();
    // SAFETY: valid C string
    assert_eq!(unsafe { libc::mkfifo(mkfifo.as_ptr(), 0o600) }, 0);
    let xattr_ok = {
        let f = fs::File::open(data.join("small.txt")).unwrap();
        nexus_agent::sys::fsetxattr(std::os::fd::AsRawFd::as_raw_fd(&f), b"user.nexus", b"tagged").is_ok()
    };
    // a pre hook that "dumps a database" into the backed-up tree
    write_hook(
        &paths,
        "pre",
        "10-dump",
        &format!(
            "echo dumping job $NEXUS_JOB\nprintf 'CREATE TABLE t;\\n' > '{}/dump.sql'",
            data.display()
        ),
    );
    write_hook(&paths, "post", "10-done", "echo post success=$NEXUS_SUCCESS");

    // -- MITM on enrollment: the relayed proof does not verify on the agent's leg
    mitm_enrollment_fails(addr);
    assert_eq!(fs::read_to_string(paths.failures()).unwrap(), "1");

    // -- enrollment
    let ca = enroll(addr, "agent42");
    assert!(!paths.token().exists(), "token deleted after enrollment");
    assert!(!paths.failures().exists());
    assert_eq!(fs::read_to_string(paths.agent_id()).unwrap(), "agent42");
    // enrollment is over: a second Enroll attempt does not even get a TLS session
    assert!(handshake(addr, enroll_client(), "x")
        .and_then(|mut s| read_msg(&mut s).map(drop))
        .is_err());

    // -- mTLS client checks
    mtls_rejections(addr, &ca);

    // -- backup 1 (full)
    let mut s = session(addr, &ca, "agent42");
    write_msg(&mut s, &Message::ListVolumes).unwrap();
    match read_msg(&mut s).unwrap() {
        Message::Volumes { list } => assert!(list
            .iter()
            .any(|v| v.mountpoint == "/" || data.starts_with(&v.mountpoint))),
        m => panic!("unexpected {m:?}"),
    }
    let mut store = HashMap::new();
    let b1 = backup(&mut s, 1, &data, None, &mut store, true);
    assert!(
        !b1.consistent,
        "no snapshot without root: fallback mode reported honestly"
    );
    assert!(b1.hook_log.contains("dumping job 1"), "{}", b1.hook_log);
    assert!(b1.hook_log.contains("post success=1"), "{}", b1.hook_log);
    assert!(b1.stats.errors.is_empty(), "{:?}", b1.stats.errors);
    assert_eq!(b1.stats.unchanged, 0);
    assert!(
        !b1.entries.iter().any(|e| e.path.ends_with(b"ignored.skip")),
        "excluded"
    );
    assert!(
        b1.entries.iter().any(|e| e.path.ends_with(b"dump.sql")),
        "hook output is backed up"
    );
    let hard = b1.entries.iter().find(|e| e.path.ends_with(b"sub/hard")).unwrap();
    assert_eq!(hard.kind, Kind::Hardlink);
    let small = b1.entries.iter().find(|e| e.path.ends_with(b"small.txt")).unwrap();
    if xattr_ok {
        assert!(small.xattrs.iter().any(|(k, v)| k == b"user.nexus" && v == b"tagged"));
    }
    let full_read = b1.stats.read_bytes;
    assert!(full_read >= big.len() as u64);

    // Want for a chunk the agent never saw -> error, connection stays usable
    write_msg(
        &mut s,
        &Message::Prepare {
            job: 99,
            paths: vec![data.to_string_lossy().into()],
            excludes: vec![],
            hooks: false,
        },
    )
    .unwrap();
    assert!(matches!(read_msg(&mut s).unwrap(), Message::Prepared { .. }));
    write_msg(&mut s, &Message::Scan { job: 99, base: None }).unwrap();
    while !matches!(read_msg(&mut s).unwrap(), Message::ScanDone { .. }) {}
    write_msg(
        &mut s,
        &Message::Want {
            job: 99,
            hashes: vec![[7u8; 32]],
        },
    )
    .unwrap();
    assert!(matches!(
        read_msg(&mut s).unwrap(),
        Message::Error {
            code: E_CHUNKS_GONE,
            ..
        }
    ));
    write_msg(
        &mut s,
        &Message::Release {
            job: 99,
            success: false,
        },
    )
    .unwrap();
    assert!(matches!(read_msg(&mut s).unwrap(), Message::Released { .. }));

    // -- backup 2 (incremental): only the modified file (and the fresh dump) are read
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(data.join("sub/deeper/c"), b"c changed").unwrap();
    let b2 = backup(&mut s, 2, &data, Some(1_000), &mut store, true);
    let dump_len = fs::metadata(data.join("dump.sql")).unwrap().len();
    assert_eq!(b2.stats.read_bytes, 9 + dump_len, "unchanged files are not re-read");
    let unchanged: Vec<_> = b2.entries.iter().filter(|e| e.unchanged).map(rel).collect();
    assert!(unchanged.iter().any(|p| p.ends_with("big.bin")));
    assert!(unchanged.iter().any(|p| p.ends_with("small.txt")));
    assert!(!unchanged.iter().any(|p| p.ends_with("sub/deeper/c")));
    let big2 = b2.entries.iter().find(|e| e.path.ends_with(b"big.bin")).unwrap();
    let big1 = b1.entries.iter().find(|e| e.path.ends_with(b"big.bin")).unwrap();
    assert_eq!(big2.chunks, big1.chunks);

    // -- a failed backup does not commit its cache: backup 3 (failed) then 4 still see
    //    the cache of backup 2
    fs::write(data.join("small.txt"), b"hello again\n").unwrap();
    let b3 = backup(&mut s, 3, &data, Some(2_000), &mut store, false);
    assert!(b3.hook_log.contains("post success=0"));
    let b4 = backup(&mut s, 4, &data, Some(2_000), &mut store, true);
    assert_eq!(
        b4.stats.read_bytes,
        12 + dump_len,
        "small.txt re-read: cache of the failed job was not committed"
    );
    drop(s);

    // -- restore the last backup into a fresh directory
    let target = t.path().join("restore");
    let mut s = session(addr, &ca, "agent42");
    write_msg(
        &mut s,
        &Message::RestoreBegin {
            job: 50,
            target: target.to_string_lossy().into(),
            overwrite: Overwrite::Never,
            confirm: "CONFIRM-1234".into(),
        },
    )
    .unwrap();
    assert!(matches!(read_msg(&mut s).unwrap(), Message::RestoreReady));
    for batch in b4.entries.chunks(3) {
        write_msg(&mut s, &Message::RestoreEntries { batch: batch.to_vec() }).unwrap();
    }
    let mut sent = std::collections::HashSet::new();
    for e in &b4.entries {
        for (h, _) in &e.chunks {
            if sent.insert(*h) {
                write_msg(
                    &mut s,
                    &Message::RestoreChunk {
                        hash: *h,
                        data: store[h].clone(),
                    },
                )
                .unwrap();
            }
        }
    }
    write_msg(&mut s, &Message::RestoreEnd).unwrap();
    let stats = match read_msg(&mut s).unwrap() {
        Message::RestoreDone { stats } => stats,
        m => panic!("unexpected {m:?}"),
    };
    assert!(stats.errors.is_empty(), "{:?}", stats.errors);
    // byte + metadata comparison against the live tree
    let mut compared = 0;
    for e in &b4.entries {
        let orig = Path::new("/").join(rel(e));
        let rest = target.join(rel(e));
        let (om, rm) = (
            fs::symlink_metadata(&orig).unwrap(),
            fs::symlink_metadata(&rest).unwrap(),
        );
        assert_eq!(om.file_type(), rm.file_type(), "{}", orig.display());
        assert_eq!(om.mode(), rm.mode(), "{}", orig.display());
        assert_eq!((om.uid(), om.gid()), (rm.uid(), rm.gid()));
        if !om.is_dir() {
            assert_eq!(
                (om.mtime(), om.mtime_nsec()),
                (rm.mtime(), rm.mtime_nsec()),
                "{}",
                orig.display()
            );
        }
        if om.is_file() {
            assert_eq!(fs::read(&orig).unwrap(), fs::read(&rest).unwrap(), "{}", orig.display());
        }
        if om.file_type().is_symlink() {
            assert_eq!(fs::read_link(&orig).unwrap(), fs::read_link(&rest).unwrap());
        }
        assert_eq!(
            nexus_agent::sys::lxattrs(&orig).unwrap(),
            nexus_agent::sys::lxattrs(&rest).unwrap()
        );
        compared += 1;
    }
    assert!(compared >= 10, "{compared}");
    let rdata = target.join(data.strip_prefix("/").unwrap());
    assert_eq!(
        fs::metadata(rdata.join("sub/hard")).unwrap().ino(),
        fs::metadata(rdata.join("small.txt")).unwrap().ino()
    );
    // directory times are applied after their children were written
    let (od, rd) = (
        fs::metadata(data.join("sub")).unwrap(),
        fs::metadata(rdata.join("sub")).unwrap(),
    );
    assert_eq!((od.mtime(), od.mtime_nsec()), (rd.mtime(), rd.mtime_nsec()));
    // second restore with Never keeps everything and reports it
    write_msg(
        &mut s,
        &Message::RestoreBegin {
            job: 51,
            target: target.to_string_lossy().into(),
            overwrite: Overwrite::Never,
            confirm: "C".into(),
        },
    )
    .unwrap();
    assert!(matches!(read_msg(&mut s).unwrap(), Message::RestoreReady));
    write_msg(
        &mut s,
        &Message::RestoreEntries {
            batch: b4.entries.iter().filter(|e| e.kind == Kind::File).cloned().collect(),
        },
    )
    .unwrap();
    write_msg(&mut s, &Message::RestoreEnd).unwrap();
    match read_msg(&mut s).unwrap() {
        Message::RestoreDone { stats } => assert!(stats.errors.is_empty(), "{:?}", stats.errors),
        m => panic!("unexpected {m:?}"),
    }
    // restore onto / without Always is refused
    write_msg(
        &mut s,
        &Message::RestoreBegin {
            job: 52,
            target: "/".into(),
            overwrite: Overwrite::IfOlder,
            confirm: "C".into(),
        },
    )
    .unwrap();
    assert!(matches!(read_msg(&mut s).unwrap(), Message::Error { .. }));
    // an update that is not signed by a pinned key is refused
    write_msg(
        &mut s,
        &Message::Update {
            version: "9.9.9".into(),
            binary: b"\x7fELF".to_vec(),
            signature: b"AAAA".to_vec(),
        },
    )
    .unwrap();
    assert!(matches!(read_msg(&mut s).unwrap(), Message::Error { .. }));
}

/// Appliance ⇄ MITM ⇄ agent with two TLS sessions: the appliance's proof is bound to
/// its own leg, so the agent rejects it when the MITM relays it.
fn mitm_enrollment_fails(agent: SocketAddr) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["mitm".to_string()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, "nexus-agent enrollment");
    let cert = p.self_signed(&key).unwrap();
    let mut scfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    scfg.alpn_protocols = vec![ALPN.to_vec()];
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let mitm_addr = l.local_addr().unwrap();
    let relay = std::thread::spawn(move || {
        let (tcp, _) = l.accept().unwrap();
        let mut a = StreamOwned::new(rustls::ServerConnection::new(Arc::new(scfg)).unwrap(), tcp);
        while a.conn.is_handshaking() {
            a.conn.complete_io(&mut a.sock).unwrap();
        }
        let mut b = handshake(agent, enroll_client(), "agent").unwrap();
        let m = read_msg(&mut a).unwrap();
        write_msg(&mut b, &m).unwrap();
        let reply = read_msg(&mut b).unwrap();
        write_msg(&mut a, &reply).unwrap();
        reply
    });
    let mut s = handshake(mitm_addr, enroll_client(), "agent").unwrap();
    let ex = exporter(&s);
    write_msg(
        &mut s,
        &Message::Enroll {
            proof: enroll_proof(&token_digest(TOKEN), "appliance", &ex),
        },
    )
    .unwrap();
    match read_msg(&mut s).unwrap() {
        Message::Error { code, .. } => assert_eq!(code, E_AUTH),
        m => panic!("MITM relay must fail, got {m:?}"),
    }
    assert!(matches!(relay.join().unwrap(), Message::Error { code: E_AUTH, .. }));
}

fn mtls_rejections(addr: SocketAddr, ca: &Ca) {
    let try_hello = |cfg: Arc<ClientConfig>| -> bool {
        match handshake(addr, cfg, "agent42.agent.nexus") {
            Err(_) => false,
            Ok(mut s) => {
                write_msg(&mut s, &Message::Hello { version: VERSION }).is_ok()
                    && matches!(read_msg(&mut s), Ok(Message::HelloReply { .. }))
            }
        }
    };
    assert!(!try_hello(mtls_client(ca, None)), "no client certificate");
    assert!(
        !try_hello(mtls_client(ca, Some(client_cert(ca, "nexus-agent:evil", true)))),
        "wrong CN prefix"
    );
    assert!(
        !try_hello(mtls_client(ca, Some(client_cert(ca, "nexus-appliance:x", false)))),
        "no clientAuth EKU"
    );
    let other = ca_other();
    assert!(
        !try_hello(mtls_client(ca, Some(client_cert(&other, "nexus-appliance:x", true)))),
        "foreign CA"
    );
    assert!(try_hello(mtls_client(
        ca,
        Some(client_cert(ca, "nexus-appliance:x", true))
    )));
    // wrong protocol version is refused
    let mut s = handshake(
        addr,
        mtls_client(ca, Some(client_cert(ca, "nexus-appliance:x", true))),
        "agent42.agent.nexus",
    )
    .unwrap();
    write_msg(&mut s, &Message::Hello { version: VERSION + 1 }).unwrap();
    assert!(matches!(read_msg(&mut s).unwrap(), Message::Error { .. }));
}

fn ca_other() -> Ca {
    ca("some other CA")
}

#[test]
fn enrollment_locks_after_five_failed_proofs_until_reinit() {
    let t = tempfile::tempdir().unwrap();
    let (paths, addr) = start_agent(t.path());
    for i in 1..=5 {
        let mut s = handshake(addr, enroll_client(), "agent").unwrap();
        write_msg(&mut s, &Message::Enroll { proof: [i as u8; 32] }).unwrap();
        assert!(matches!(read_msg(&mut s).unwrap(), Message::Error { code: E_AUTH, .. }));
    }
    // even the right proof is refused now
    let mut s = handshake(addr, enroll_client(), "agent").unwrap();
    let ex = exporter(&s);
    let _ = write_msg(
        &mut s,
        &Message::Enroll {
            proof: enroll_proof(&token_digest(TOKEN), "appliance", &ex),
        },
    );
    assert!(matches!(
        read_msg(&mut s).unwrap(),
        Message::Error { code: E_LOCKED, .. }
    ));
    assert!(nexus_agent::status(&paths).contains("LOCKED"));
    // wrong ALPN is refused before anything else
    let mut c = (*enroll_client()).clone();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    assert!(handshake(addr, Arc::new(c), "agent")
        .and_then(|mut s| read_msg(&mut s).map(drop))
        .is_err());
    // re-init resets the lock; a new agent process (service restart) can enroll
    nexus_agent::init(&paths, TOKEN, None).unwrap();
    assert!(nexus_agent::status(&paths).contains("enrollment pending (0 failed proofs)"));
}
