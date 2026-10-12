//! agent-conn against an in-process fake agent (tests/fake): enrollment incl.
//! a man in the middle, mTLS verification, backup → tree snapshot, incremental
//! runs, hostile agents, mapping-index recovery after GC, restore, downloads.

mod fake;

use agent_conn::backup::{self, Spec};
use agent_conn::ca::{sha256_hex, Ca};
use agent_conn::files::{self, Format};
use agent_conn::map::MapDb;
use agent_conn::restore::{self, Spec as RestoreSpec};
use agent_conn::tls::{session_config, Session};
use agent_conn::{enroll, source_name, update, TREE_INDEX};
use agent_proto::{read_msg, write_msg, Overwrite, ALPN};
use chunkstore::{Index, Keyring, Options, Store, TreeKind};
use fake::{FakeAgent, Malice};
use rcgen::{ExtendedKeyUsagePurpose, KeyPair};
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const ID: &str = "0123456789abcdef";
const TOKEN: &str = "MFRGGZDFMZTWQ2LKNNWG23TPOA";
const T: Duration = Duration::from_secs(20);

fn opts() -> Options {
    Options {
        min_lock_secs: 0,
        gc_grace_secs: 0,
        ..Default::default()
    }
}

fn rnd(n: usize, seed: u64) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ seed;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// A small host tree: nested dirs, multi-chunk file, empty file, symlink, xattr file.
fn make_tree(root: &Path) {
    fs::create_dir_all(root.join("etc/ssh")).unwrap();
    fs::create_dir_all(root.join("var/lib/db")).unwrap();
    fs::write(root.join("etc/hostname"), b"web01\n").unwrap();
    fs::write(root.join("etc/ssh/sshd_config"), b"PermitRootLogin no\n").unwrap();
    fs::set_permissions(root.join("etc/ssh/sshd_config"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.join("var/lib/db/data.bin"), rnd(300_000, 1)).unwrap();
    fs::write(root.join("var/lib/db/copy.bin"), rnd(300_000, 1)).unwrap(); // dedup
    fs::write(root.join("var/empty"), b"").unwrap();
    fs::write(root.join("var/label.xattr"), b"x").unwrap();
    std::os::unix::fs::symlink("../etc/hostname", root.join("var/host")).unwrap();
}

struct Env {
    _d: tempfile::TempDir,
    root: std::path::PathBuf,
    restored: std::path::PathBuf,
    store_dir: std::path::PathBuf,
    ca: Ca,
    agent: FakeAgent,
}

impl Env {
    fn new() -> Env {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("host");
        let restored = d.path().join("restored");
        make_tree(&root);
        let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
        let agent = FakeAgent::start(&root, &restored, Some(TOKEN));
        Env {
            store_dir: d.path().join("store"),
            root,
            restored,
            ca,
            agent,
            _d: d,
        }
    }
    fn store(&self) -> Store {
        Store::open(&self.store_dir, Keyring::new("acme", &[(1, [9; 32])]), opts()).unwrap()
    }
    fn enroll(&self) -> String {
        let e = enroll::enroll(
            &self.ca,
            "127.0.0.1",
            self.agent.port(),
            &agent_proto::token_digest(TOKEN),
            ID,
            T,
        )
        .unwrap();
        // EnrollDone has no answer: wait until the agent processed it (the CLI
        // confirms with an mTLS Hello instead)
        for _ in 0..500 {
            if self.agent.st.lock().unwrap().enrolled.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        e.cert_sha256
    }
    fn session(&self, pin: &str) -> Session {
        let mut s = Session::connect(
            "127.0.0.1",
            self.agent.port(),
            session_config(&self.ca, ID, Some(pin)).unwrap(),
            T,
        )
        .unwrap();
        s.hello(ID).unwrap();
        s
    }
    fn backup(&self, store: &Store, pin: &str, job: u64) -> anyhow::Result<backup::Report> {
        let mut map = MapDb::open(&self.store_dir).unwrap();
        let mut s = self.session(pin);
        let r = backup::backup(
            store,
            &mut map,
            &mut s,
            ID,
            &Spec {
                job,
                paths: vec!["/".into()],
                excludes: vec![],
                hooks: true,
                filters: Default::default(),
                limits: Default::default(),
            },
            &mut |l| eprintln!("{l}"),
        );
        s.close();
        r
    }
}

fn tree(store: &Store, time: u64) -> Vec<chunkstore::TreeEntry> {
    let m = store.load_manifest(&source_name(ID), time).unwrap();
    match store.load_index(&m, TREE_INDEX).unwrap() {
        Index::Tree { entries } => entries,
        _ => panic!("not a tree"),
    }
}

#[test]
fn enrollment_with_token_proofs_then_mtls() {
    let e = Env::new();
    // wrong token: the agent refuses, stays in enrollment mode
    let bad = enroll::enroll(
        &e.ca,
        "127.0.0.1",
        e.agent.port(),
        &agent_proto::token_digest("WRONG"),
        ID,
        T,
    );
    assert!(bad.is_err());
    assert_eq!(e.agent.st.lock().unwrap().failed_proofs, 1);
    assert!(e.agent.st.lock().unwrap().enrolled.is_none());

    let pin = e.enroll();
    {
        let st = e.agent.st.lock().unwrap();
        let (cert, _) = st.enrolled.as_ref().unwrap();
        assert_eq!(sha256_hex(pem::parse(cert).unwrap().contents()), pin);
        assert_eq!(st.agent_id.as_deref(), Some(ID));
        assert!(st.token_digest.is_none(), "token is single use");
    }
    let s = e.session(&pin);
    s.close();
    assert_eq!(
        e.agent.st.lock().unwrap().peer_cn.as_deref(),
        Some(format!("nexus-appliance:{}", e.ca.appliance_id).as_str())
    );
    // the token cannot be used a second time
    assert!(enroll::enroll(
        &e.ca,
        "127.0.0.1",
        e.agent.port(),
        &agent_proto::token_digest(TOKEN),
        ID,
        T
    )
    .is_err());
}

/// TLS-terminating relay between appliance and agent (both legs TLS 1.3).
fn mitm(agent_port: u16) -> u16 {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let key = KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["mitm".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut scfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        scfg.alpn_protocols = vec![ALPN.to_vec()];
        // the relay re-uses the appliance's enrollment client config shape (no validation)
        let ca = Ca::load_or_create(&tempfile::tempdir().unwrap().keep()).unwrap();
        let ccfg = agent_conn::tls::enroll_config(&ca).unwrap();
        for c in l.incoming() {
            let c = c.unwrap();
            let mut a = rustls::StreamOwned::new(rustls::ServerConnection::new(Arc::new(scfg.clone())).unwrap(), c);
            let up = std::net::TcpStream::connect(("127.0.0.1", agent_port)).unwrap();
            let mut b = rustls::StreamOwned::new(
                rustls::ClientConnection::new(ccfg.clone(), ServerName::try_from("x").unwrap()).unwrap(),
                up,
            );
            // relay request/response pairs at the message level
            while let Ok(m) = read_msg(&mut a) {
                if write_msg(&mut b, &m).is_err() {
                    break;
                }
                match read_msg(&mut b) {
                    Ok(r) => {
                        let _ = write_msg(&mut a, &r);
                    }
                    Err(_) => break,
                }
            }
        }
    });
    port
}

#[test]
fn man_in_the_middle_cannot_relay_enrollment() {
    let e = Env::new();
    let port = mitm(e.agent.port());
    let r = enroll::enroll(&e.ca, "127.0.0.1", port, &agent_proto::token_digest(TOKEN), ID, T);
    let err = format!("{:#}", r.err().expect("enrollment through a relay must fail"));
    assert!(err.contains("proof"), "{err}");
    let st = e.agent.st.lock().unwrap();
    assert!(st.enrolled.is_none(), "agent not enrolled");
    assert_eq!(
        st.failed_proofs, 1,
        "the agent saw an appliance proof for another session"
    );
}

#[test]
fn mtls_rejects_foreign_ca_wrong_cn_eku_and_pin() {
    let e = Env::new();
    let connect =
        |pin: Option<&str>| Session::connect("127.0.0.1", e.agent.port(), session_config(&e.ca, ID, pin).unwrap(), T);
    let ca_pem = e.ca.ca_pem.clone();
    // right CA, right CN: accepted without pin
    let key = KeyPair::generate().unwrap();
    let good =
        e.ca.issue(&key, &format!("nexus-agent:{ID}"), ExtendedKeyUsagePurpose::ServerAuth)
            .unwrap();
    e.agent.force_cert(key, good.clone(), ca_pem.clone());
    e.agent.st.lock().unwrap().agent_id = Some(ID.into());
    connect(None).unwrap().close();
    // … but not against the pin of another certificate
    assert!(connect(Some(&"00".repeat(32))).is_err());
    let pin = sha256_hex(pem::parse(&good).unwrap().contents());
    connect(Some(&pin)).unwrap().close();

    // certificate from another appliance's CA
    let other = Ca::load_or_create(&e._d.path().join("other-ca")).unwrap();
    let key = KeyPair::generate().unwrap();
    let foreign = other
        .issue(&key, &format!("nexus-agent:{ID}"), ExtendedKeyUsagePurpose::ServerAuth)
        .unwrap();
    // (the agent trusts our CA for the client side, so the handshake fails only on our side)
    e.agent.force_cert(key, foreign, ca_pem.clone());
    assert!(connect(None).is_err(), "foreign CA");

    // our CA, another agent's CN
    let key = KeyPair::generate().unwrap();
    let wrong =
        e.ca.issue(
            &key,
            "nexus-agent:fedcba9876543210",
            ExtendedKeyUsagePurpose::ServerAuth,
        )
        .unwrap();
    e.agent.force_cert(key, wrong, ca_pem.clone());
    assert!(connect(None).is_err(), "wrong CN");

    // our CA, right CN, but a client certificate (no serverAuth)
    let key = KeyPair::generate().unwrap();
    let client =
        e.ca.issue(&key, &format!("nexus-agent:{ID}"), ExtendedKeyUsagePurpose::ClientAuth)
            .unwrap();
    e.agent.force_cert(key, client, ca_pem);
    assert!(connect(None).is_err(), "EKU");
}

#[test]
fn hello_with_wrong_agent_id_is_refused() {
    let e = Env::new();
    let pin = e.enroll();
    e.agent.st.lock().unwrap().report_id = Some("fedcba9876543210".into());
    let mut s = Session::connect(
        "127.0.0.1",
        e.agent.port(),
        session_config(&e.ca, ID, Some(&pin)).unwrap(),
        T,
    )
    .unwrap();
    assert!(s.hello(ID).is_err());
}

#[test]
fn backup_incremental_and_restore_roundtrip() {
    let e = Env::new();
    let pin = e.enroll();
    let store = e.store();

    let r1 = e.backup(&store, &pin, 1).unwrap();
    assert!(r1.consistent && r1.base.is_none());
    let t1 = r1.time;
    let first_wanted = e.agent.st.lock().unwrap().wanted.len();
    // data.bin == copy.bin: 5 chunks each, transferred once; + 3 small files (empty has none)
    assert_eq!(first_wanted, 5 + 3);
    assert_eq!(e.agent.st.lock().unwrap().releases, vec![(1, true)]);

    // byte-exact via write_chunks, metadata kept
    let entries = tree(&store, t1);
    for en in entries.iter().filter(|x| x.kind == TreeKind::File) {
        let mut out = Vec::new();
        store.write_chunks(&en.chunks, &mut out).unwrap();
        let p = e.root.join(std::str::from_utf8(&en.path).unwrap());
        assert_eq!(out, fs::read(&p).unwrap(), "{p:?}");
    }
    let sshd = entries.iter().find(|x| x.path == b"etc/ssh/sshd_config").unwrap();
    assert_eq!(sshd.mode & 0o777, 0o600);
    let link = entries.iter().find(|x| x.path == b"var/host").unwrap();
    assert_eq!(
        (link.kind.clone(), link.link_target.as_deref()),
        (TreeKind::Symlink, Some(&b"../etc/hostname"[..]))
    );
    let xa = entries.iter().find(|x| x.path == b"var/label.xattr").unwrap();
    assert_eq!(xa.xattrs, vec![(b"user.test".to_vec(), b"value".to_vec())]);
    // the mapping index never lands in the snapshot data, only next to the store
    assert!(e.store_dir.join("agent-map.db").exists());

    // second run, nothing changed: base = t1, every file unchanged, no chunk transferred
    let r2 = e.backup(&store, &pin, 2).unwrap();
    assert_eq!(r2.base, Some(t1));
    assert!(r2.time > t1);
    assert_eq!(r2.wanted_chunks, 0);
    assert_eq!(r2.unchanged, 6);
    assert_eq!(e.agent.st.lock().unwrap().wanted.len(), first_wanted);
    assert_eq!(e.agent.st.lock().unwrap().scans[1].as_ref().unwrap().time, t1);

    // one file changes: only its new chunk travels
    fs::write(e.root.join("etc/hostname"), b"web02\n").unwrap();
    let r3 = e.backup(&store, &pin, 3).unwrap();
    assert_eq!(r3.wanted_chunks, 1);

    // restore everything below /etc and /var to /srv/restore on the agent
    let map = MapDb::open(&e.store_dir).unwrap();
    let mut s = e.session(&pin);
    let st = restore::restore(
        &store,
        &map,
        &mut s,
        &RestoreSpec {
            job: 4,
            source_agent: ID.into(),
            time: t1,
            paths: vec!["/".into()],
            target: "/srv/restore".into(),
            overwrite: Overwrite::Never,
            confirm: "web01".into(),
        },
        &mut |l| eprintln!("{l}"),
    )
    .unwrap();
    s.close();
    assert_eq!(st.files, 6);
    let out = e.restored.join("srv/restore");
    for f in [
        "etc/ssh/sshd_config",
        "var/lib/db/data.bin",
        "var/lib/db/copy.bin",
        "var/empty",
    ] {
        assert_eq!(fs::read(out.join(f)).unwrap(), fs::read(e.root.join(f)).unwrap(), "{f}");
    }
    assert_eq!(fs::read(out.join("etc/hostname")).unwrap(), b"web01\n", "t1 content");
    assert_eq!(
        fs::read_link(out.join("var/host")).unwrap(),
        Path::new("../etc/hostname")
    );
    assert_eq!(
        e.agent.st.lock().unwrap().restores,
        vec![("/srv/restore".to_string(), Overwrite::Never, "web01".to_string())]
    );

    // single subtree: parents are included, siblings not
    let sel = restore::select(&entries, &["/etc/ssh".into()]).unwrap();
    let names: Vec<_> = sel
        .iter()
        .map(|x| String::from_utf8_lossy(&x.path).into_owned())
        .collect();
    assert_eq!(names, ["etc", "etc/ssh", "etc/ssh/sshd_config"]);
    assert!(restore::select(&entries, &["/../etc".into()]).is_err());
}

#[test]
fn downloads_from_tree_snapshots() {
    let e = Env::new();
    let pin = e.enroll();
    let store = e.store();
    let t = e.backup(&store, &pin, 1).unwrap().time;
    let entries = tree(&store, t);
    let ls = files::list(&entries, "/var").unwrap();
    let names: Vec<_> = ls.iter().map(|x| (x.name.as_str(), x.kind)).collect();
    assert_eq!(
        names,
        [
            ("empty", "file"),
            ("host", "symlink"),
            ("label.xattr", "file"),
            ("lib", "dir")
        ]
    );
    let d = tempfile::tempdir().unwrap();
    let tarp = d.path().join("o.tar");
    let n = files::extract(
        &store,
        &entries,
        &["/var/lib".into(), "/var/label.xattr".into()],
        Format::Tar,
        fs::File::create(&tarp).unwrap(),
    )
    .unwrap();
    assert_eq!(n, 6, "var, var/label.xattr, var/lib, var/lib/db, 2 files");
    let mut a = tar::Archive::new(fs::File::open(&tarp).unwrap());
    let mut seen = Vec::new();
    for en in a.entries().unwrap() {
        let mut en = en.unwrap();
        let p = en.path().unwrap().to_string_lossy().into_owned();
        if p == "var/lib/db/data.bin" {
            let mut b = Vec::new();
            en.read_to_end(&mut b).unwrap();
            assert_eq!(b, rnd(300_000, 1));
        }
        if p == "var/label.xattr" {
            let x: Vec<_> = en
                .pax_extensions()
                .unwrap()
                .unwrap()
                .map(|x| x.unwrap().key().unwrap().to_owned())
                .collect();
            assert_eq!(x, ["SCHILY.xattr.user.test"]);
        }
        seen.push(p);
    }
    assert!(seen.contains(&"var/lib/db/copy.bin".to_string()));
    let zipp = d.path().join("o.zip");
    files::extract(
        &store,
        &entries,
        &["/etc".into()],
        Format::Zip,
        fs::File::create(&zipp).unwrap(),
    )
    .unwrap();
    let mut z = zip::ZipArchive::new(fs::File::open(&zipp).unwrap()).unwrap();
    let mut s = String::new();
    z.by_name("etc/ssh/sshd_config")
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    assert_eq!(s, "PermitRootLogin no\n");
    assert_eq!(
        z.by_name("etc/ssh/sshd_config").unwrap().unix_mode().unwrap() & 0o777,
        0o600
    );
}

#[test]
fn hostile_agent_data_is_rejected_and_nothing_committed() {
    for malice in [Malice::CorruptChunk, Malice::ExtraChunk] {
        let e = Env::new();
        let pin = e.enroll();
        let store = e.store();
        e.agent.st.lock().unwrap().malice = malice;
        let err = e.backup(&store, &pin, 7).expect_err("must fail");
        eprintln!("{malice:?}: {err:#}");
        assert!(
            store.list_snapshots().unwrap().is_empty(),
            "{malice:?}: nothing committed"
        );
        assert_eq!(e.agent.st.lock().unwrap().releases, vec![(7, false)], "{malice:?}");
        if malice == Malice::CorruptChunk {
            assert!(format!("{err:#}").contains("does not match"));
            assert!(
                MapDb::open(&e.store_dir).unwrap().is_empty().unwrap(),
                "no mapping for bad data"
            );
        }
        // the agent behaves again: the next backup is a full one (no base)
        e.agent.st.lock().unwrap().malice = Malice::None;
        let r = e.backup(&store, &pin, 8).unwrap();
        assert!(r.base.is_none());
    }
}

#[test]
fn mapped_chunk_removed_by_gc_is_transferred_again() {
    let e = Env::new();
    let pin = e.enroll();
    let store = e.store();
    let t1 = e.backup(&store, &pin, 1).unwrap().time;
    let entries = tree(&store, t1);
    let victim = entries.iter().find(|x| x.path == b"etc/hostname").unwrap().chunks[0];
    let hexid = agent_conn::hex(&victim);
    fs::remove_file(e.store_dir.join("chunks").join(&hexid[..4]).join(&hexid)).unwrap();
    let before = e.agent.st.lock().unwrap().wanted.len();
    let r = e.backup(&store, &pin, 2).unwrap();
    assert_eq!(r.wanted_chunks, 1, "only the missing chunk");
    assert_eq!(e.agent.st.lock().unwrap().wanted.len(), before + 1);
    assert_eq!(
        e.agent.st.lock().unwrap().wanted[before],
        *blake3::hash(b"web01\n").as_bytes()
    );
    let mut out = Vec::new();
    let t2 = tree(&store, r.time);
    let h = t2.iter().find(|x| x.path == b"etc/hostname").unwrap();
    store.write_chunks(&h.chunks, &mut out).unwrap();
    assert_eq!(out, b"web01\n");

    // a lost mapping index only costs a re-transfer (chunks are not new in the store)
    for f in ["agent-map.db", "agent-map.db-wal", "agent-map.db-shm"] {
        let _ = fs::remove_file(e.store_dir.join(f));
    }
    let r = e.backup(&store, &pin, 3).unwrap();
    assert_eq!(r.wanted_chunks, 8);
    assert_eq!(r.new_chunks, 0);
}

#[test]
fn inconsistent_scan_is_reported() {
    let e = Env::new();
    let pin = e.enroll();
    let store = e.store();
    e.agent.st.lock().unwrap().consistent = false;
    let r = e.backup(&store, &pin, 1).unwrap();
    assert!(!r.consistent);
    assert_eq!(r.inconsistent_files, 12);
    assert!(tree(&store, r.time).iter().all(|x| x.inconsistent));
}

#[test]
fn update_is_pushed() {
    let e = Env::new();
    let pin = e.enroll();
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("nexus-agent"), vec![0x7f; 1000]).unwrap();
    fs::write(d.path().join("nexus-agent.sig"), b"MEUCIQ...").unwrap();
    fs::write(d.path().join("nexus-agent.version"), b"0.2.0\n").unwrap();
    let b = update::load(d.path()).unwrap();
    let mut s = e.session(&pin);
    update::push(&mut s, &b).unwrap();
    s.close();
    assert_eq!(e.agent.st.lock().unwrap().updates, vec![("0.2.0".into(), 1000, 9)]);
    fs::write(d.path().join("nexus-agent"), vec![0; agent_proto::MAX_FRAME]).unwrap();
    assert!(update::load(d.path()).is_err(), "too large for one frame");
}
