//! Minimal in-process agent (rustls server on agent-proto): enrollment,
//! Hello, Prepare/Scan of a directory tree (fixed-size chunks, metadata cache
//! for `unchanged`), Want/Chunk, Release, Restore into a local directory,
//! Update. Knobs simulate hostile agents.

#![allow(dead_code)]

use agent_proto::*;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Malice {
    None,
    /// chunk data does not match the hash
    CorruptChunk,
    /// sends a chunk nobody asked for
    ExtraChunk,
}

#[derive(Clone)]
pub struct CacheEntry {
    size: u64,
    mtime: i64,
    ctime: i64,
    inode: u64,
    chunks: Vec<(Hash, u32)>,
}

pub struct State {
    pub token_digest: Option<String>,
    pub key: KeyPair,
    pub self_signed: String,
    /// mTLS mode once set: (cert pem, ca pem)
    pub enrolled: Option<(String, String)>,
    pub agent_id: Option<String>,
    /// id reported in HelloReply (default: agent_id)
    pub report_id: Option<String>,
    pub root: PathBuf,
    pub restore_root: PathBuf,
    pub failed_proofs: u32,
    pub cache: Option<HashMap<Vec<u8>, CacheEntry>>,
    pending: Option<HashMap<Vec<u8>, CacheEntry>>,
    data: HashMap<Hash, Vec<u8>>,
    pub wanted: Vec<Hash>,
    pub scans: Vec<Option<BaseRef>>,
    pub releases: Vec<(u64, bool)>,
    pub restores: Vec<(String, Overwrite, String)>,
    /// every entry of every restore, as received
    pub received: Vec<Entry>,
    pub malice: Malice,
    pub consistent: bool,
    pub version: String,
    pub updates: Vec<(String, usize, usize)>,
    /// appliance client cert CN seen in the last mTLS session
    pub peer_cn: Option<String>,
}

pub struct FakeAgent {
    pub addr: SocketAddr,
    pub st: Arc<Mutex<State>>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn der(pem: &str) -> Vec<u8> {
    pem::parse(pem).unwrap().contents().to_vec()
}

impl FakeAgent {
    pub fn start(root: &Path, restore_root: &Path, token: Option<&str>) -> FakeAgent {
        let key = KeyPair::generate().unwrap();
        let self_signed = CertificateParams::new(vec!["fake-agent".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        let st = Arc::new(Mutex::new(State {
            token_digest: token.map(token_digest),
            key,
            self_signed,
            enrolled: None,
            agent_id: None,
            report_id: None,
            root: root.to_owned(),
            restore_root: restore_root.to_owned(),
            failed_proofs: 0,
            cache: None,
            pending: None,
            data: HashMap::new(),
            wanted: Vec::new(),
            scans: Vec::new(),
            releases: Vec::new(),
            restores: Vec::new(),
            received: Vec::new(),
            malice: Malice::None,
            consistent: true,
            version: "0.1.0".into(),
            updates: Vec::new(),
            peer_cn: None,
        }));
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let st2 = st.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { continue };
                let st = st2.clone();
                // one session at a time, like the real agent's per-connection handling
                let _ = serve(s, &st);
            }
        });
        FakeAgent { addr, st }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Switch to mTLS mode with an arbitrary certificate (tests of the appliance verifier).
    pub fn force_cert(&self, key: KeyPair, cert_pem: String, ca_pem: String) {
        let mut s = self.st.lock().unwrap();
        s.key = key;
        s.enrolled = Some((cert_pem, ca_pem));
    }
}

fn server_config(st: &State) -> Arc<ServerConfig> {
    let b = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(st.key.serialize_der()));
    let mut cfg = match &st.enrolled {
        None => b
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(der(&st.self_signed))], key)
            .unwrap(),
        Some((cert, ca)) => {
            let mut roots = RootCertStore::empty();
            roots.add(CertificateDer::from(der(ca))).unwrap();
            let v = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .unwrap();
            b.with_client_cert_verifier(v)
                .with_single_cert(vec![CertificateDer::from(der(cert))], key)
                .unwrap()
        }
    };
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(cfg)
}

fn cn(der: &[u8]) -> Option<String> {
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = c.subject().iter_common_name().next()?.as_str().ok()?.to_owned();
    Some(cn)
}

type Tls = StreamOwned<ServerConnection, TcpStream>;

fn serve(tcp: TcpStream, st: &Arc<Mutex<State>>) -> std::io::Result<()> {
    let cfg = server_config(&st.lock().unwrap());
    let mtls = st.lock().unwrap().enrolled.is_some();
    let conn = ServerConnection::new(cfg).map_err(std::io::Error::other)?;
    let mut s = StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    if mtls {
        let peer = s.conn.peer_certificates().and_then(|c| c.first()).and_then(|c| cn(c));
        if !peer.as_deref().is_some_and(|c| c.starts_with("nexus-appliance:")) {
            return Ok(());
        }
        st.lock().unwrap().peer_cn = peer;
    }
    let mut restore: Option<Restore> = None;
    loop {
        let m = match read_msg(&mut s) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        let mut g = st.lock().unwrap();
        if !mtls {
            enroll_step(&mut s, &mut g, m)?;
            if g.enrolled.is_some() || g.token_digest.is_none() {
                return Ok(());
            }
            continue;
        }
        match m {
            Message::Hello { .. } => {
                let id = g.report_id.clone().or(g.agent_id.clone()).unwrap_or_default();
                write_msg(
                    &mut s,
                    &Message::HelloReply {
                        version: VERSION,
                        agent_id: id,
                        os: "Debian GNU/Linux 13".into(),
                        kernel: "6.12".into(),
                        hostname: "fake".into(),
                        agent_version: g.version.clone(),
                        caps: vec!["scan".into(), "restore".into()],
                    },
                )?;
            }
            Message::Prepare { job, .. } => write_msg(
                &mut s,
                &Message::Prepared {
                    job,
                    snapshots: vec![],
                    consistent: g.consistent,
                    hook_log: "pre-hook ok\n".into(),
                },
            )?,
            Message::Scan { base, .. } => scan(&mut s, &mut g, base)?,
            Message::Want { hashes, .. } => {
                for h in hashes {
                    g.wanted.push(h);
                    let mut data = g.data.get(&h).cloned().unwrap_or_default();
                    if g.malice == Malice::CorruptChunk {
                        data[0] ^= 0xff;
                    }
                    write_msg(&mut s, &Message::Chunk { hash: h, data })?;
                }
                if g.malice == Malice::ExtraChunk {
                    write_msg(
                        &mut s,
                        &Message::Chunk {
                            hash: *blake3::hash(b"x").as_bytes(),
                            data: b"x".to_vec(),
                        },
                    )?;
                }
                write_msg(&mut s, &Message::WantDone)?;
            }
            Message::Release { job, success } => {
                g.releases.push((job, success));
                let p = g.pending.take();
                if success {
                    g.cache = p;
                }
                write_msg(
                    &mut s,
                    &Message::Released {
                        job,
                        hook_log: "post-hook ok\n".into(),
                    },
                )?;
            }
            Message::RestoreBegin {
                target,
                overwrite,
                confirm,
                ..
            } => {
                if confirm.is_empty() || !target.starts_with('/') {
                    write_msg(
                        &mut s,
                        &Message::Error {
                            code: 400,
                            message: "confirmation token and absolute target required".into(),
                        },
                    )?;
                    continue;
                }
                g.restores.push((target.clone(), overwrite, confirm));
                let base = g.restore_root.join(target.trim_start_matches('/'));
                fs::create_dir_all(&base)?;
                restore = Some(Restore {
                    base,
                    queue: VecDeque::new(),
                    stats: ScanStats::default(),
                });
                write_msg(&mut s, &Message::RestoreReady)?;
            }
            Message::RestoreEntries { batch } => {
                let r = restore.as_mut().expect("RestoreBegin first");
                g.received.extend(batch.iter().cloned());
                for e in batch {
                    let p = r.base.join(std::str::from_utf8(&e.path).unwrap());
                    match e.kind {
                        Kind::Dir => {
                            fs::create_dir_all(&p)?;
                            fs::set_permissions(&p, fs::Permissions::from_mode(e.mode & 0o7777))?;
                            r.stats.dirs += 1;
                        }
                        Kind::Symlink => {
                            std::os::unix::fs::symlink(
                                std::str::from_utf8(e.link_target.as_ref().unwrap()).unwrap(),
                                &p,
                            )?;
                        }
                        Kind::File => {
                            fs::File::create(&p)?;
                            fs::set_permissions(&p, fs::Permissions::from_mode(e.mode & 0o7777))?;
                            r.stats.files += 1;
                            if !e.chunks.is_empty() {
                                r.queue.push_back((p, e.chunks, 0));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Message::RestoreChunk { hash, data } => {
                let r = restore.as_mut().expect("RestoreBegin first");
                let (p, chunks, i) = r.queue.front_mut().expect("chunk without a file");
                assert_eq!(chunks[*i].0, hash, "chunks arrive in entry/chunk order");
                assert_eq!(blake3::hash(&data).as_bytes(), &hash);
                fs::OpenOptions::new().append(true).open(&*p)?.write_all(&data)?;
                r.stats.bytes += data.len() as u64;
                *i += 1;
                if *i == chunks.len() {
                    r.queue.pop_front();
                }
            }
            Message::RestoreEnd => {
                let r = restore.take().expect("RestoreBegin first");
                assert!(r.queue.is_empty(), "all chunks delivered");
                write_msg(&mut s, &Message::RestoreDone { stats: r.stats })?;
            }
            Message::Update {
                version,
                binary,
                signature,
            } => {
                g.updates.push((version.clone(), binary.len(), signature.len()));
                g.version = version;
                write_msg(&mut s, &Message::UpdateDone)?;
            }
            _ => write_msg(
                &mut s,
                &Message::Error {
                    code: 400,
                    message: "unexpected".into(),
                },
            )?,
        }
    }
}

/// file being written: (path, chunk list, next chunk)
type Pending = (PathBuf, Vec<(Hash, u32)>, usize);

struct Restore {
    base: PathBuf,
    queue: VecDeque<Pending>,
    stats: ScanStats,
}

fn enroll_step(s: &mut Tls, g: &mut State, m: Message) -> std::io::Result<()> {
    let ex: [u8; 32] = s
        .conn
        .export_keying_material([0u8; 32], EXPORTER_LABEL, None)
        .map_err(std::io::Error::other)?;
    match m {
        Message::Enroll { proof } => {
            let Some(digest) = g.token_digest.clone() else {
                return write_msg(
                    s,
                    &Message::Error {
                        code: 403,
                        message: "not in enrollment mode".into(),
                    },
                );
            };
            if !proof_eq(&proof, &enroll_proof(&digest, "appliance", &ex)) {
                g.failed_proofs += 1;
                if g.failed_proofs >= 5 {
                    g.token_digest = None; // locked until `init` again
                }
                return write_msg(
                    s,
                    &Message::Error {
                        code: 401,
                        message: "enrollment proof invalid".into(),
                    },
                );
            }
            let csr = CertificateParams::default()
                .serialize_request(&g.key)
                .unwrap()
                .pem()
                .unwrap();
            write_msg(
                s,
                &Message::EnrollReply {
                    proof: enroll_proof(&digest, "agent", &ex),
                    csr_pem: csr,
                },
            )
        }
        Message::EnrollDone {
            cert_pem,
            ca_pem,
            agent_id,
        } => {
            g.agent_id = Some(agent_id);
            g.enrolled = Some((cert_pem, ca_pem));
            g.token_digest = None;
            Ok(())
        }
        _ => write_msg(
            s,
            &Message::Error {
                code: 400,
                message: "enrollment mode".into(),
            },
        ),
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let mut v: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    v.sort();
    for p in v {
        out.push(p.strip_prefix(root).unwrap().to_owned());
        if fs::symlink_metadata(&p).unwrap().is_dir() {
            walk(root, &p, out);
        }
    }
}

fn scan(s: &mut Tls, g: &mut State, base: Option<BaseRef>) -> std::io::Result<()> {
    g.scans.push(base.clone());
    let mut paths = Vec::new();
    let root = g.root.clone();
    walk(&root, &root, &mut paths);
    let mut entries = Vec::new();
    let mut cache = HashMap::new();
    let mut stats = ScanStats::default();
    for rel in paths {
        let p = root.join(&rel);
        let md = fs::symlink_metadata(&p)?;
        let path = rel.to_str().unwrap().as_bytes().to_vec();
        let ft = md.file_type();
        let mut e = Entry {
            path: path.clone(),
            kind: Kind::File,
            mode: md.mode(),
            uid: md.uid(),
            gid: md.gid(),
            size: 0,
            mtime_ns: md.mtime() * 1_000_000_000 + md.mtime_nsec(),
            ctime_ns: md.ctime() * 1_000_000_000 + md.ctime_nsec(),
            inode: md.ino(),
            rdev: md.rdev(),
            link_target: None,
            xattrs: vec![],
            chunks: vec![],
            unchanged: false,
            inconsistent: !g.consistent,
        };
        if ft.is_dir() {
            e.kind = Kind::Dir;
            stats.dirs += 1;
        } else if ft.is_symlink() {
            e.kind = Kind::Symlink;
            e.link_target = Some(fs::read_link(&p)?.to_str().unwrap().as_bytes().to_vec());
        } else {
            e.size = md.len();
            stats.files += 1;
            stats.bytes += e.size;
            if path.ends_with(b".xattr") {
                e.xattrs = vec![(b"user.test".to_vec(), b"value".to_vec())];
            }
            let cached = base
                .as_ref()
                .and(g.cache.as_ref())
                .and_then(|c| c.get(&path))
                .filter(|c| (c.size, c.mtime, c.ctime, c.inode) == (e.size, e.mtime_ns, e.ctime_ns, e.inode))
                .cloned();
            // the fake always reads the file so it can serve any Want
            let data = fs::read(&p)?;
            let mut chunks = Vec::new();
            for c in data.chunks(CHUNK) {
                let h = *blake3::hash(c).as_bytes();
                g.data.insert(h, c.to_vec());
                chunks.push((h, c.len() as u32));
            }
            match cached {
                Some(c) => {
                    e.unchanged = true;
                    e.chunks = c.chunks;
                    stats.unchanged += 1;
                }
                None => {
                    e.chunks = chunks;
                    stats.read_bytes += e.size;
                }
            }
            cache.insert(
                path.clone(),
                CacheEntry {
                    size: e.size,
                    mtime: e.mtime_ns,
                    ctime: e.ctime_ns,
                    inode: e.inode,
                    chunks: e.chunks.clone(),
                },
            );
        }
        entries.push(e);
    }
    g.pending = Some(cache);
    for b in entries.chunks(3) {
        write_msg(s, &Message::Entries { batch: b.to_vec() })?;
    }
    write_msg(s, &Message::ScanDone { stats })
}
