//! An in-process NexusStor speaking the backup protocol (NexusStor
//! `docs/nexusbackup-protocol.md`): TLS 1.3 with ALPN `nexusbackup/1` and a
//! mandatory client certificate, pairing with a one-time code, and the requests
//! inventory, snapshot, diff, files, list, lun and release over an in-memory
//! model of vStors (paths -> nodes; a snapshot is a copy of the map). `zfs diff`
//! is computed per dataset by comparing two snapshots (renamed directories as
//! one `R` line, as ZFS reports them). `Evil` switches in hostile answers.

#![allow(dead_code)]

use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, ServerConnection, SignatureScheme, StreamOwned};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

pub const CODE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub kind: &'static str,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub data: Vec<u8>,
    pub target: Option<String>,
    pub xattrs: BTreeMap<String, Vec<u8>>,
    pub acl: Option<Vec<u8>>,
}

pub fn dir() -> Node {
    Node {
        kind: "dir",
        mode: 0o040755,
        uid: 20000,
        gid: 20000,
        mtime: 1_793_000_000,
        data: Vec::new(),
        target: None,
        xattrs: BTreeMap::new(),
        acl: None,
    }
}

pub fn file(data: &[u8]) -> Node {
    Node {
        kind: "file",
        mode: 0o100644,
        data: data.to_vec(),
        ..dir()
    }
}

pub fn symlink(t: &str) -> Node {
    Node {
        kind: "symlink",
        mode: 0o120777,
        target: Some(t.into()),
        ..dir()
    }
}

#[derive(Clone, Default)]
pub struct Snapshot {
    pub tree: BTreeMap<String, Node>,
    pub luns: BTreeMap<String, Vec<u8>>,
    pub dirs: Vec<String>,
}

#[derive(Default)]
pub struct VStor {
    /// dataset dirs (`data`, `data/projects`, `s3`)
    pub dirs: Vec<String>,
    pub live: BTreeMap<String, Node>,
    pub luns: BTreeMap<String, Vec<u8>>,
    pub snaps: BTreeMap<String, Snapshot>,
    /// directory renames since the last snapshot (reported as `R` lines)
    pub renames: Vec<(String, String)>,
}

/// Hostile behaviour of the next answers.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum Evil {
    #[default]
    None,
    /// `list` names an entry `..`
    ListDotDot,
    /// `files` answers with a record for `/etc/shadow`
    FilesAbsolute,
    /// `files` answers with a 2 MiB record header line
    FilesOversized,
    /// `diff` names a path outside the dataset's mountpoint
    DiffOutside,
    /// `diff` answers 409 (the base was destroyed by a rollback after the inventory was read)
    Diff409,
}

#[derive(Default)]
pub struct State {
    pub name: String,
    pub vstors: BTreeMap<String, VStor>,
    /// SHA-256 of the paired client certificate
    pub paired: Option<String>,
    pub pair_calls: u32,
    pub failed_pairs: u32,
    /// every request line received (`METHOD path`)
    pub requests: Vec<String>,
    pub evil: Evil,
    pub clock: u64,
    /// `list` page size (the contract allows 10000; small to exercise paging)
    pub page: usize,
    /// every vStor's `anomaly` in the inventory (NexusStor's change-rate finding)
    pub anomaly: Option<Value>,
    /// `POST /vstors/<v>/report` bodies received (contract step 3), with the vStor
    pub reports: Vec<(String, Value)>,
    /// `POST /vstors/<v>/finding` bodies received, with the vStor
    pub findings: Vec<(String, Value)>,
    /// contract step 4: the restore directory (`dir/into`) and the files written into it (path -> bytes; dirs and
    /// symlinks as headers), finished / aborted
    pub restore_path: Option<String>,
    pub restored: BTreeMap<String, Vec<u8>>,
    pub restored_heads: Vec<Value>,
    pub restore_requests: u32,
    pub restore_finished: bool,
    pub restore_aborted: bool,
}

pub struct Fake {
    pub state: Arc<Mutex<State>>,
    pub port: u16,
    /// SHA-256 of the server certificate (the pairing token's fingerprint)
    pub fingerprint: String,
}

impl Fake {
    /// The regular files of vStor `v` below `data/` (live tree): path -> contents.
    pub fn data_files(&self, v: &str) -> BTreeMap<String, Vec<u8>> {
        let g = self.state.lock().unwrap();
        g.vstors[v]
            .live
            .iter()
            .filter(|(p, n)| n.kind == "file" && p.starts_with("data/"))
            .map(|(p, n)| (p.clone(), n.data.clone()))
            .collect()
    }
}

pub fn sha256(der: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect()
}

/// A token as NexusStor shows it.
pub fn token(port: u16, fingerprint: &str, expires: u64) -> String {
    let j =
        json!({"address": format!("127.0.0.1:{port}"), "fingerprint": fingerprint, "code": CODE, "expires": expires});
    format!(
        "nst1.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(j.to_string())
    )
}

/// A self-signed certificate and its PKCS#8 key (PEM).
pub fn cert(cn: &str) -> (String, String, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec![cn.to_owned()]).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    let c = p.self_signed(&key).unwrap();
    (c.pem(), key.serialize_pem(), c.der().to_vec())
}

#[derive(Debug)]
struct AnyClient(Arc<rustls::crypto::CryptoProvider>);

impl ClientCertVerifier for AnyClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2".into()))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl Fake {
    pub fn start(state: State) -> Fake {
        let (pem, key, der) = cert("nexusstor.test");
        let _ = pem;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = pem::parse(key).unwrap();
        let mut cfg = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(AnyClient(provider)))
            .with_single_cert(
                vec![CertificateDer::from(der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.contents().to_vec())),
            )
            .unwrap();
        cfg.alpn_protocols = vec![b"nexusbackup/1".to_vec()];
        let cfg = Arc::new(cfg);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(State {
            clock: 1_793_500_000,
            page: 3,
            ..state
        }));
        let st = state.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (cfg, st) = (cfg.clone(), st.clone());
                std::thread::spawn(move || {
                    let _ = serve(s, cfg, &st);
                });
            }
        });
        Fake {
            state,
            port,
            fingerprint: sha256(&der),
        }
    }
}

type Tls = StreamOwned<ServerConnection, TcpStream>;

fn respond(s: &mut Tls, status: u16, body: &Value) -> std::io::Result<()> {
    let b = body.to_string();
    write!(
        s,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
        b.len()
    )?;
    s.flush()
}

/// A chunked octet stream (chunks of at most 64 KiB, as a streaming server sends them).
fn stream(s: &mut Tls, body: &[u8]) -> std::io::Result<()> {
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
    )?;
    for c in body.chunks(64 << 10) {
        write!(s, "{:x}\r\n", c.len())?;
        s.write_all(c)?;
        s.write_all(b"\r\n")?;
    }
    s.write_all(b"0\r\n\r\n")?;
    s.flush()
}

fn serve(tcp: TcpStream, cfg: Arc<ServerConfig>, st: &Mutex<State>) -> std::io::Result<()> {
    let mut s = StreamOwned::new(ServerConnection::new(cfg).unwrap(), tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    let client = s
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| sha256(c))
        .expect("client certificate is mandatory");
    let mut r = BufReader::new(&mut s);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        r.read_line(&mut h)?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap();
        }
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    drop(r);
    let mut parts = line.split_whitespace();
    let (method, target) = (
        parts.next().unwrap_or("").to_owned(),
        parts.next().unwrap_or("").to_owned(),
    );
    let raw = body.clone();
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let mut g = st.lock().unwrap();
    g.requests.push(format!("{method} {target}"));
    let Some(rest) = target.strip_prefix("/nexusbackup/v1") else {
        return respond(&mut s, 404, &json!({"error": "not found"}));
    };
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let q: BTreeMap<&str, &str> = query.split('&').filter_map(|kv| kv.split_once('=')).collect();
    if path == "/pair" && method == "POST" {
        g.pair_calls += 1;
        if body["code"] != CODE || g.failed_pairs >= 5 {
            g.failed_pairs += 1;
            return respond(&mut s, 403, &json!({"error": "invalid pairing code"}));
        }
        g.paired = Some(client);
        let name = g.name.clone();
        return respond(&mut s, 200, &json!({"pairing": "p1", "nexusstor": name, "vstors": "*"}));
    }
    if g.paired.as_deref() != Some(client.as_str()) {
        return respond(&mut s, 403, &json!({"error": "not paired"}));
    }
    let seg: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (method.as_str(), seg.as_slice()) {
        ("GET", ["inventory"]) => {
            let inv = inventory(&g);
            respond(&mut s, 200, &inv)
        }
        ("POST", ["vstors", v, "snapshots"]) => {
            g.clock += 10;
            let name = format!("nexusbackup-{}", g.clock);
            let Some(vs) = g.vstors.get_mut(*v) else {
                return respond(&mut s, 403, &json!({"error": "not in scope"}));
            };
            let snap = Snapshot {
                tree: vs.live.clone(),
                luns: vs.luns.clone(),
                dirs: vs.dirs.clone(),
            };
            vs.snaps.insert(name.clone(), snap);
            let created = g.clock;
            respond(&mut s, 200, &json!({"snapshot": name, "created": created}))
        }
        ("DELETE", ["vstors", v, "snapshots", sn]) => {
            if !sn.starts_with("nexusbackup-") {
                return respond(&mut s, 400, &json!({"error": "not a nexusbackup snapshot"}));
            }
            let vs = g.vstors.get_mut(*v).unwrap();
            vs.snaps.remove(*sn); // a snapshot that is gone already is ok as well
            respond(&mut s, 200, &json!({"ok": true}))
        }
        ("GET", ["vstors", v, "diff"]) => {
            let evil = g.evil;
            let vs = &g.vstors[*v];
            let (Some(a), Some(b)) = (vs.snaps.get(q["base"]), vs.snaps.get(q["snap"])) else {
                return respond(&mut s, 409, &json!({"error": "zfs diff: snapshot does not exist"}));
            };
            if evil == Evil::Diff409 {
                return respond(&mut s, 409, &json!({"error": "zfs diff: snapshot does not exist"}));
            }
            let mut out = diff(v, a, b, &vs.renames);
            if evil == Evil::DiffOutside {
                out = out.replacen(
                    "{\"end\":true}",
                    "+\tF\t/var/tank/vstors/other/data/x\n{\"end\":true}",
                    1,
                );
            }
            stream(&mut s, out.as_bytes())
        }
        ("POST", ["vstors", v, "files"]) => {
            let evil = g.evil;
            let snap = &g.vstors[*v].snaps[body["snap"].as_str().unwrap()];
            let mut out = Vec::new();
            for p in body["paths"].as_array().unwrap() {
                let p = p.as_str().unwrap();
                match snap.tree.get(p) {
                    None => {
                        out.extend(format!("{}\n", json!({"path": p, "error": "No such file or directory"})).bytes());
                    }
                    Some(n) => {
                        let shown = if evil == Evil::FilesAbsolute { "/etc/shadow" } else { p };
                        let b64 = base64::engine::general_purpose::STANDARD;
                        let mut xattrs: serde_json::Map<String, Value> = n
                            .xattrs
                            .iter()
                            .map(|(k, v)| (k.clone(), json!(b64.encode(v))))
                            .collect();
                        if evil == Evil::FilesOversized {
                            xattrs.insert("user.huge".into(), json!("A".repeat(2 << 20)));
                        }
                        let rec = json!({"path": shown, "type": n.kind, "mode": n.mode, "uid": n.uid, "gid": n.gid,
                            "size": if n.kind == "file" { n.data.len() } else { n.target.as_ref().map_or(0, String::len) },
                            "mtime": n.mtime, "mtime_ns": 0, "target": n.target, "xattrs": xattrs,
                            "nfs4_acl": n.acl.as_ref().map(|a| b64.encode(a))});
                        out.extend(format!("{rec}\n").bytes());
                        if n.kind == "file" {
                            out.extend_from_slice(&n.data);
                        }
                    }
                }
            }
            out.extend(b"{\"end\": true}\n");
            stream(&mut s, &out)
        }
        ("POST", ["vstors", v, "report"]) => {
            if !g.vstors.contains_key(*v) {
                return respond(&mut s, 403, &json!({"error": "not in scope"}));
            }
            g.reports.push(((*v).to_owned(), body.clone()));
            respond(&mut s, 200, &json!({"vstor": v, "state": body["state"]}))
        }
        ("POST", ["vstors", v, "finding"]) => {
            g.findings.push(((*v).to_owned(), body.clone()));
            respond(&mut s, 200, &json!({"finding": 1, "locked": null}))
        }
        ("POST", ["vstors", v, "restores"]) => {
            if !g.vstors.contains_key(*v) {
                return respond(&mut s, 403, &json!({"error": "not in scope"}));
            }
            let p = format!(
                "{}/{}",
                body["dir"].as_str().unwrap_or(""),
                body["into"].as_str().unwrap_or("")
            );
            g.restore_path = Some(p.clone());
            respond(&mut s, 200, &json!({"restore": "r1", "path": p}))
        }
        ("PUT", ["restores", "r1", "records"]) => {
            g.restore_requests += 1;
            let mut rest = &raw[..];
            let (mut files, mut bytes) = (0u64, 0u64);
            while !rest.is_empty() {
                let nl = rest.iter().position(|c| *c == b'\n').unwrap();
                let h: Value = serde_json::from_slice(&rest[..nl]).unwrap();
                let n = if h["type"] == "file" {
                    h["size"].as_u64().unwrap() as usize
                } else {
                    0
                };
                let data = rest[nl + 1..nl + 1 + n].to_vec();
                rest = &rest[nl + 1 + n..];
                let path = h["path"].as_str().unwrap().to_owned();
                if h["append"] == true {
                    g.restored
                        .get_mut(&path)
                        .expect("append to a file that was created")
                        .extend(data);
                } else {
                    assert!(g.restored.insert(path, data).is_none(), "created twice");
                    files += 1;
                }
                bytes += n as u64;
                g.restored_heads.push(h);
            }
            respond(
                &mut s,
                200,
                &json!({"files": files, "bytes": bytes, "failed": 0, "errors": []}),
            )
        }
        ("POST", ["restores", "r1", "finish"]) => {
            g.restore_finished = true;
            let n = g.restored.len();
            let b: usize = g.restored.values().map(Vec::len).sum();
            respond(
                &mut s,
                200,
                &json!({"restore": "r1", "files": n, "bytes": b, "failed": 0}),
            )
        }
        ("DELETE", ["restores", "r1"]) => {
            g.restore_aborted = true;
            respond(&mut s, 200, &json!({"aborted": true}))
        }
        ("POST", ["vstors", v, "list"]) => {
            let (evil, page) = (g.evil, g.page);
            let snap = &g.vstors[*v].snaps[body["snap"].as_str().unwrap()];
            let d = body["dir"].as_str().unwrap();
            let after = body["after"].as_str();
            let mut names: Vec<(String, &Node)> = snap
                .tree
                .iter()
                .filter_map(|(k, n)| {
                    let rest = k.strip_prefix(d)?.strip_prefix('/')?;
                    (!rest.contains('/')).then(|| (rest.to_owned(), n))
                })
                .filter(|(name, _)| after.is_none_or(|a| name.as_str() > a))
                .collect();
            names.sort_by(|a, b| a.0.cmp(&b.0));
            let more = names.len() > page;
            names.truncate(page);
            let mut entries: Vec<Value> = names
                .iter()
                .map(|(name, n)| json!({"name": name, "type": n.kind, "size": n.data.len(), "mtime": n.mtime}))
                .collect();
            if evil == Evil::ListDotDot {
                entries.insert(0, json!({"name": "..", "type": "dir", "size": 0, "mtime": 0}));
            }
            respond(&mut s, 200, &json!({"entries": entries, "more": more}))
        }
        ("GET", ["vstors", v, "luns", lun]) => {
            let snap = &g.vstors[*v].snaps[q["snap"]];
            let data = &snap.luns[*lun];
            let off: usize = q["offset"].parse().unwrap();
            let len: usize = q["len"].parse().unwrap();
            assert!(off.is_multiple_of(4096) && len <= 64 << 20);
            let end = (off + len).min(data.len());
            let out = data[off.min(end)..end].to_vec();
            // the contract: lun answers carry a Content-Length
            write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                out.len()
            )?;
            s.write_all(&out)?;
            s.flush()
        }
        _ => respond(&mut s, 404, &json!({"error": "unknown request"})),
    }
}

fn mountpoint(v: &str, dir: &str) -> String {
    format!("/var/tank/vstors/{v}/{dir}")
}

/// The dataset dir owning `p` (longest prefix).
fn owner<'a>(dirs: &'a [String], p: &str) -> Option<&'a String> {
    dirs.iter()
        .filter(|d| p == d.as_str() || p.starts_with(&format!("{d}/")))
        .max_by_key(|d| d.len())
}

/// zfs escaping: bytes outside 0x21..=0x7e and `\` as `\NNNN`.
pub fn esc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if (0x21..=0x7e).contains(&b) && b != b'\\' {
                (b as char).to_string()
            } else {
                format!("\\{b:04o}")
            }
        })
        .collect()
}

fn diff(v: &str, a: &Snapshot, b: &Snapshot, renames: &[(String, String)]) -> String {
    let mut out = String::new();
    for d in &b.dirs {
        let ds = format!("tank/vstors/{v}/{d}");
        if !a.dirs.contains(d) {
            out.push_str(&format!("{}\n", json!({"dataset": ds, "dir": d, "new": true})));
            continue;
        }
        let mp = mountpoint(v, d);
        out.push_str(&format!("{}\n", json!({"dataset": ds, "dir": d, "mountpoint": mp})));
        let abs = |p: &str| {
            let rel = p.strip_prefix(d.as_str()).unwrap().trim_start_matches('/');
            format!("{mp}/{}", esc(rel))
        };
        let ftype = |n: &Node| match n.kind {
            "file" => "F",
            "dir" => "/",
            _ => "@",
        };
        let renamed = |p: &str| {
            renames
                .iter()
                .any(|(f, t)| p.starts_with(&format!("{f}/")) || p.starts_with(&format!("{t}/")) || p == f || p == t)
        };
        for (f, t) in renames {
            if owner(&b.dirs, t) == Some(d) {
                out.push_str(&format!("R\t/\t{}\t{}\n", abs(f), abs(t)));
            }
        }
        for (p, n) in &b.tree {
            if owner(&b.dirs, p) != Some(d) || renamed(p) {
                continue;
            }
            match a.tree.get(p) {
                None => out.push_str(&format!("+\t{}\t{}\n", ftype(n), abs(p))),
                Some(o) if o != n => out.push_str(&format!("M\t{}\t{}\n", ftype(n), abs(p))),
                _ => {}
            }
        }
        for (p, n) in &a.tree {
            if owner(&a.dirs, p) == Some(d) && !renamed(p) && !b.tree.contains_key(p) {
                out.push_str(&format!("-\t{}\t{}\n", ftype(n), abs(p)));
            }
        }
    }
    out.push_str("{\"end\":true}\n");
    out
}

fn inventory(g: &State) -> Value {
    let vstors: Vec<Value> = g
        .vstors
        .iter()
        .map(|(name, v)| {
            json!({
                "name": name, "uid": 20000, "quota": 1u64 << 40, "used": 4096, "encrypted": true,
                "datasets": v.dirs.iter().map(|d| json!({"path": d, "dataset": format!("tank/vstors/{name}/{d}"), "used": 1})).collect::<Vec<_>>(),
                "exports": [{"path": "/", "dir": v.dirs[0]}],
                "shares": [{"name": "data", "dir": v.dirs[0]}],
                "s3_root": v.dirs.iter().find(|d| d.as_str() == "s3"),
                "luns": v.luns.iter().map(|(l, d)| json!({"name": l, "id": 0, "size": d.len()})).collect::<Vec<_>>(),
                "snapshots": v.snaps.keys().map(|s| json!({"name": s, "created": 1, "held": true})).collect::<Vec<_>>(),
                "anomaly": g.anomaly,
                "definition": {"name": name, "network": {"vlan": 10}},
            })
        })
        .collect();
    json!({"nexusstor": g.name, "at": g.clock, "vstors": vstors})
}
