//! Requests and strict parsers of the NexusStor backup protocol (NexusStor
//! `docs/nexusbackup-protocol.md`). Everything NexusStor sends is hostile input:
//! names and paths are checked against the protocol's charsets, sizes and counts
//! are bounded, and file records must name exactly the requested path.

use crate::client::{Client, Response};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use plugin_sdk::proto::{valid_guest_id, valid_path, Kind, Meta, MAX_PATH, MAX_XATTR, STREAMS_DIR};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{BufRead, Read};

/// JSON answers (contract limit).
pub const MAX_JSON: u64 = 16 << 20;
/// Paths per `files` request (contract limit).
pub const MAX_FILES: usize = 1000;
/// Bytes per `lun` request (contract limit).
pub const MAX_LUN_READ: u64 = 64 << 20;
/// Entries per `list` answer (contract).
pub const MAX_LIST: usize = 10_000;
/// One record header or `diff` header line (not in the contract: the largest
/// legitimate one is a path plus 64 KiB of xattrs in base64).
pub const MAX_LINE: usize = 1 << 20;
/// One raw `zfs diff -FH` line: two escaped paths (`\NNNN` per byte).
pub const MAX_DIFF_LINE: usize = 2 * 5 * MAX_PATH + 64;
/// Entries of one vStor tree (the host's per-snapshot bound).
pub const MAX_ENTRIES: usize = 20_000_000;
/// Largest file or LUN accepted (1 PiB).
pub const MAX_SIZE: u64 = 1 << 50;

/// Snapshot names the helper creates: `nexusbackup-<unix time>`.
pub fn valid_snap(s: &str) -> bool {
    s.strip_prefix("nexusbackup-")
        .is_some_and(|t| (1..=20).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_digit()) && !t.starts_with('0'))
}

/// LUN names (also the stream name `luns/<name>`): `[A-Za-z0-9._-]{1,64}`, not `.`/`..`.
pub fn valid_lun(s: &str) -> bool {
    valid_guest_id(s) && s != "." && s != ".."
}

/// A path relative to the vStor root that may be a tree path (not below the
/// host's reserved streams directory).
pub fn valid_tree_path(p: &str) -> bool {
    valid_path(p.as_bytes()) && p.split('/').next() != Some(STREAMS_DIR)
}

#[derive(Deserialize, Debug, Clone)]
pub struct Inventory {
    pub nexusstor: String,
    #[serde(default)]
    pub at: u64,
    pub vstors: Vec<VStor>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct VStor {
    pub name: String,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub quota: Option<u64>,
    #[serde(default)]
    pub used: Option<u64>,
    #[serde(default)]
    pub encrypted: bool,
    pub datasets: Vec<Dataset>,
    #[serde(default)]
    pub exports: Vec<Export>,
    #[serde(default)]
    pub shares: Vec<Share>,
    #[serde(default)]
    pub s3_root: Option<String>,
    #[serde(default)]
    pub luns: Vec<Lun>,
    #[serde(default)]
    pub snapshots: Vec<Snap>,
    #[serde(default)]
    pub anomaly: Option<Value>,
    #[serde(default)]
    pub definition: Value,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Dataset {
    pub path: String,
    #[serde(default)]
    pub dataset: String,
    #[serde(default)]
    pub used: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Export {
    pub path: String,
    pub dir: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Share {
    pub name: String,
    pub dir: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Lun {
    pub name: String,
    #[serde(default)]
    pub id: u32,
    pub size: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Snap {
    pub name: String,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub held: bool,
}

fn printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

impl Inventory {
    /// Checks every name, path and count; a single bad vStor fails the whole answer
    /// (NexusStor validates its own catalog, so this is a broken or hostile peer).
    pub fn check(&self) -> Result<()> {
        ensure!(printable(&self.nexusstor, 255), "inventory: invalid NexusStor name");
        ensure!(self.vstors.len() <= 10_000, "inventory: too many vStors");
        let mut names = HashSet::new();
        for v in &self.vstors {
            ensure!(
                valid_guest_id(&v.name) && names.insert(v.name.as_str()),
                "inventory: invalid or repeated vStor name {:?}",
                v.name
            );
            v.check().with_context(|| format!("inventory: vStor {}", v.name))?;
        }
        Ok(())
    }
}

impl VStor {
    fn check(&self) -> Result<()> {
        ensure!(!self.datasets.is_empty(), "no file system datasets");
        ensure!(self.datasets.len() <= 1000, "too many datasets");
        let mut dirs = HashSet::new();
        for d in &self.datasets {
            ensure!(
                valid_tree_path(&d.path) && dirs.insert(d.path.as_str()),
                "invalid or repeated dataset dir {:?}",
                d.path
            );
            ensure!(d.dataset.len() <= 256, "dataset name too long");
        }
        let inside = |p: &str| dirs.iter().any(|d| p == *d || p.starts_with(&format!("{d}/")));
        ensure!(
            self.exports.len() <= 1000 && self.shares.len() <= 1000,
            "too many exports or shares"
        );
        for e in &self.exports {
            ensure!(
                valid_tree_path(&e.dir) && inside(&e.dir) && printable(&e.path, MAX_PATH),
                "invalid export {:?}",
                e.path
            );
        }
        for s in &self.shares {
            ensure!(
                valid_tree_path(&s.dir) && inside(&s.dir) && printable(&s.name, 255),
                "invalid share {:?}",
                s.name
            );
        }
        if let Some(r) = &self.s3_root {
            ensure!(valid_tree_path(r) && inside(r), "invalid s3_root {r:?}");
        }
        ensure!(self.luns.len() <= 1000, "too many LUNs");
        let mut luns = HashSet::new();
        for l in &self.luns {
            ensure!(
                valid_lun(&l.name) && luns.insert(l.name.as_str()),
                "invalid or repeated LUN {:?}",
                l.name
            );
            ensure!(l.size <= MAX_SIZE, "LUN {}: size out of range", l.name);
        }
        ensure!(self.snapshots.len() <= 10_000, "too many snapshots");
        for s in &self.snapshots {
            ensure!(valid_snap(&s.name), "invalid snapshot name {:?}", s.name);
        }
        ensure!(
            self.definition.to_string().len() <= 4 << 20,
            "definition larger than 4 MiB"
        );
        Ok(())
    }

    /// Dataset dirs, sorted.
    pub fn dirs(&self) -> Vec<String> {
        let mut d: Vec<String> = self.datasets.iter().map(|d| d.path.clone()).collect();
        d.sort();
        d
    }

    pub fn has_snapshot(&self, s: &str) -> bool {
        self.snapshots.iter().any(|x| x.name == s)
    }
}

/// Answer of `pair`.
#[derive(Deserialize, Debug)]
pub struct Paired {
    pub pairing: String,
    pub nexusstor: String,
    pub vstors: Value,
}

#[derive(Deserialize, Debug)]
pub struct Created {
    pub snapshot: String,
    #[serde(default)]
    pub created: u64,
}

/// Entry type of `list` entries and `files` records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    File,
    Dir,
    Symlink,
    Other,
}

fn parse_type(s: &str) -> Result<Type> {
    Ok(match s {
        "file" => Type::File,
        "dir" => Type::Dir,
        "symlink" => Type::Symlink,
        "other" => Type::Other,
        _ => bail!("unknown entry type {s:?}"),
    })
}

/// One entry of a `list` answer.
#[derive(Debug, Clone)]
pub struct ListEntry {
    pub name: String,
    pub kind: Type,
}

/// A checked `list` answer: names valid and strictly increasing after `after`.
pub fn parse_list(v: &Value, after: Option<&str>) -> Result<(Vec<ListEntry>, bool)> {
    let entries = v["entries"].as_array().context("list: no entries")?;
    ensure!(entries.len() <= MAX_LIST, "list: more than {MAX_LIST} entries");
    let more = v["more"].as_bool().context("list: no `more`")?;
    let mut out: Vec<ListEntry> = Vec::with_capacity(entries.len());
    let mut last = after.map(str::to_owned);
    for e in entries {
        let name = e["name"].as_str().context("list: entry without name")?;
        ensure!(
            !name.is_empty() && name.len() <= 255 && valid_path(name.as_bytes()) && !name.contains('/'),
            "list: invalid name {name:?}"
        );
        ensure!(
            last.as_deref().is_none_or(|l| name > l),
            "list: names not in increasing order"
        );
        let kind = parse_type(e["type"].as_str().context("list: entry without type")?)?;
        last = Some(name.to_owned());
        out.push(ListEntry {
            name: name.to_owned(),
            kind,
        });
    }
    ensure!(!more || !out.is_empty(), "list: `more` without entries");
    Ok((out, more))
}

/// Reads one line of at most `max` bytes (without the newline); `None` at EOF.
pub fn line(r: &mut impl BufRead, max: usize) -> Result<Option<Vec<u8>>> {
    let mut l = Vec::new();
    r.take(max as u64 + 1).read_until(b'\n', &mut l)?;
    if l.is_empty() {
        return Ok(None);
    }
    ensure!(l.len() <= max, "line longer than {max} bytes from NexusStor");
    ensure!(l.pop() == Some(b'\n'), "stream from NexusStor ended inside a line");
    Ok(Some(l))
}

/// What `files` says about one path.
#[derive(Debug)]
pub enum Record {
    /// Metadata (for a file `meta.size` content bytes follow in the stream).
    Entry { path: String, meta: Meta },
    /// The path could not be read (`error`), or its metadata exceeds what a
    /// snapshot entry can hold (`refused`); for a file its content still follows
    /// (`skip` bytes).
    Failed { path: String, reason: String, skip: u64 },
    /// `{"end": true}`
    End,
}

fn mode_type(mode: u32) -> Option<Kind> {
    Some(match mode & 0o170000 {
        0o100000 => Kind::File,
        0o040000 => Kind::Dir,
        0o120000 => Kind::Symlink,
        0o010000 => Kind::Fifo,
        0o020000 | 0o060000 => Kind::Device,
        0o140000 => Kind::Socket,
        _ => return None,
    })
}

/// Parses one record header line of a `files` stream.
pub fn parse_record(l: &[u8]) -> Result<Record> {
    let v: Value = serde_json::from_slice(l).context("files: record is not JSON")?;
    if v["end"] == true {
        ensure!(
            v.as_object().is_some_and(|o| o.len() == 1),
            "files: malformed end record"
        );
        return Ok(Record::End);
    }
    let path = v["path"].as_str().context("files: record without path")?.to_owned();
    ensure!(valid_tree_path(&path), "files: invalid path {path:?} in a record");
    if let Some(e) = v.get("error") {
        let reason: String = e
            .as_str()
            .context("files: malformed error")?
            .chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect();
        return Ok(Record::Failed { path, reason, skip: 0 });
    }
    let ty = parse_type(v["type"].as_str().context("files: record without type")?)?;
    let num = |k: &str| {
        v[k].as_u64()
            .with_context(|| format!("files: {path:?}: {k} missing or invalid"))
    };
    let mode = u32::try_from(num("mode")?)
        .ok()
        .filter(|m| *m <= 0o177777)
        .context("files: invalid mode")?;
    let kind = mode_type(mode).context("files: mode without a file type")?;
    let agrees = match ty {
        Type::File => kind == Kind::File,
        Type::Dir => kind == Kind::Dir,
        Type::Symlink => kind == Kind::Symlink,
        Type::Other => matches!(kind, Kind::Fifo | Kind::Device | Kind::Socket),
    };
    ensure!(agrees, "files: {path:?}: type and mode disagree");
    let uid = u32::try_from(num("uid")?).context("files: uid out of range")?;
    let gid = u32::try_from(num("gid")?).context("files: gid out of range")?;
    let size = num("size")?;
    ensure!(size <= MAX_SIZE, "files: {path:?}: size out of range");
    let secs = v["mtime"].as_i64().context("files: mtime missing")?;
    let ns = v
        .get("mtime_ns")
        .map_or(Some(0), Value::as_u64)
        .filter(|n| *n < 1_000_000_000);
    let mtime_ns = secs
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(ns? as i64))
        .context("files: mtime out of range")?;
    let link_target = match (ty, &v["target"]) {
        (Type::Symlink, Value::String(t)) => {
            ensure!(
                !t.is_empty() && t.len() <= MAX_PATH && !t.contains('\0'),
                "files: {path:?}: invalid symlink target"
            );
            Some(t.as_bytes().to_vec())
        }
        (Type::Symlink, _) => bail!("files: {path:?}: symlink without target"),
        (_, Value::Null) => None,
        _ => bail!("files: {path:?}: target on a non-symlink"),
    };
    let content = if ty == Type::File { size } else { 0 };
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut xattrs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    match &v["xattrs"] {
        Value::Null => {}
        Value::Object(o) => {
            ensure!(o.len() <= 1000, "files: {path:?}: too many xattrs");
            for (k, x) in o {
                ensure!(
                    !k.is_empty() && k.len() <= 255 && !k.contains('\0') && k != "system.nfs4_acl",
                    "files: {path:?}: invalid xattr name"
                );
                let val = b64
                    .decode(x.as_str().context("files: xattr value is not a string")?)
                    .context("files: xattr value is not base64")?;
                xattrs.push((k.as_bytes().to_vec(), val));
            }
        }
        _ => bail!("files: {path:?}: xattrs must be an object"),
    }
    match &v["nfs4_acl"] {
        Value::Null => {}
        Value::String(a) => {
            let val = b64.decode(a).context("files: nfs4_acl is not base64")?;
            // stored like the NAS connector's ACLs: the raw `system.nfs4_acl` xattr
            xattrs.push((b"system.nfs4_acl".to_vec(), val));
        }
        _ => bail!("files: {path:?}: nfs4_acl must be a string or null"),
    }
    xattrs.sort();
    if xattrs.iter().map(|(k, x)| k.len() + x.len()).sum::<usize>() > MAX_XATTR {
        return Ok(Record::Failed {
            path,
            reason: format!("xattrs and ACL larger than {} KiB (left out)", MAX_XATTR >> 10),
            skip: content,
        });
    }
    let meta = Meta {
        kind: Some(kind),
        mode,
        uid,
        gid,
        size: content,
        mtime_ns,
        ctime_ns: 0,
        inode: 0,
        link_target,
        xattrs,
    };
    Ok(Record::Entry { path, meta })
}

/// The changes of one dataset in a `diff` stream.
#[derive(Debug)]
pub struct DatasetDiff {
    /// the dataset's dir (relative to the vStor root)
    pub dir: String,
    /// created after the base: no changes listed, read it in full
    pub new: bool,
    /// changes; paths relative to the vStor root (`dir/...`, the dir itself for the dataset root)
    pub lines: Vec<truenas::diff::Line>,
}

/// Parses a `diff` stream: header lines (JSON), raw `zfs diff -FH` lines (the
/// TrueNAS connector's parser), `{"end": true}` last. `dirs` = the vStor's dataset
/// dirs from the inventory; a header naming another dir, or one twice, is refused.
pub fn parse_diff(r: &mut impl BufRead, dirs: &[String]) -> Result<Vec<DatasetDiff>> {
    let mut out: Vec<DatasetDiff> = Vec::new();
    let mut mountpoint: Option<Vec<u8>> = None;
    let (mut bytes, mut count) = (0usize, 0usize);
    loop {
        let Some(l) = line(r, MAX_LINE.max(MAX_DIFF_LINE))? else {
            bail!("diff: stream ended without the end line");
        };
        bytes += l.len() + 1;
        ensure!(bytes <= truenas::diff::MAX_OUTPUT, "diff: output too large");
        if l.first() == Some(&b'{') {
            let v: Value = serde_json::from_slice(&l).context("diff: header is not JSON")?;
            if v["end"] == true {
                ensure!(line(r, 1)?.is_none(), "diff: data after the end line");
                return Ok(out);
            }
            let dir = v["dir"].as_str().context("diff: header without dir")?.to_owned();
            ensure!(dirs.contains(&dir), "diff: {dir:?} is not a dataset of this vStor");
            ensure!(!out.iter().any(|d| d.dir == dir), "diff: dataset {dir:?} listed twice");
            v["dataset"].as_str().context("diff: header without dataset")?;
            let new = v["new"] == true;
            mountpoint = if new {
                None
            } else {
                let mp = v["mountpoint"].as_str().context("diff: header without mountpoint")?;
                ensure!(
                    mp.starts_with('/')
                        && mp.len() <= MAX_PATH
                        && (mp == "/" || valid_path(mp[1..].trim_end_matches('/').as_bytes())),
                    "diff: invalid mountpoint"
                );
                Some(mp.as_bytes().to_vec())
            };
            out.push(DatasetDiff {
                dir,
                new,
                lines: Vec::new(),
            });
            continue;
        }
        ensure!(l.len() <= MAX_DIFF_LINE, "diff: line too long");
        let (Some(d), Some(mp)) = (out.last_mut(), mountpoint.as_deref()) else {
            bail!("diff: change line outside a dataset with a mountpoint");
        };
        count += 1;
        ensure!(count <= MAX_ENTRIES, "diff: too many changes");
        let mut raw = l;
        raw.push(b'\n');
        let mut parsed = truenas::diff::parse(&raw, mp).context("diff")?;
        ensure!(parsed.len() == 1, "diff: malformed line");
        let mut x = parsed.remove(0);
        let prefix = |p: &mut Vec<u8>| {
            let mut full = d.dir.as_bytes().to_vec();
            if !p.is_empty() {
                full.push(b'/');
                full.extend_from_slice(p);
            }
            *p = full;
        };
        use truenas::diff::Change;
        match &mut x.change {
            Change::Added(p) | Change::Removed(p) | Change::Modified(p) | Change::Links { path: p, .. } => prefix(p),
            Change::Renamed { from, to } => {
                prefix(from);
                prefix(to);
            }
        }
        d.lines.push(x);
    }
}

/// A `files` stream: records in exactly the requested order.
pub struct Files<R> {
    pub r: R,
}

impl<R: BufRead> Files<R> {
    /// The record for `want` (must be the next one).
    pub fn next(&mut self, want: &str) -> Result<Record> {
        let l = line(&mut self.r, MAX_LINE)?.context("files: stream ended early")?;
        let rec = parse_record(&l)?;
        match &rec {
            Record::End => bail!("files: stream ended before {want:?}"),
            Record::Entry { path, .. } | Record::Failed { path, .. } if path != want => {
                bail!("files: record for {path:?} where {want:?} was requested")
            }
            _ => Ok(rec),
        }
    }

    /// The end record, then EOF.
    pub fn end(&mut self) -> Result<()> {
        let l = line(&mut self.r, MAX_LINE)?.context("files: stream ended without the end record")?;
        ensure!(
            matches!(parse_record(&l)?, Record::End),
            "files: more records than requested"
        );
        ensure!(line(&mut self.r, 1)?.is_none(), "files: data after the end record");
        Ok(())
    }
}

/// The protocol's requests (one connection each).
pub struct Nst {
    pub client: Client,
}

impl Nst {
    pub fn inventory(&self) -> Result<Inventory> {
        let inv: Inventory = self.client.request("GET", "/inventory", None)?.json(MAX_JSON)?;
        inv.check()?;
        Ok(inv)
    }

    pub fn pair(&self, code: &str, name: &str) -> Result<Paired> {
        let p: Paired = self
            .client
            .request("POST", "/pair", Some(&json!({"code": code, "name": name})))?
            .json(64 << 10)?;
        ensure!(
            printable(&p.pairing, 128) && printable(&p.nexusstor, 255),
            "pair: malformed answer"
        );
        Ok(p)
    }

    pub fn snapshot(&self, v: &str) -> Result<Created> {
        let c: Created = self
            .client
            .request("POST", &format!("/vstors/{v}/snapshots"), Some(&json!({})))?
            .json(64 << 10)?;
        ensure!(valid_snap(&c.snapshot), "snapshot: invalid name {:?}", c.snapshot);
        Ok(c)
    }

    pub fn release(&self, v: &str, s: &str) -> Result<()> {
        ensure!(valid_snap(s), "not a nexusbackup snapshot");
        self.client
            .request("DELETE", &format!("/vstors/{v}/snapshots/{s}"), None)?
            .ok()?
            .bytes(64 << 10)?;
        Ok(())
    }

    pub fn diff(&self, v: &str, base: &str, snap: &str) -> Result<Response> {
        self.client
            .request("GET", &format!("/vstors/{v}/diff?base={base}&snap={snap}"), None)?
            .ok()
    }

    pub fn files(&self, v: &str, snap: &str, paths: &[String]) -> Result<Files<Response>> {
        ensure!(paths.len() <= MAX_FILES, "too many paths for one files request");
        let r = self
            .client
            .request(
                "POST",
                &format!("/vstors/{v}/files"),
                Some(&json!({"snap": snap, "paths": paths})),
            )?
            .ok()?;
        Ok(Files { r })
    }

    pub fn list(&self, v: &str, snap: &str, dir: &str, after: Option<&str>) -> Result<(Vec<ListEntry>, bool)> {
        let a: Value = self
            .client
            .request(
                "POST",
                &format!("/vstors/{v}/list"),
                Some(&json!({"snap": snap, "dir": dir, "after": after})),
            )?
            .json(MAX_JSON)?;
        parse_list(&a, after).with_context(|| format!("{v}@{snap}:{dir}"))
    }

    pub fn lun(&self, v: &str, snap: &str, lun: &str, offset: u64, len: u64) -> Result<Response> {
        ensure!(len <= MAX_LUN_READ && offset.is_multiple_of(4096), "invalid LUN read");
        self.client
            .request(
                "GET",
                &format!("/vstors/{v}/luns/{lun}?snap={snap}&offset={offset}&len={len}"),
                None,
            )?
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use truenas::diff::Change;

    fn rec(v: Value) -> Result<Record> {
        parse_record(v.to_string().as_bytes())
    }

    fn file() -> Value {
        json!({"path": "data/a.txt", "type": "file", "mode": 0o100644, "uid": 20000, "gid": 20000,
               "size": 12, "mtime": 1_793_500_000, "mtime_ns": 5, "target": null,
               "xattrs": {"user.DOSATTRIB": "AQI="}, "nfs4_acl": "AAEC"})
    }

    #[test]
    fn records() {
        let Record::Entry { path, meta } = rec(file()).unwrap() else {
            panic!()
        };
        assert_eq!(path, "data/a.txt");
        assert_eq!((meta.kind, meta.size, meta.uid), (Some(Kind::File), 12, 20000));
        assert_eq!(meta.mtime_ns, 1_793_500_000_000_000_005);
        assert_eq!(
            meta.xattrs,
            vec![
                (b"system.nfs4_acl".to_vec(), vec![0, 1, 2]),
                (b"user.DOSATTRIB".to_vec(), vec![1, 2]),
            ]
        );
        assert!(matches!(rec(json!({"end": true})).unwrap(), Record::End));
        assert!(matches!(
            rec(json!({"path": "data/x", "error": "EACCES"})).unwrap(),
            Record::Failed { .. }
        ));
        let mut big = file();
        big["xattrs"] = json!({"user.big": base64::engine::general_purpose::STANDARD.encode(vec![0u8; MAX_XATTR])});
        assert!(matches!(rec(big).unwrap(), Record::Failed { skip: 12, .. }));
        let l = json!({"path": "data/l", "type": "symlink", "mode": 0o120777, "uid": 0, "gid": 0, "size": 3,
                       "mtime": 1, "target": "../x"});
        let Record::Entry { meta, .. } = rec(l).unwrap() else {
            panic!()
        };
        assert_eq!((meta.size, meta.link_target.as_deref()), (0, Some(&b"../x"[..])));
    }

    #[test]
    fn hostile_records_are_refused() {
        for (k, bad) in [
            ("path", json!("../etc/shadow")),
            ("path", json!("/etc/shadow")),
            ("path", json!("data/../../x")),
            ("path", json!(".nexus-streams/x")),
            ("path", json!("")),
            ("type", json!("block")),
            ("mode", json!(0o040755)),
            ("mode", json!(0o1000000)),
            ("uid", json!(-1)),
            ("size", json!(MAX_SIZE + 1)),
            ("mtime_ns", json!(1_000_000_000)),
            ("target", json!("x")),
            ("xattrs", json!({"system.nfs4_acl": "AA=="})),
            ("xattrs", json!({"user.a": "!!"})),
            ("xattrs", json!(["user.a"])),
            ("nfs4_acl", json!(7)),
        ] {
            let mut v = file();
            v[k] = bad.clone();
            assert!(rec(v).is_err(), "{k}={bad}");
        }
        assert!(rec(json!({"end": true, "x": 1})).is_err());
        // an oversized record line is refused before it is parsed
        let mut c = Cursor::new(vec![b'{'; MAX_LINE + 10]);
        assert!(line(&mut c, MAX_LINE).is_err());
        let mut f = Files {
            r: Cursor::new(format!("{}\n", file()).into_bytes()),
        };
        assert!(f.next("data/b.txt").is_err()); // not the requested path
    }

    #[test]
    fn list_answers() {
        let v = json!({"entries": [{"name": "a", "type": "file", "size": 1, "mtime": 1},
                                   {"name": "b", "type": "dir", "size": 0, "mtime": 1}], "more": true});
        let (e, more) = parse_list(&v, None).unwrap();
        assert!(more && e.len() == 2 && e[1].kind == Type::Dir);
        assert!(parse_list(&v, Some("a")).is_err()); // not after `after`
        for bad in ["..", ".", "a/b", "", "x\0"] {
            let v = json!({"entries": [{"name": bad, "type": "file"}], "more": false});
            assert!(parse_list(&v, None).is_err(), "{bad:?}");
        }
        let v = json!({"entries": [{"name": "b", "type": "file"}, {"name": "a", "type": "file"}], "more": false});
        assert!(parse_list(&v, None).is_err());
        assert!(parse_list(&json!({"entries": [], "more": true}), None).is_err());
    }

    #[test]
    fn diff_streams() {
        let dirs = vec!["data".to_owned(), "data/projects".to_owned(), "s3".to_owned()];
        let s =
            "{\"dataset\": \"tank/vstors/acme\", \"dir\": \"data\", \"mountpoint\": \"/var/tank/vstors/acme/data\"}\n\
M\t/\t/var/tank/vstors/acme/data/\n\
+\tF\t/var/tank/vstors/acme/data/a\\0040b\n\
R\t/\t/var/tank/vstors/acme/data/old\t/var/tank/vstors/acme/data/new\n\
{\"dataset\": \"tank/vstors/acme/s3\", \"dir\": \"s3\", \"new\": true}\n\
{\"end\": true}\n";
        let d = parse_diff(&mut Cursor::new(s.as_bytes()), &dirs).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].lines[0].change, Change::Modified(b"data".to_vec()));
        assert_eq!(d[0].lines[1].change, Change::Added(b"data/a b".to_vec()));
        assert_eq!(
            d[0].lines[2].change,
            Change::Renamed {
                from: b"data/old".to_vec(),
                to: b"data/new".to_vec()
            }
        );
        assert!(d[1].new && d[1].lines.is_empty());
        let hdr = "{\"dataset\": \"x\", \"dir\": \"data\", \"mountpoint\": \"/m\"}\n";
        for bad in [
            format!("{hdr}+\tF\t/other/x\n{{\"end\": true}}\n"), // outside the mountpoint
            format!("{hdr}+\tF\t/m/../x\n{{\"end\": true}}\n"),  // traversal
            "{\"dataset\": \"x\", \"dir\": \"other\", \"mountpoint\": \"/m\"}\n{\"end\": true}\n".to_owned(),
            "{\"dataset\": \"x\", \"dir\": \"data\", \"mountpoint\": \"m\"}\n{\"end\": true}\n".to_owned(),
            format!("{hdr}{hdr}{{\"end\": true}}\n"),   // twice
            "+\tF\t/m/x\n{\"end\": true}\n".to_owned(), // no header
            format!("{hdr}+\tF\t/m/x\n"),               // no end line
            format!("{hdr}{{\"end\": true}}\nx\n"),     // trailing data
        ] {
            assert!(parse_diff(&mut Cursor::new(bad.as_bytes()), &dirs).is_err(), "{bad}");
        }
    }

    #[test]
    fn names() {
        assert!(valid_snap("nexusbackup-1793500000"));
        for s in [
            "nexusbackup-",
            "nexusbackup-01",
            "auto-1",
            "nexusbackup-1/x",
            "nexusbackup-1 ",
        ] {
            assert!(!valid_snap(s), "{s}");
        }
        assert!(valid_lun("vm1") && !valid_lun("..") && !valid_lun("a/b"));
        assert!(valid_tree_path("data/x") && !valid_tree_path(".nexus-streams") && !valid_tree_path("/data"));
    }
}
