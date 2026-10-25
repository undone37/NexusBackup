//! Instant rollback of a container in place (#55, docs/pve-connector.md "Instant
//! rollback"): file level, only the files that differ from the snapshot are written.
//!
//! 1. Checks (else [`Outcome::Fallback`], the caller restores in full with replace
//!    original): the container exists, is unprivileged (the node writes as its mapped
//!    root), and has the snapshot's backed-up mount points (same paths).
//! 2. It is shut down and tagged `nexus-rollback`; `rollback-ct-begin` on the node sets
//!    the PVE lock `rollback`, so it cannot be started meanwhile.
//! 3. `rollback-ct`: the node mounts it and lists every file of its current state with
//!    type, mode, ids, mtime, size and SHA-256 ([`read_listing`]). The appliance reads the
//!    snapshot's tar ([`plan`]), and sends the paths to delete (gone in the snapshot, or
//!    of another type) and a tar of the entries that differ, every directory (their
//!    modes and mtimes) and every hard link ([`write_tar`]). The node removes and extracts
//!    inside the container's user namespace, as PVE's own restore does.
//! 4. `rollback-ct-end` removes the lock, the tag goes, it starts if asked.
//!
//! Unlike a VM there is no pre-rollback backup: a container has no change tracking, so
//! backing up its current state reads all of it (back it up first to keep it). A failure
//! after the lock leaves it stopped and locked; running the rollback again resumes (the
//! listing is taken anew).

use crate::backup::read_config;
use crate::ct::{root_tar, source_name, CONFIG_FILE};
use crate::rollback::{conf_map, live_map, tags_with, RollbackOpts, TAG};
use anyhow::{bail, Context, Result};
use chunkstore::Store;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Child;
use tar::EntryType;

/// What the rollback needs from PVE (implemented for `Cluster`; tests use a fake).
pub trait CtOps {
    /// node of an existing container (`None`: no such guest, or a VM)
    fn locate(&self, vmid: u32) -> Result<Option<String>>;
    fn config(&self, node: &str, vmid: u32) -> Result<Map<String, Value>>;
    fn set_config(&self, node: &str, vmid: u32, changes: &[(String, Option<String>)]) -> Result<()>;
    fn running(&self, node: &str, vmid: u32) -> Result<bool>;
    /// `shutdown`, `start`, to completion
    fn act(&self, node: &str, vmid: u32, action: &str) -> Result<()>;
    /// `rollback-ct-begin` / `rollback-ct-end` on the node: its answer line
    fn helper(&self, node: &str, cmd: &str) -> Result<String>;
    /// a `rollback-ct <vmid>` session, stdin and stdout piped
    fn session(&self, node: &str, vmid: u32) -> Result<Child>;
}

/// Printed as `rolled-back {json}` for the job result.
#[derive(Debug, PartialEq, Serialize)]
pub struct Report {
    pub vmid: u32,
    pub snapshot: u64,
    pub resumed: bool,
    /// files (not directories) written, and their bytes
    pub files_written: u64,
    pub bytes_written: u64,
    pub deleted: u64,
    pub unchanged: u64,
    pub started: bool,
    pub link_down: bool,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    RolledBack(Report),
    /// in place is impossible (the reason); nothing was changed
    Fallback(String),
}

/// Paths of the mount points a backup includes (`mpN` with `backup=1`).
fn backed_up_mounts(conf: &std::collections::BTreeMap<String, String>) -> BTreeSet<String> {
    conf.iter()
        .filter(|(k, _)| k.strip_prefix("mp").is_some_and(|n| n.parse::<u32>().is_ok()))
        .filter_map(|(_, v)| {
            let opts: Vec<&str> = v.split(',').collect();
            opts.contains(&"backup=1")
                .then(|| opts.iter().find_map(|o| o.strip_prefix("mp=")))
                .flatten()
                .map(|p| p.trim_end_matches('/').to_owned())
        })
        .collect()
}

/// `None` when the container can be rolled back in place, else why not.
pub fn precheck(snap_conf: &str, live: &std::collections::BTreeMap<String, String>) -> Option<String> {
    if live.get("unprivileged").map(String::as_str) != Some("1") {
        return Some("the container is privileged (only unprivileged ones are rolled back in place)".into());
    }
    let (want, have) = (backed_up_mounts(&conf_map(snap_conf)), backed_up_mounts(live));
    if want != have {
        return Some(format!(
            "its backed-up mount points changed (snapshot: {want:?}, now: {have:?})"
        ));
    }
    None
}

/// Path of a tar entry or listing record as both compare it: no `./`, no trailing `/`,
/// the root is `.`.
pub fn norm(p: &[u8]) -> Vec<u8> {
    let p = p.strip_prefix(b"./").unwrap_or(p);
    let mut p = p;
    while let Some(q) = p.strip_suffix(b"/") {
        p = q;
    }
    if p.is_empty() {
        b".".to_vec()
    } else {
        p.to_vec()
    }
}

/// The node's listing: path -> `<type> <mode> <uid> <gid> <mtime> <size> <sha256|->`
/// (records up to an empty one, then its status line).
// ponytail: the whole listing in memory (some 100 bytes per file); stream a sorted one
// if containers with tens of millions of files appear.
pub fn read_listing(r: &mut impl BufRead) -> Result<HashMap<Vec<u8>, String>> {
    let mut map = HashMap::new();
    loop {
        let mut rec = Vec::new();
        r.read_until(0, &mut rec)?;
        if rec.pop() != Some(0) {
            bail!("listing ended early");
        }
        if rec.is_empty() {
            break;
        }
        let mut f = rec.splitn(8, |&b| b == b' ');
        let key: Vec<&[u8]> = f.by_ref().take(7).collect();
        let path = f.next().context("listing record without a path")?;
        map.insert(norm(path), String::from_utf8_lossy(&key.join(&b' ')).into_owned());
    }
    let mut status = String::new();
    r.read_line(&mut status)?;
    if status != "ok\n" {
        bail!("node: {}", status.trim().trim_start_matches("error "));
    }
    Ok(map)
}

/// The listing's type letter of a tar entry type; `None`: not a file (pax and GNU
/// meta headers).
fn type_char(t: EntryType) -> Option<char> {
    Some(match t {
        EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => '0',
        EntryType::Link => '1',
        EntryType::Symlink => '2',
        EntryType::Char => '3',
        EntryType::Block => '4',
        EntryType::Directory => '5',
        EntryType::Fifo => '6',
        _ => return None,
    })
}

/// What to change: the snapshot's entries to write (by normalized path) and the
/// current paths to delete first.
#[derive(Debug, Default)]
pub struct Plan {
    pub send: HashSet<Vec<u8>>,
    pub delete: Vec<Vec<u8>>,
    pub files: u64,
    pub bytes: u64,
    pub unchanged: u64,
}

/// An entry's pax extensions (xattrs, ACLs, GNU sparse keys, ...).
fn pax_map<R: Read>(e: &mut tar::Entry<R>) -> Result<Vec<(String, Vec<u8>)>> {
    Ok(match e.pax_extensions()? {
        Some(x) => x
            .filter_map(Result::ok)
            .filter_map(|x| Some((x.key().ok()?.to_owned(), x.value_bytes().to_vec())))
            .collect(),
        None => Vec::new(),
    })
}

fn pax_get<'a>(pax: &'a [(String, Vec<u8>)], key: &str) -> Option<&'a [u8]> {
    pax.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_slice())
}

/// The file's own path and, for a GNU tar PAX sparse file (format 1.0: what `--sparse` writes in POSIX
/// archives, which `--xattrs` / `--acls` select; ZFS compression makes many files look sparse), its real
/// size: the header names it `…/GNUSparseFile.<pid>/<name>` and its data starts with the sparse map.
fn real_path(raw: &[u8], pax: &[(String, Vec<u8>)]) -> Result<(Vec<u8>, Option<u64>)> {
    if !pax.iter().any(|(k, _)| k.starts_with("GNU.sparse.")) {
        return Ok((norm(raw), None));
    }
    let name = String::from_utf8_lossy(raw);
    if pax_get(pax, "GNU.sparse.major") != Some(b"1") || pax_get(pax, "GNU.sparse.minor") != Some(b"0") {
        bail!("{name}: a GNU sparse format other than PAX 1.0 is not supported");
    }
    let real = pax_get(pax, "GNU.sparse.name").with_context(|| format!("{name}: sparse without its name"))?;
    let size = pax_get(pax, "GNU.sparse.realsize")
        .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
        .with_context(|| format!("{name}: sparse without its size"))?;
    Ok((norm(real), Some(size)))
}

/// SHA-256 of a PAX 1.0 sparse file's content, holes as zeros: the data holds the map (decimal lines:
/// the count, then offset and length of each segment; padded to 512 bytes), then the segments.
fn sparse_sha256(r: impl Read, size: u64) -> io::Result<String> {
    let mut r = BufReader::new(r);
    let mut used = 0u64;
    let mut num = || -> io::Result<u64> {
        let mut line = Vec::new();
        used += r.by_ref().take(32).read_until(b'\n', &mut line)? as u64;
        std::str::from_utf8(line.trim_ascii())
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad sparse map"))
    };
    let n = num()?;
    let mut map = Vec::new();
    for _ in 0..n {
        map.push((num()?, num()?));
    }
    io::copy(&mut r.by_ref().take((512 - used % 512) % 512), &mut io::sink())?;
    let mut sha = Sha256::new();
    let mut pos = 0;
    let zeros = |sha: &mut Sha256, n: u64| io::copy(&mut io::repeat(0).take(n), sha);
    for (off, len) in map {
        if off < pos || off + len > size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad sparse map"));
        }
        zeros(&mut sha, off - pos)?;
        if io::copy(&mut r.by_ref().take(len), &mut sha)? != len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        pos = off + len;
    }
    zeros(&mut sha, size - pos)?;
    Ok(hex(&sha.finalize()))
}

/// Compares the snapshot's tar with the listing of the current state.
pub fn plan(target: impl Read, current: &HashMap<Vec<u8>, String>) -> Result<Plan> {
    let mut p = Plan::default();
    let mut seen = HashSet::new();
    let mut ar = tar::Archive::new(target);
    for e in ar.entries().context("snapshot tar")? {
        let mut e = e.context("snapshot tar entry")?;
        let Some(t) = type_char(e.header().entry_type()) else {
            continue;
        };
        let pax = pax_map(&mut e)?;
        let (path, sparse) = real_path(&e.path_bytes(), &pax)?;
        let h = e.header();
        let (mode, uid, gid, mtime) = (h.mode()? & 0o7777, h.uid()?, h.gid()?, h.mtime()?);
        let (size, hash) = match (t, sparse) {
            ('0', Some(size)) => (size, sparse_sha256(&mut e, size).context("snapshot tar sparse data")?),
            ('0', None) => {
                let mut sha = Sha256::new();
                let n = io::copy(&mut e, &mut sha).context("snapshot tar data")?;
                (n, hex(&sha.finalize()))
            }
            ('1' | '2', _) => (0, hex(&Sha256::digest(e.link_name_bytes().unwrap_or_default()))),
            _ => (0, "-".into()),
        };
        let key = format!("{t} {mode:o} {uid} {gid} {mtime} {size} {hash}");
        let have = current.get(&path);
        if let Some(cur) = have {
            let ct = cur.chars().next();
            // tar replaces a file, a link or a symlink by itself, never a directory or by one
            if ct != Some(t) && !(t == '1' && ct == Some('0')) && (ct == Some('5') || t == '5' || t == '1') {
                p.delete.push(path.clone());
            }
        }
        if t == '5' || t == '1' || have != Some(&key) {
            if t != '5' {
                p.files += 1;
                p.bytes += size;
            }
            p.send.insert(path.clone());
        } else {
            p.unchanged += 1;
        }
        seen.insert(path);
    }
    p.delete.extend(
        current
            .keys()
            .filter(|k| !seen.contains(*k) && k.as_slice() != b".")
            .cloned(),
    );
    p.delete.sort();
    p.delete.dedup();
    Ok(p)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Re-reads the snapshot's tar and writes the entries of `plan.send` as they are (headers, pax
/// extensions such as xattrs, ACLs and the PAX sparse keys, data; old GNU sparse files as regular ones).
pub fn write_tar(target: impl Read, plan: &Plan, out: impl Write) -> Result<()> {
    let mut b = tar::Builder::new(out);
    let mut ar = tar::Archive::new(target);
    for e in ar.entries().context("snapshot tar")? {
        let mut e = e.context("snapshot tar entry")?;
        if type_char(e.header().entry_type()).is_none() {
            continue;
        }
        let path = e.path_bytes().into_owned();
        let mut pax = pax_map(&mut e)?;
        if !plan.send.contains(&real_path(&path, &pax)?.0) {
            continue;
        }
        // the builder writes the path and the link target itself
        pax.retain(|(k, _)| !matches!(k.as_str(), "path" | "linkpath"));
        if !pax.is_empty() {
            b.append_pax_extensions(pax.iter().map(|(k, v)| (k.as_str(), v.as_slice())))?;
        }
        let mut h = e.header().clone();
        let p = Path::new(OsStr::from_bytes(&path));
        match h.entry_type() {
            EntryType::Link | EntryType::Symlink => {
                let target = e.link_name_bytes().context("link without a target")?.into_owned();
                b.append_link(&mut h, p, Path::new(OsStr::from_bytes(&target)))?;
            }
            t => {
                if t == EntryType::GNUSparse {
                    h.set_entry_type(EntryType::Regular);
                    h.set_size(e.size());
                }
                b.append_data(&mut h, p, &mut e)?;
            }
        }
    }
    b.into_inner()?.flush()?;
    Ok(())
}

/// One `rollback-ct` session: listing in, plan, delete list and tar out, the answer.
fn apply(mut child: Child, store: &Store, root: &chunkstore::FileEntry) -> Result<Plan> {
    let mut out = BufReader::with_capacity(1 << 20, child.stdout.take().context("session stdout")?);
    let current = read_listing(&mut out).context("listing of the current state")?;
    let plan = plan(store.chunk_reader(&root.chunks), &current)?;
    println!(
        "{} files differ ({} bytes), {} unchanged, {} paths to delete",
        plan.files,
        plan.bytes,
        plan.unchanged,
        plan.delete.len()
    );
    let mut w = BufWriter::with_capacity(1 << 20, child.stdin.take().context("session stdin")?);
    let list: Vec<u8> = plan.delete.iter().flat_map(|d| d.iter().copied().chain([0])).collect();
    w.write_all(&(list.len() as u64).to_be_bytes())?;
    w.write_all(&list)?;
    write_tar(store.chunk_reader(&root.chunks), &plan, &mut w)?;
    w.flush()?;
    drop(w);
    let mut answer = String::new();
    out.read_line(&mut answer)?;
    let _ = child.wait();
    if !answer.starts_with("ok applied") {
        bail!("node: {}", answer.trim().trim_start_matches("error "));
    }
    Ok(plan)
}

/// Rolls container `vmid` back to snapshot `ct-<vmid>/<time>` in place (module doc).
pub fn rollback(ops: &impl CtOps, store: &Store, vmid: u32, time: u64, o: &RollbackOpts) -> Result<Outcome> {
    let m = store.load_manifest(&source_name(vmid), time)?;
    let snap_conf = read_config(store, &m, CONFIG_FILE)?.context("snapshot without pct.conf")?;
    let root = root_tar(store, &m)?;
    let Some(node) = ops.locate(vmid)? else {
        return Ok(Outcome::Fallback(format!("container {vmid} no longer exists")));
    };
    let live = live_map(&ops.config(&node, vmid)?);
    let tagged = live
        .get("tags")
        .is_some_and(|t| t.split([';', ',', ' ']).any(|x| x == TAG));
    let resumed = tagged && live.get("lock").map(String::as_str) == Some("rollback");
    if resumed {
        println!("resuming the interrupted rollback of container {vmid}");
    } else {
        if let Some(why) = precheck(&snap_conf, &live) {
            return Ok(Outcome::Fallback(why));
        }
        if ops.running(&node, vmid)? {
            ops.act(&node, vmid, "shutdown").context("shut the container down")?;
        }
        ops.set_config(&node, vmid, &[("tags".into(), tags_with(live.get("tags"), true))])
            .context("tag the container for the rollback")?;
    }
    let answer = ops.helper(&node, &format!("rollback-ct-begin {vmid}"))?;
    println!("node {node}: {answer}");
    let plan = ops.session(&node, vmid).and_then(|c| apply(c, store, &root)).context(
        "rollback interrupted: the container stays stopped and locked (rollback); run the rollback again to \
             finish it, or restore it with Replace original",
    )?;
    let answer = ops.helper(&node, &format!("rollback-ct-end {vmid}"))?;
    println!("node {node}: {answer}");
    let live = ops.config(&node, vmid)?;
    let mut changes = vec![("tags".to_owned(), tags_with(live_map(&live).get("tags"), false))];
    if o.link_down {
        changes.extend(crate::restore::link_down_changes(&live));
    }
    ops.set_config(&node, vmid, &changes).context("untag the container")?;
    if o.start {
        ops.act(&node, vmid, "start").context("start the container")?;
    }
    Ok(Outcome::RolledBack(Report {
        vmid,
        snapshot: time,
        resumed,
        files_written: plan.files,
        bytes_written: plan.bytes,
        deleted: plan.delete.len() as u64,
        unchanged: plan.unchanged,
        started: o.start,
        link_down: o.link_down,
    }))
}

impl CtOps for crate::backup::Cluster {
    fn locate(&self, vmid: u32) -> Result<Option<String>> {
        Ok(self
            .guest_nodes()?
            .remove(&vmid)
            .filter(|(_, k)| k == "lxc")
            .map(|(n, _)| n))
    }
    fn config(&self, node: &str, vmid: u32) -> Result<Map<String, Value>> {
        self.api.guest_config(node, "lxc", vmid)
    }
    fn set_config(&self, node: &str, vmid: u32, changes: &[(String, Option<String>)]) -> Result<()> {
        self.api.set_config(node, "lxc", vmid, changes)
    }
    fn running(&self, node: &str, vmid: u32) -> Result<bool> {
        self.api.guest_running(node, "lxc", vmid)
    }
    fn act(&self, node: &str, vmid: u32, action: &str) -> Result<()> {
        let form: &[(&str, &str)] = if action == "shutdown" {
            &[("timeout", "180"), ("forceStop", "1")]
        } else {
            &[]
        };
        self.api.guest_power(node, "lxc", vmid, action, form)
    }
    fn helper(&self, node: &str, cmd: &str) -> Result<String> {
        let out = self.ssh(node)?.run(cmd, None)?;
        Ok(String::from_utf8_lossy(&out).trim().to_owned())
    }
    fn session(&self, node: &str, vmid: u32) -> Result<Child> {
        Ok(self
            .ssh(node)?
            .cmd(&format!("rollback-ct {vmid}"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_compare_without_dot_slash() {
        assert_eq!(norm(b"./etc/"), b"etc");
        assert_eq!(norm(b"./"), b".");
        assert_eq!(norm(b"."), b".");
        assert_eq!(norm(b"var/lib"), b"var/lib");
    }

    #[test]
    fn precheck_privileged_and_mount_points() {
        let snap = "unprivileged: 1\nmp0: local:vol-1,mp=/data,backup=1\nmp1: local:vol-2,mp=/scratch\n";
        let live = |extra: &[(&str, &str)]| {
            let mut m = conf_map("unprivileged: 1\nmp0: local:vol-1,mp=/data/,backup=1\n");
            m.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
            m
        };
        assert_eq!(precheck(snap, &live(&[])), None, "mp1 has no backup: not compared");
        assert!(precheck(snap, &live(&[("unprivileged", "0")]))
            .unwrap()
            .contains("privileged"));
        assert!(precheck(snap, &live(&[("mp2", "local:vol-3,mp=/srv,backup=1")]))
            .unwrap()
            .contains("mount points"));
    }

    #[test]
    fn pax_sparse_files() {
        let map = b"2\n0\n3\n10\n2\n";
        let mut data = map.to_vec();
        data.resize(512, 0);
        data.extend_from_slice(b"abcxy");
        assert_eq!(
            sparse_sha256(&data[..], 16).unwrap(),
            hex(&Sha256::digest(b"abc\0\0\0\0\0\0\0xy\0\0\0\0"))
        );
        assert!(sparse_sha256(&data[..], 11).is_err(), "a segment beyond the size");
        let pax = |major: &str| {
            vec![
                ("GNU.sparse.major".to_owned(), major.as_bytes().to_vec()),
                ("GNU.sparse.minor".to_owned(), b"0".to_vec()),
                ("GNU.sparse.name".to_owned(), b"./etc/big".to_vec()),
                ("GNU.sparse.realsize".to_owned(), b"16".to_vec()),
            ]
        };
        let raw = b"./etc/GNUSparseFile.77/big";
        assert_eq!(real_path(raw, &pax("1")).unwrap(), (b"etc/big".to_vec(), Some(16)));
        assert!(real_path(raw, &pax("0")).is_err(), "other sparse formats are refused");
        assert_eq!(real_path(b"./etc/a", &[]).unwrap(), (b"etc/a".to_vec(), None));
    }

    #[test]
    fn listing_records_and_status() {
        let raw = b"5 755 0 0 1 0 - .\x000 644 0 0 2 3 abc etc/a b\x00\x00ok\n";
        let m = read_listing(&mut &raw[..]).unwrap();
        assert_eq!(m[&b"etc/a b".to_vec()], "0 644 0 0 2 3 abc");
        assert_eq!(m.len(), 2);
        let err = read_listing(&mut &b"\x00error CT 1 is running\n"[..]).unwrap_err();
        assert!(err.to_string().contains("CT 1 is running"), "{err}");
        assert!(read_listing(&mut &b"5 755 0 0 1 0 - ."[..]).is_err(), "cut short");
    }
}
