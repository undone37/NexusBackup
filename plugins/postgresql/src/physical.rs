//! Physical backup of the whole cluster over the replication protocol, and the
//! point-in-time restore built from it.
//!
//! Snapshot layout (files, so incrementals can say `Unchanged`):
//! `data/…` the base backup (BASE_BACKUP: data directory incl. backup_label,
//! tablespace_map, backup_manifest and the WAL needed to make it consistent),
//! `tablespaces/<oid>/…` other tablespaces, `wal/<segment>` all WAL since the base
//! backup, streamed from a physical replication slot (which keeps the server from
//! recycling WAL between backups). A full backup re-creates the slot; an
//! incremental one re-references `data/` and the earlier segments from the
//! previous snapshot and streams the new WAL up to the server's current position
//! (the last segment is zero-padded and streamed again next time). Every snapshot
//! is therefore self-contained: base backup + WAL up to the snapshot's time.

use crate::pg::{be64, data_row, error, fmt_lsn, Conn, Opts, Row};
use anyhow::{anyhow, bail, Context, Result};
use plugin_sdk::{Ctx, Kind, Meta, Sink, Source};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub v: u32,
    /// IDENTIFY_SYSTEM systemid / timeline of the backed-up cluster
    pub system: String,
    pub tli: u32,
    /// WAL segment size
    pub seg: u64,
    /// time of the base backup (unix seconds)
    pub full_time: u64,
    /// first LSN of `wal/` (= segment of the base backup's end)
    pub wal_from: u64,
    /// segment-aligned LSN the next incremental streams from
    pub next: u64,
    /// all paths of `data/` and `tablespaces/`, front-coded (`<shared prefix len>:<rest>`)
    pub files: Vec<String>,
}

/// State blobs are ≤ 1 MiB; a larger path list is dropped (= the next backup is full).
const MAX_STATE: usize = 1000 << 10;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn encode_paths(paths: &[String]) -> Vec<String> {
    let mut prev = "";
    paths
        .iter()
        .map(|p| {
            let n = prev
                .char_indices()
                .zip(p.chars())
                .take_while(|((_, a), b)| a == b)
                .last()
                .map_or(0, |((i, a), _)| i + a.len_utf8());
            prev = p;
            format!("{n}:{}", &p[n..])
        })
        .collect()
}

pub fn decode_paths(enc: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(enc.len());
    for e in enc {
        let (n, rest) = e.split_once(':').context("state: bad path entry")?;
        let n: usize = n.parse()?;
        let prev = out.last().map_or("", String::as_str);
        let head = prev.get(..n).context("state: bad path prefix")?;
        out.push(format!("{head}{rest}"));
    }
    Ok(out)
}

/// WAL segment file name.
pub fn seg_name(tli: u32, lsn: u64, seg: u64) -> String {
    let segno = lsn / seg;
    let per_id = 0x1_0000_0000 / seg;
    format!("{tli:08X}{:08X}{:08X}", segno / per_id, segno % per_id)
}

fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let n: u64 = s[..split].parse().with_context(|| format!("size {s:?}"))?;
    Ok(n * match s[split..].trim() {
        "" | "B" => 1,
        "kB" => 1 << 10,
        "MB" => 1 << 20,
        "GB" => 1 << 30,
        u => bail!("size unit {u:?}"),
    })
}

fn meta(kind: Kind, mode: u32, size: u64, mtime: u64) -> Meta {
    Meta {
        kind: Some(kind),
        mode,
        size,
        mtime_ns: mtime as i64 * 1_000_000_000,
        ..Default::default()
    }
}

/// (systemid, timeline, current WAL flush position)
fn identify(c: &mut Conn) -> Result<(String, u32, u64)> {
    let r = c.query("IDENTIFY_SYSTEM")?;
    let r = r.first().context("IDENTIFY_SYSTEM: no row")?;
    let get = |i: usize| r.get(i).cloned().flatten().unwrap_or_default();
    Ok((get(0), get(1).parse()?, crate::pg::parse_lsn(&get(2))?))
}

pub struct Report {
    pub state: State,
    pub summary: String,
}

/// Backup of the cluster: incremental on top of `prev` if possible, else full.
pub fn backup(ctx: &Ctx, sink: &mut Sink, o: &Opts, slot: &str, full_days: u64) -> Result<Report> {
    let prev: Option<State> = ctx
        .state
        .as_deref()
        .filter(|_| sink.has_base())
        .and_then(|s| serde_json::from_slice(s).ok());
    if let Some(p) = prev {
        if p.files.is_empty() {
            ctx.info("previous snapshot has no file list: full backup");
        } else if now().saturating_sub(p.full_time) >= full_days * 86400 {
            ctx.info(format!("base backup older than {full_days} days: full backup"));
        } else if let Some(r) = incremental(ctx, sink, o, slot, &p)? {
            return Ok(r);
        }
    }
    full(ctx, sink, o, slot)
}

fn full(ctx: &Ctx, sink: &mut Sink, o: &Opts, slot: &str) -> Result<Report> {
    let mut c = Conn::connect(o)?;
    let (system, tli, _) = identify(&mut c)?;
    let seg = parse_size(&c.value("SHOW wal_segment_size")?.unwrap_or_default())?;
    // a fresh slot: it holds the WAL from before the base backup on
    match c.exec(&format!("DROP_REPLICATION_SLOT {slot}")) {
        Err(e) if crate::pg::sqlstate(&e) == Some("42704") => {}
        r => r.context("dropping the old replication slot")?,
    }
    c.exec(&format!("CREATE_REPLICATION_SLOT {slot} PHYSICAL RESERVE_WAL"))
        .context("creating the replication slot")?;
    let cmd = if c.major >= 15 {
        "BASE_BACKUP (LABEL 'nexusbackup', CHECKPOINT 'fast', WAL true, WAIT true, MANIFEST 'yes', TABLESPACE_MAP true)"
    } else {
        "BASE_BACKUP LABEL 'nexusbackup' FAST WAL MANIFEST 'yes' TABLESPACE_MAP"
    };
    ctx.info(format!(
        "base backup of PostgreSQL {} (timeline {tli})",
        c.server_version
    ));
    let t0 = now();
    sink.entry(b"data", meta(Kind::Dir, 0o700, 0, t0))?;
    let mut files = vec!["data".to_owned()];
    // result sets: start position, tablespaces, (COPY), end position — split by
    // RowDescription (newer servers send no CommandComplete between them)
    let mut results: Vec<Vec<Row>> = Vec::new();
    let mut copies = 0usize;
    let mut bytes = 0u64;
    c.query_start(cmd)?;
    loop {
        let (t, b) = c.recv()?;
        match t {
            b'T' => results.push(Vec::new()),
            b'D' => results
                .last_mut()
                .context("BASE_BACKUP: row without a result")?
                .push(data_row(&b)?),
            b'H' if c.major >= 15 => {
                // one COPY: 'n' new archive, 'd' data, 'p' progress, 'm' manifest follows
                let mut ev = CopyReader::new(&mut c, true).boundary()?;
                loop {
                    match ev {
                        Ev::Archive(name) => {
                            let prefix = archive_prefix(&name)?;
                            let mut r = CopyReader::new(&mut c, true);
                            bytes += send_tar(ctx, sink, &mut r, &prefix, &mut files, t0)?;
                            ev = r.boundary()?;
                        }
                        Ev::Manifest => {
                            let mut m = Vec::new();
                            let mut r = CopyReader::new(&mut c, true);
                            r.read_to_end(&mut m)?;
                            ev = r.boundary()?;
                            sink.file(
                                b"data/backup_manifest",
                                meta(Kind::File, 0o600, m.len() as u64, t0),
                                &mut &m[..],
                            )?;
                            files.push("data/backup_manifest".into());
                        }
                        Ev::End => break,
                    }
                }
            }
            b'H' => {
                // PostgreSQL 14: one COPY per tablespace (in the order of the
                // tablespace result, the main directory last), then the manifest
                let ts = results.get(1).context("BASE_BACKUP: no tablespace list")?;
                let mut r = CopyReader::new(&mut c, false);
                match ts.get(copies) {
                    Some(row) => {
                        let prefix = match row.first().cloned().flatten() {
                            Some(oid) => archive_prefix(&format!("{oid}.tar"))?,
                            None => "data".to_owned(),
                        };
                        bytes += send_tar(ctx, sink, &mut r, &prefix, &mut files, t0)?;
                        io::copy(&mut r, &mut io::sink())?;
                    }
                    None => {
                        let mut m = Vec::new();
                        r.read_to_end(&mut m)?;
                        sink.file(
                            b"data/backup_manifest",
                            meta(Kind::File, 0o600, m.len() as u64, t0),
                            &mut &m[..],
                        )?;
                        files.push("data/backup_manifest".into());
                    }
                }
                copies += 1;
            }
            b'E' => return Err(error(&b)).context("BASE_BACKUP"),
            b'Z' => break,
            _ => {}
        }
    }
    let end = results
        .last()
        .and_then(|r| r.first())
        .and_then(|r| r.first().cloned().flatten())
        .context("BASE_BACKUP: no end position")?;
    let end = crate::pg::parse_lsn(&end)?;
    c.close();
    let next = end - end % seg;
    let mut st = State {
        v: 1,
        system,
        tli,
        seg,
        full_time: t0,
        wal_from: next,
        next,
        files: encode_paths(&files),
    };
    if serde_json::to_vec(&st)?.len() > MAX_STATE {
        ctx.warn("too many files for an incremental chain: the next backup is full again");
        st.files.clear();
    }
    Ok(Report {
        state: st,
        summary: format!(
            "full: base backup {} files, {} bytes, end {}",
            files.len(),
            bytes,
            fmt_lsn(end)
        ),
    })
}

fn archive_prefix(name: &str) -> Result<String> {
    if name == "base.tar" {
        return Ok("data".into());
    }
    match name.strip_suffix(".tar") {
        Some(oid) if !oid.is_empty() && oid.bytes().all(|b| b.is_ascii_digit()) => Ok(format!("tablespaces/{oid}")),
        _ => bail!("BASE_BACKUP: unexpected archive {name:?}"),
    }
}

/// Sends the entries of one tar archive below `prefix`; returns the file bytes.
fn send_tar(
    ctx: &Ctx,
    sink: &mut Sink,
    r: &mut dyn Read,
    prefix: &str,
    files: &mut Vec<String>,
    t0: u64,
) -> Result<u64> {
    if prefix != "data" {
        for p in ["tablespaces".to_owned(), prefix.to_owned()] {
            if !files.contains(&p) {
                sink.entry(p.as_bytes(), meta(Kind::Dir, 0o700, 0, t0))?;
                files.push(p);
            }
        }
    }
    let mut bytes = 0;
    let mut a = tar::Archive::new(r);
    for e in a.entries()? {
        let mut e = e?;
        let raw = e.path_bytes().into_owned();
        let rel = String::from_utf8(raw).context("non-UTF-8 path in the base backup")?;
        let rel = rel.trim_start_matches("./").trim_end_matches('/');
        if rel.is_empty() {
            continue;
        }
        let path = format!("{prefix}/{rel}");
        let h = e.header();
        let (mode, mtime) = (h.mode()? & 0o7777, h.mtime()?);
        match h.entry_type() {
            tar::EntryType::Regular => {
                let size = e.size();
                bytes += size;
                sink.file(path.as_bytes(), meta(Kind::File, mode, size, mtime), &mut e)?;
            }
            tar::EntryType::Directory => sink.entry(path.as_bytes(), meta(Kind::Dir, mode, 0, mtime))?,
            tar::EntryType::Symlink => {
                let mut m = meta(Kind::Symlink, 0o777, 0, mtime);
                m.link_target = e.link_name_bytes().map(|l| l.into_owned());
                sink.entry(path.as_bytes(), m)?;
            }
            t => {
                ctx.warn(format!("{path}: tar entry type {t:?} skipped"));
                continue;
            }
        }
        files.push(path);
    }
    // the rest of the archive (end-of-archive blocks) up to the next boundary
    io::copy(&mut a.into_inner(), &mut io::sink())?;
    Ok(bytes)
}

enum Ev {
    Archive(String),
    Manifest,
    End,
}

/// The data of one archive of a BASE_BACKUP COPY; EOF at the next boundary.
struct CopyReader<'a> {
    c: &'a mut Conn,
    /// PostgreSQL ≥ 15: typed CopyData ('n'/'d'/'p'/'m')
    typed: bool,
    buf: Vec<u8>,
    pos: usize,
    ev: Option<Ev>,
}

impl<'a> CopyReader<'a> {
    fn new(c: &'a mut Conn, typed: bool) -> Self {
        CopyReader {
            c,
            typed,
            buf: Vec::new(),
            pos: 0,
            ev: None,
        }
    }

    /// Skips to the boundary and returns it.
    fn boundary(mut self) -> Result<Ev> {
        io::copy(&mut self, &mut io::sink())?;
        self.ev.take().context("COPY ended without a boundary")
    }
}

impl Read for CopyReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            if self.ev.is_some() {
                return Ok(0);
            }
            let (t, b) = self.c.recv().map_err(io::Error::other)?;
            match t {
                b'd' if !self.typed => (self.buf, self.pos) = (b, 0),
                b'd' => match b.first() {
                    Some(b'd') => (self.buf, self.pos) = (b, 1),
                    Some(b'n') => {
                        let name = b[1..].split(|x| *x == 0).next().unwrap_or_default();
                        self.ev = Some(Ev::Archive(String::from_utf8_lossy(name).into_owned()));
                    }
                    Some(b'm') => self.ev = Some(Ev::Manifest),
                    Some(b'p') => {}
                    _ => return Err(io::Error::other("BASE_BACKUP: unknown COPY message")),
                },
                b'c' => self.ev = Some(Ev::End),
                b'E' => return Err(io::Error::other(error(&b))),
                t => {
                    return Err(io::Error::other(format!(
                        "BASE_BACKUP: unexpected message {:?}",
                        t as char
                    )))
                }
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Incremental: previous data + WAL as `Unchanged`, new WAL streamed. None = do a full backup.
fn incremental(ctx: &Ctx, sink: &mut Sink, o: &Opts, slot: &str, p: &State) -> Result<Option<Report>> {
    let mut c = Conn::connect(o)?;
    let (system, tli, target) = identify(&mut c)?;
    if system != p.system || tli != p.tli {
        ctx.info(format!(
            "cluster or timeline changed ({} tl {} → {system} tl {tli}): full backup",
            p.system, p.tli
        ));
        return Ok(None);
    }
    let data = decode_paths(&p.files)?;
    let old_wal: Vec<String> = (p.wal_from / p.seg..p.next / p.seg)
        .map(|s| format!("wal/{}", seg_name(p.tli, s * p.seg, p.seg)))
        .collect();
    let paths: Vec<Vec<u8>> = data.iter().chain(&old_wal).map(|s| s.as_bytes().to_vec()).collect();
    let base: HashMap<Vec<u8>, Meta> = sink.base(&paths)?.into_iter().map(|e| (e.path, e.meta)).collect();
    if paths.iter().any(|p| !base.contains_key(p)) {
        ctx.info("previous snapshot incomplete: full backup");
        return Ok(None);
    }
    // start streaming before sending anything: if the slot lost the WAL, a full backup follows
    let streaming = target > p.next;
    if streaming {
        c.query_start(&format!(
            "START_REPLICATION SLOT {slot} PHYSICAL {} TIMELINE {tli}",
            fmt_lsn(p.next)
        ))?;
        loop {
            let (t, b) = c.recv()?;
            match t {
                b'W' => break,
                b'E' => {
                    ctx.warn(format!("WAL streaming refused ({}): full backup", error(&b)));
                    return Ok(None);
                }
                _ => {}
            }
        }
    }
    let t0 = now();
    for path in paths.iter().take(data.len()) {
        let m = base[path].clone();
        if m.kind == Some(Kind::File) {
            sink.unchanged(path, m)?;
        } else {
            sink.entry(path, m)?;
        }
    }
    sink.entry(b"wal", meta(Kind::Dir, 0o700, 0, t0))?;
    for path in &paths[data.len()..] {
        sink.unchanged(path, base[path].clone())?;
    }
    let mut new = 0u64;
    if streaming {
        let mut w = Wal {
            c: &mut c,
            pos: p.next,
            target,
            buf: Vec::new(),
            off: 0,
            flush: p.next,
            status_at: Instant::now(),
        };
        // the slot may now drop everything before the previous snapshot's end
        w.status()?;
        let mut lsn = p.next;
        while lsn < target {
            let name = seg_name(tli, lsn, p.seg);
            let mut s = Seg {
                w: &mut w,
                at: lsn,
                end: lsn + p.seg,
            };
            sink.file(
                format!("wal/{name}").as_bytes(),
                meta(Kind::File, 0o600, p.seg, t0),
                &mut s,
            )?;
            new += 1;
            lsn += p.seg;
            ctx.progress(lsn - p.next, target - p.next, format!("WAL {name}"));
        }
        let _ = c.send(b'c', &[]);
    }
    c.close();
    let next = target - target % p.seg;
    let st = State {
        next: next.max(p.next),
        ..p.clone()
    };
    Ok(Some(Report {
        state: st,
        summary: format!(
            "incremental: {} data entries unchanged, {} WAL segments ({} new), up to {}",
            data.len(),
            old_wal.len() as u64 + new,
            new,
            fmt_lsn(target)
        ),
    }))
}

/// Physical replication stream from `pos`; bytes up to `target` are used.
struct Wal<'a> {
    c: &'a mut Conn,
    /// LSN of `buf[off]`
    pos: u64,
    target: u64,
    buf: Vec<u8>,
    off: usize,
    /// what the slot may release (the previous snapshot's end)
    flush: u64,
    status_at: Instant,
}

impl Wal<'_> {
    /// Standby status update: received up to `pos`, "flushed" only up to `flush`.
    fn status(&mut self) -> Result<()> {
        let epoch_2000 = 946_684_800u64;
        let us = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64 - epoch_2000 * 1_000_000;
        let mut m = vec![b'r'];
        for v in [self.pos, self.flush, self.flush, us] {
            m.extend_from_slice(&v.to_be_bytes());
        }
        m.push(0);
        self.status_at = Instant::now();
        self.c.send(b'd', &m)
    }

    fn fill(&mut self) -> Result<()> {
        while self.off == self.buf.len() {
            if self.status_at.elapsed().as_secs() >= 10 {
                self.status()?;
            }
            let (t, b) = self.c.recv()?;
            match (t, b.first()) {
                (b'd', Some(b'w')) => {
                    let start = be64(&b, 1)?;
                    if start != self.pos {
                        bail!("WAL stream at {}, expected {}", fmt_lsn(start), fmt_lsn(self.pos));
                    }
                    self.buf = b;
                    self.off = 25;
                }
                (b'd', Some(b'k')) => {
                    if b.get(17) == Some(&1) {
                        self.status()?;
                    }
                }
                (b'c', _) => bail!(
                    "the server ended WAL streaming at {} (timeline switch?)",
                    fmt_lsn(self.pos)
                ),
                (b'E', _) => return Err(error(&b).into()),
                (t, _) => bail!("unexpected message {:?} in the WAL stream", t as char),
            }
        }
        Ok(())
    }
}

/// One WAL segment: streamed bytes up to the target, zeros after it.
struct Seg<'a, 'b> {
    w: &'b mut Wal<'a>,
    at: u64,
    end: u64,
}

impl Read for Seg<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at >= self.end {
            return Ok(0);
        }
        let left = (self.end - self.at) as usize;
        if self.at >= self.w.target {
            let n = out.len().min(left);
            out[..n].fill(0);
            self.at += n as u64;
            return Ok(n);
        }
        self.w.fill().map_err(io::Error::other)?;
        let n = out
            .len()
            .min(left)
            .min(self.w.buf.len() - self.w.off)
            .min((self.w.target - self.at) as usize);
        out[..n].copy_from_slice(&self.w.buf[self.w.off..self.w.off + n]);
        self.w.off += n;
        self.w.pos += n as u64;
        self.at += n as u64;
        Ok(n)
    }
}

/// Point-in-time restore: unpacks `data/` as a new data directory on the restore
/// host (SSH), the WAL into `<dir>/nexus_wal/`, and configures recovery (target time
/// or end of WAL, then promote). The user starts PostgreSQL (same major version) on it.
pub fn pitr(ctx: &Ctx, src: &mut Source, ssh: &crate::ssh::Ssh) -> Result<String> {
    let p = &ctx.params["params"];
    let dir = p["directory"].as_str().unwrap_or_default();
    if !valid_dir(dir) {
        bail!("directory: an absolute path of [A-Za-z0-9._/-], without `..`");
    }
    let top: Vec<&str> = ctx.params["top"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    if !top.contains(&"data") {
        bail!("this snapshot holds no base backup (point-in-time restore needs a cluster snapshot)");
    }
    if top.contains(&"tablespaces") {
        bail!("snapshots with additional tablespaces cannot be restored point-in-time yet (use the download)");
    }
    let mut conf = String::from("\n# NexusBackup point-in-time restore\nrestore_command = 'cp nexus_wal/%f \"%p\"'\n");
    if let Some(t) = p["target_time"].as_str().filter(|t| !t.is_empty()) {
        conf += &format!("recovery_target_time = {}\n", crate::pg::lit(t));
    }
    conf += "recovery_target_action = 'promote'\narchive_mode = 'off'\n";
    if let Some(port) = p["port"].as_u64() {
        conf += &format!("port = {port}\n");
    }

    let q = crate::ssh::sh_quote(dir);
    ssh.run(&format!("umask 077 && mkdir -- {q} && command -v tar >/dev/null"))
        .context("creating the target directory (it must not exist)")?;
    let exec = ssh.exec(&format!("exec tar -x -f - -C {q}"))?;
    let mut tar = tar::Builder::new(io::BufWriter::with_capacity(1 << 18, exec));
    let (mut files, mut bytes, mut wal) = (0u64, 0u64, 0u64);
    let mut seen_conf = false;
    src.files(&[b"data".to_vec(), b"wal".to_vec()], |item, data| {
        let path = String::from_utf8_lossy(&item.path).into_owned();
        let rel = match path.split_once('/') {
            Some(("data", r)) => r.to_owned(),
            Some(("wal", r)) => {
                wal += 1;
                format!("nexus_wal/{r}")
            }
            None if path == "wal" => "nexus_wal".into(),
            _ => return Ok(()),
        };
        let m = &item.meta;
        let mut h = tar::Header::new_gnu();
        h.set_mode(m.mode & 0o7777);
        h.set_mtime(m.mtime_ns.max(0) as u64 / 1_000_000_000);
        match m.kind.unwrap_or(Kind::File) {
            Kind::Dir => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                tar.append_data(&mut h, &rel, io::empty())?;
            }
            Kind::File if rel == "postgresql.auto.conf" => {
                let mut c = Vec::new();
                data.read_to_end(&mut c)?;
                c.extend_from_slice(conf.as_bytes());
                h.set_size(c.len() as u64);
                tar.append_data(&mut h, &rel, &c[..])?;
                seen_conf = true;
            }
            Kind::File => {
                h.set_size(m.size);
                tar.append_data(&mut h, &rel, data)?;
                files += 1;
                bytes += m.size;
            }
            k => ctx.warn(format!("{path}: {k:?} skipped")),
        }
        Ok(())
    })?;
    let mut h = tar::Header::new_gnu();
    h.set_mode(0o600);
    h.set_mtime(now());
    h.set_size(0);
    tar.append_data(&mut h, "recovery.signal", io::empty())?;
    if !seen_conf {
        h.set_size(conf.len() as u64);
        tar.append_data(&mut h, "postgresql.auto.conf", conf.as_bytes())?;
    }
    let exec = tar
        .into_inner()?
        .into_inner()
        .map_err(|e| anyhow!("ssh: {}", e.error()))?;
    exec.finish().context("unpacking on the restore host")?;
    let until = p["target_time"]
        .as_str()
        .filter(|t| !t.is_empty())
        .map_or("the end of the WAL".to_owned(), |t| t.to_owned());
    Ok(format!(
        "{files} files ({bytes} bytes) + {wal} WAL segments restored to {dir}; recovery to {until}, then promote: \
         start PostgreSQL of the same major version on it (pg_ctl -D {dir} start)"
    ))
}

pub fn valid_dir(d: &str) -> bool {
    d.len() > 1
        && d.len() <= 1024
        && d.starts_with('/')
        && d.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && d.split('/').all(|c| c != ".." && c != ".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn front_coding_roundtrip() {
        let p: Vec<String> = [
            "data",
            "data/base",
            "data/base/1",
            "data/base/1/112",
            "data/base/1/113",
            "data/x",
            "wal",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let e = encode_paths(&p);
        assert_eq!(e[3], "11:/112");
        assert_eq!(decode_paths(&e).unwrap(), p);
        assert!(decode_paths(&["9:x".into()]).is_err());
    }

    #[test]
    fn segment_names_and_sizes() {
        assert_eq!(seg_name(1, 0x16_B374_D848, 16 << 20), "0000000100000016000000B3");
        assert_eq!(seg_name(2, 0x1_0000_0000, 1 << 30), "000000020000000100000000");
        assert_eq!(parse_size("16MB").unwrap(), 16 << 20);
        assert_eq!(parse_size("1GB").unwrap(), 1 << 30);
        assert!(parse_size("16 parsecs").is_err());
    }

    #[test]
    fn restore_dirs() {
        assert!(valid_dir("/var/lib/postgresql/17/restore"));
        for bad in ["/", "rel/dir", "/a/../etc", "/a b", "/a/'x'", "/a/./b"] {
            assert!(!valid_dir(bad), "{bad}");
        }
    }
}
