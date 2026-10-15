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
//!
//! Frequent runs (`every 15m`) are cheap: an unchanged base sends no data file,
//! only the WAL since the previous run (the partial last segment again). Each run
//! first commits a tiny transaction (`pg_current_xact_id()`) on a normal
//! connection: its commit record carries a timestamp, so every time up to the
//! snapshot's is reachable by `recovery_target_time` even on an idle server, and
//! the snapshot's recoverable range (base backup end → that commit) goes into the
//! snapshot metadata (`SnapshotMeta`, shown in the restore dialog).

use crate::pg::{be64, data_row, error, fmt_lsn, Conn, Opts, Row};
use anyhow::{bail, Context, Result};
use plugin_sdk::{Ctx, Kind, Meta, Sink};
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
    /// end LSN of the base backup and the first server time after it (unix seconds;
    /// 0 in states before plugin 1.2.0): the start of the recoverable range
    #[serde(default)]
    pub base_end: u64,
    #[serde(default)]
    pub base_time: u64,
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
    /// snapshot metadata: `{"recoverable": {from_time, from_lsn, to_time, to_lsn, timeline}}`
    pub meta: serde_json::Value,
}

/// Commits a transaction with an xid (a commit record with a timestamp, see the
/// module doc), waits until it is flushed (it wrote no other WAL, so the commit is
/// asynchronous: the WAL writer flushes it within `wal_writer_delay`) and returns
/// its server time (unix seconds, fractional). Falls back to the server's time
/// without a commit (a standby) and to the appliance's clock (no SQL access).
fn marker(ctx: &Ctx, sql: &Opts) -> f64 {
    let r = Conn::connect(sql).and_then(|mut c| {
        let v = c
            .value(
                "SELECT extract(epoch FROM now())::text || CASE WHEN pg_is_in_recovery() THEN '' \
                 ELSE ' ' || pg_current_xact_id()::text END",
            )?
            .context("no value")?;
        let (t, xid) = v.split_once(' ').unwrap_or((&v, ""));
        let t: f64 = t.parse()?;
        if !xid.is_empty() {
            let lsn = c.value("SELECT pg_current_wal_insert_lsn()")?.context("no LSN")?;
            let q = format!("SELECT pg_current_wal_flush_lsn() >= {}::pg_lsn", crate::pg::lit(&lsn));
            let t0 = Instant::now();
            while c.value(&q)?.as_deref() != Some("t") && t0.elapsed().as_secs() < 30 {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        c.close();
        Ok(t)
    });
    r.unwrap_or_else(|e| {
        ctx.warn(format!(
            "no SQL connection for the recovery marker ({e:#}): the recoverable range uses the appliance clock"
        ));
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64())
    })
}

pub fn range(st: &State, to_time: u64, to_lsn: u64) -> serde_json::Value {
    let from_lsn = if st.base_end > 0 { st.base_end } else { st.wal_from };
    let from_time = if st.base_time > 0 { st.base_time } else { st.full_time };
    serde_json::json!({"recoverable": {
        "from_time": from_time, "from_lsn": fmt_lsn(from_lsn),
        "to_time": to_time.max(from_time), "to_lsn": fmt_lsn(to_lsn.max(from_lsn)), "timeline": st.tli,
    }})
}

/// Backup of the cluster: incremental on top of `prev` if possible, else full.
/// `o`: the replication connection, `sql`: a normal one (database `postgres`).
pub fn backup(ctx: &Ctx, sink: &mut Sink, o: &Opts, sql: &Opts, slot: &str, full_days: u64) -> Result<Report> {
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
        } else if let Some(r) = incremental(ctx, sink, o, sql, slot, &p)? {
            return Ok(r);
        }
    }
    full(ctx, sink, o, sql, slot)
}

fn full(ctx: &Ctx, sink: &mut Sink, o: &Opts, sql: &Opts, slot: &str) -> Result<Report> {
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
    // the first full second after the backup ended (recovery targets before it are refused)
    let base_time = marker(ctx, sql).ceil() as u64;
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
        base_end: end,
        base_time,
    };
    // this snapshot holds the WAL up to the end of the backup only
    let meta = range(&st, base_time, end);
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
        meta,
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
                m.link_target = e.link_name_bytes().map(std::borrow::Cow::into_owned);
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
fn incremental(ctx: &Ctx, sink: &mut Sink, o: &Opts, sql: &Opts, slot: &str, p: &State) -> Result<Option<Report>> {
    // the marker commit lies before the flush position IDENTIFY_SYSTEM reports
    let to_time = marker(ctx, sql).floor() as u64;
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
    let meta = range(&st, to_time, target);
    Ok(Some(Report {
        meta,
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
        .map(std::string::ToString::to_string)
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
}
