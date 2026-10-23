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
//! `settings.conf` holds the source's values of the settings that a recovering
//! server needs at least as high as the primary ([`RECOVERY_MINIMUMS`]), for the
//! point-in-time restore (sent again by every run: they may change).
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
    /// the complete files of `wal/` (segments and timeline history files) once a run
    /// followed a timeline switch (names carry several timelines then); None: derived
    /// from `wal_from..next` on `tli` (states before plugin 1.3.1)
    #[serde(default)]
    pub wal_files: Option<Vec<String>>,
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
/// Settings PostgreSQL requires on a recovering server to be at least the primary's
/// (it aborts recovery otherwise: "insufficient parameter settings"); a restore into a
/// fresh configuration would get the defaults (lab 2026-10-23: Patroni's 1000 connections).
pub const RECOVERY_MINIMUMS: [&str; 5] = [
    "max_connections",
    "max_worker_processes",
    "max_wal_senders",
    "max_prepared_transactions",
    "max_locks_per_transaction",
];
/// Top-level snapshot file with the [`RECOVERY_MINIMUMS`] of the source.
pub const SETTINGS_FILE: &str = "settings.conf";

/// The source's [`RECOVERY_MINIMUMS`] as `postgresql.conf` lines (`SHOW` works on a
/// replication connection, but not once it streams).
fn recovery_minimums(c: &mut Conn) -> Result<String> {
    let mut s = String::from("# NexusBackup: settings of the source that recovery needs at least\n");
    for n in RECOVERY_MINIMUMS {
        if let Some(v) = c.value(&format!("SHOW {n}"))? {
            s += &format!("{n} = {v}\n");
        }
    }
    Ok(s)
}

fn send_settings(sink: &mut Sink, s: &str, t0: u64) -> Result<()> {
    sink.file(
        SETTINGS_FILE.as_bytes(),
        meta(Kind::File, 0o600, s.len() as u64, t0),
        &mut s.as_bytes(),
    )
}

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
    let settings = recovery_minimums(&mut c)?;
    // a fresh slot: it holds the WAL from before the base backup on
    match c.exec(&format!("DROP_REPLICATION_SLOT {slot}")) {
        Err(e) if crate::pg::sqlstate(&e) == Some("42704") => {}
        r => r.context("dropping the old replication slot")?,
    }
    match c.exec(&format!("CREATE_REPLICATION_SLOT {slot} PHYSICAL RESERVE_WAL")) {
        // Patroni keeps a permanent slot of this name and may have re-created it after the
        // drop: it reserves WAL from now on as well (the base backup carries its own WAL)
        Err(e) if crate::pg::sqlstate(&e) == Some("42710") => {
            ctx.info(format!(
                "slot {slot} re-created by the cluster manager (Patroni permanent slot): kept"
            ));
        }
        r => r.context("creating the replication slot")?,
    }
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
    send_settings(sink, &settings, t0)?;
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
        wal_files: Some(Vec::new()),
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
    if system != p.system {
        ctx.info(format!("another cluster ({} → {system}): full backup", p.system));
        return Ok(None);
    }
    // what to stream: (timeline, from, to); after a switchover or failover the old
    // timeline up to its switch point first, then each newer one (`follow`)
    let (steps, history) = match follow(&mut c, p, slot, tli, target) {
        Ok(s) => s,
        Err(why) => {
            ctx.info(format!("timeline {} → {tli}: {why}: full backup", p.tli));
            return Ok(None);
        }
    };
    if tli != p.tli {
        ctx.info(format!(
            "timeline {} → {tli}: following the switch ({}), no new base backup",
            p.tli,
            steps
                .iter()
                .map(|(t, f, e)| format!("tl {t} {}..{}", fmt_lsn(*f), fmt_lsn(*e)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let data = decode_paths(&p.files)?;
    let old_wal: Vec<String> = match &p.wal_files {
        Some(w) => w.clone(),
        None => (p.wal_from / p.seg..p.next / p.seg)
            .map(|s| format!("wal/{}", seg_name(p.tli, s * p.seg, p.seg)))
            .collect(),
    };
    let paths: Vec<Vec<u8>> = data.iter().chain(&old_wal).map(|s| s.as_bytes().to_vec()).collect();
    let base: HashMap<Vec<u8>, Meta> = sink.base(&paths)?.into_iter().map(|e| (e.path, e.meta)).collect();
    if paths.iter().any(|p| !base.contains_key(p)) {
        ctx.info("previous snapshot incomplete: full backup");
        return Ok(None);
    }
    let settings = recovery_minimums(&mut c)?;
    // start streaming before sending anything: if the slot lost the WAL, a full backup follows
    let streaming = target > p.next;
    if streaming {
        if let Err(e) = start_stream(&mut c, slot, steps[0].0, steps[0].1)? {
            ctx.warn(format!("WAL streaming refused ({e}): full backup"));
            return Ok(None);
        }
    }
    let t0 = now();
    send_settings(sink, &settings, t0)?;
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
    let next = target - target % p.seg;
    let mut wal_files = old_wal.clone();
    for (name, text) in &history {
        sink.file(
            format!("wal/{name}").as_bytes(),
            meta(Kind::File, 0o600, text.len() as u64, t0),
            &mut text.as_slice(),
        )?;
        wal_files.push(format!("wal/{name}"));
    }
    if streaming {
        for (i, &(st_tli, from, to)) in steps.iter().enumerate() {
            if i > 0 {
                if let Err(e) = start_stream(&mut c, slot, st_tli, from)? {
                    bail!("WAL streaming on timeline {st_tli} refused: {e}");
                }
            }
            let mut w = Wal {
                c: &mut c,
                pos: from,
                target: to,
                buf: Vec::new(),
                off: 0,
                flush: p.next,
                status_at: Instant::now(),
            };
            // the slot may now drop everything before the previous snapshot's end
            w.status()?;
            let mut lsn = from;
            while lsn < to {
                let name = seg_name(st_tli, lsn, p.seg);
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
                // complete: every segment of an older timeline, on the last one all
                // but the partial segment (streamed again next time)
                if i + 1 < steps.len() || lsn + p.seg <= next {
                    wal_files.push(format!("wal/{name}"));
                }
                lsn += p.seg;
                ctx.progress(lsn - p.next, target - p.next, format!("WAL {name}"));
            }
            if i + 1 < steps.len() {
                end_stream(&mut c)?;
            }
        }
        let _ = c.send(b'c', &[]);
    }
    c.close();
    let st = State {
        next: next.max(p.next),
        tli,
        wal_files: Some(wal_files),
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

/// Parses a timeline history file: `(parent timeline, switch point)` per line.
pub fn parse_history(text: &str) -> Result<Vec<(u32, u64)>> {
    let mut out = Vec::new();
    for l in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let mut f = l.split_whitespace();
        let (Some(t), Some(lsn)) = (f.next(), f.next()) else {
            bail!("timeline history: bad line {l:?}");
        };
        out.push((t.parse()?, crate::pg::parse_lsn(lsn)?));
    }
    Ok(out)
}

/// The streaming plan from the previous state's position to `target` on timeline `tli`:
/// `(timeline, from, to)` steps (one when the timeline is the same) and the history
/// files of the newer timelines. Err = the WAL cannot be followed (another branch, or
/// the switch lies before what the last backup streamed).
pub fn plan_steps(
    p: &State,
    tli: u32,
    target: u64,
    hist: &[(u32, u64)],
) -> std::result::Result<Vec<(u32, u64, u64)>, String> {
    if tli == p.tli {
        return Ok(vec![(tli, p.next, target)]);
    }
    if tli < p.tli {
        return Err("the server is on an older timeline".into());
    }
    let chain: Vec<(u32, u64)> = hist.iter().copied().filter(|(t, _)| *t >= p.tli).collect();
    match chain.first() {
        Some((t, sw)) if *t == p.tli && *sw >= p.next => {}
        Some((t, _)) if *t == p.tli => return Err("the switch lies before the last backup's end".into()),
        _ => return Err(format!("timeline {} is not an ancestor of {tli}", p.tli)),
    }
    let mut steps = Vec::new();
    let mut from = p.next;
    for &(t, sw) in &chain {
        steps.push((t, from, sw));
        from = sw - sw % p.seg;
    }
    steps.push((tli, from, target));
    Ok(steps)
}

/// History files `(name, content)` of the newer timelines.
type History = Vec<(String, Vec<u8>)>;
/// `(timeline, from, to)` streaming steps.
type Steps = Vec<(u32, u64, u64)>;

/// Plan (`plan_steps`) plus the history files, read from the server; on PostgreSQL 15+
/// also checks that the slot still holds the WAL from the last backup's end.
fn follow(c: &mut Conn, p: &State, slot: &str, tli: u32, target: u64) -> std::result::Result<(Steps, History), String> {
    let mut history = Vec::new();
    let mut hist = Vec::new();
    if tli > p.tli {
        {
            let r = c.query(&format!("TIMELINE_HISTORY {tli}")).map_err(|e| e.to_string())?;
            let row = r.first().ok_or("TIMELINE_HISTORY: no row")?;
            let name = row.first().cloned().flatten().unwrap_or_default();
            let text = row.get(1).cloned().flatten().unwrap_or_default();
            hist = parse_history(&text).map_err(|e| e.to_string())?;
            // every newer timeline's own history file: recovery may look for each
            for (t, _) in hist.iter().filter(|(t, _)| *t > p.tli) {
                let r = c.query(&format!("TIMELINE_HISTORY {t}")).map_err(|e| e.to_string())?;
                if let Some(row) = r.first() {
                    let n = row.first().cloned().flatten().unwrap_or_default();
                    history.push((n, row.get(1).cloned().flatten().unwrap_or_default().into_bytes()));
                }
            }
            history.push((name, text.into_bytes()));
        }
    }
    let steps = plan_steps(p, tli, target, &hist)?;
    if tli != p.tli && c.major >= 15 {
        // a slot that no longer holds the last backup's end would refuse every run: check first
        let r = c
            .query(&format!("READ_REPLICATION_SLOT {slot}"))
            .map_err(|e| e.to_string())?;
        let restart = r.first().and_then(|row| row.get(1).cloned().flatten());
        match restart {
            None => {
                return Err(format!(
                    "no slot {slot} on the new primary (Patroni: a permanent slot, see the README)"
                ))
            }
            Some(l) if !slot_reaches(crate::pg::parse_lsn(&l).map_err(|e| e.to_string())?, p.next, p.seg) => {
                return Err(format!("slot {slot} starts at {l}, after the last backup's end"))
            }
            Some(_) => {}
        }
    }
    Ok((steps, history))
}

/// Whether a slot at `restart` still serves streaming from `next` (segment-aligned): the
/// server keeps WAL by whole segments, and a cluster manager advances a standby's slot
/// to a position inside a segment (lab 2026-10-23: Patroni at 0/12011E88, next 0/12000000).
pub fn slot_reaches(restart: u64, next: u64, seg: u64) -> bool {
    restart - restart % seg <= next
}

/// START_REPLICATION and wait for the copy to begin; Ok(Err) = refused by the server.
fn start_stream(c: &mut Conn, slot: &str, tli: u32, from: u64) -> Result<std::result::Result<(), String>> {
    c.query_start(&format!(
        "START_REPLICATION SLOT {slot} PHYSICAL {} TIMELINE {tli}",
        fmt_lsn(from)
    ))?;
    loop {
        let (t, b) = c.recv()?;
        match t {
            b'W' => return Ok(Ok(())),
            b'E' => {
                // the error ends the command: wait for ReadyForQuery
                let e = error(&b);
                while c.recv()?.0 != b'Z' {}
                return Ok(Err(e.to_string()));
            }
            _ => {}
        }
    }
}

/// End of an old timeline's stream: the server sent everything up to the switch point;
/// both sides end the copy, the server answers with the next timeline and ReadyForQuery.
fn end_stream(c: &mut Conn) -> Result<()> {
    c.send(b'c', &[])?;
    loop {
        match c.recv()? {
            (b'Z', _) => return Ok(()),
            (b'E', b) => bail!("ending the WAL stream: {}", error(&b)),
            _ => {}
        }
    }
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

    fn state(tli: u32, next: u64) -> State {
        State {
            v: 1,
            system: "7".into(),
            tli,
            seg: 16 << 20,
            full_time: 0,
            wal_from: 0,
            next,
            files: vec![],
            base_end: 0,
            base_time: 0,
            wal_files: Some(vec![]),
        }
    }

    #[test]
    fn timeline_switches_are_followed() {
        // history of timeline 5 as a Patroni cluster writes it: 3 -> 4 at 0/F0000A0, 4 -> 5 at 0/12000060
        let h = parse_history(
            "3\t0/F0000A0\tno recovery target specified\n\n4\t0/12000060\tno recovery target specified\n",
        )
        .unwrap();
        assert_eq!(h, [(3, 0xF00_00A0), (4, 0x1200_0060)]);
        let seg = 16u64 << 20;
        // same timeline: one step
        assert_eq!(
            plan_steps(&state(5, 0x1300_0000), 5, 0x1350_0000, &[]).unwrap(),
            [(5, 0x1300_0000, 0x1350_0000)]
        );
        // two switches since the last backup (at 0/E000000 on timeline 3)
        let s = plan_steps(&state(3, 0xE00_0000), 5, 0x1350_0000, &h).unwrap();
        assert_eq!(
            s,
            [
                (3, 0xE00_0000, 0xF00_00A0),
                (4, 0xF00_00A0 - 0xF00_00A0 % seg, 0x1200_0060),
                (5, 0x1200_0000, 0x1350_0000)
            ]
        );
        // the last backup streamed past the switch on the old timeline: its WAL there is not on the new branch
        assert!(plan_steps(&state(3, 0x1000_0000), 5, 0x1350_0000, &h).is_err());
        // another branch, or back to an older timeline
        assert!(plan_steps(&state(2, 0xE00_0000), 5, 0x1350_0000, &h).is_err());
        assert!(plan_steps(&state(6, 0xE00_0000), 5, 0x1350_0000, &h).is_err());
        assert!(parse_history("3 nonsense").is_err());
        // a slot inside the segment the next run starts with still reaches it; one segment later not
        assert!(slot_reaches(0x1201_1E88, 0x1200_0000, seg));
        assert!(slot_reaches(0x1100_0000, 0x1200_0000, seg));
        assert!(!slot_reaches(0x1300_0010, 0x1200_0000, seg));
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
