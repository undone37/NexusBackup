//! Physical backup of the whole server (mariadb-backup / Percona XtraBackup over
//! SSH) plus the binary log pulled over the connection, for point-in-time restores.
//!
//! Snapshot layout (files, so incrementals can say `Unchanged`):
//! `base/<n>` the `--stream=xbstream` output of the backup tool, cut into pieces of
//! ≤ 32 MiB (a file's size must be known before it is sent; the restore
//! concatenates them); `binlog/<file>/<offset>` the binary log from the start of
//! the file that held the base backup's binlog position on, as byte ranges of the
//! server's files (`<offset>` = position of the first byte, 10 digits), so the
//! restore rebuilds the original files and `mysqlbinlog --start-position` works.
//!
//! The binlog is pulled like `mysqlbinlog --read-from-remote-server --raw` does:
//! COM_BINLOG_DUMP (non-blocking: the server stops at its current end) with the
//! checksum and MariaDB capability announced, so the events arrive as they are in
//! the files; every event is checked to continue the previous one. An incremental
//! run re-references `base/` and the earlier pieces and pulls from where the last
//! one stopped; a new base backup is taken every `full_every_days`, on another
//! server (failover: other server_uuid / server_id) and when the binlog the next
//! pull needs was purged (MySQL keeps no slot: `binlog_expire_logs_seconds` must
//! cover the backup interval).
//!
//! Recoverable range (snapshot metadata, as plugins/postgresql): the server time
//! right after the base backup (its binlog position) → the server time taken right
//! before the pull (everything committed before it was pulled).

use crate::my::{Conn, Opts};
use crate::ssh::{defaults_file, with_defaults, Ssh};
use anyhow::{bail, Context, Result};
use plugin_sdk::{Ctx, Kind, Meta, Sink};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// Size of the pieces of `base/` and `binlog/`.
pub const PIECE: usize = 32 << 20;

/// The first bytes of every binlog file.
pub const BINLOG_MAGIC: &[u8] = b"\xfebin";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Piece {
    pub file: String,
    pub start: u64,
    pub len: u64,
    pub mtime: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub v: u32,
    /// MariaDB (mariadb-backup, mbstream) or MySQL (xtrabackup, xbstream)
    pub mariadb: bool,
    /// server_uuid (MySQL) or server_id (MariaDB): another server = a new base backup
    pub server: String,
    pub server_version: String,
    /// time of the base backup (unix seconds) and its pieces (all of PIECE bytes but the last)
    pub full_time: u64,
    pub base_pieces: u64,
    pub base_last: u64,
    /// the base backup's binlog position and the first server time after it
    pub base_file: String,
    pub base_pos: u64,
    pub base_time: u64,
    /// binlog pieces in the snapshot, in order
    pub binlog: Vec<Piece>,
    /// where the next pull starts
    pub next_file: String,
    pub next_pos: u64,
    /// server time before the last pull
    pub to_time: u64,
}

/// State blobs are ≤ 1 MiB; a longer piece list makes the next backup full.
const MAX_STATE: usize = 1000 << 10;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn meta(kind: Kind, size: u64, mtime: u64) -> Meta {
    Meta {
        kind: Some(kind),
        mode: if kind == Kind::Dir { 0o700 } else { 0o600 },
        size,
        mtime_ns: mtime as i64 * 1_000_000_000,
        ..Default::default()
    }
}

pub fn base_path(i: u64) -> String {
    format!("base/{i:06}")
}

pub fn piece_path(p: &Piece) -> String {
    format!("binlog/{}/{:010}", p.file, p.start)
}

pub fn range(st: &State) -> serde_json::Value {
    let to = |f: &str, p: u64| format!("{f}:{p}");
    serde_json::json!({"recoverable": {
        "from_time": st.base_time, "from_lsn": to(&st.base_file, st.base_pos),
        "to_time": st.to_time.max(st.base_time), "to_lsn": to(&st.next_file, st.next_pos),
        "unit": "binlog",
    }})
}

/// `server_uuid` (MySQL) / `server_id` (MariaDB) and the server's time.
fn identity(c: &mut Conn) -> Result<(String, u64)> {
    let q = if c.mariadb {
        "SELECT CONCAT('id-', @@server_id), UNIX_TIMESTAMP()"
    } else {
        "SELECT @@server_uuid, UNIX_TIMESTAMP()"
    };
    let r = c.query(q)?;
    let r = r.first().context("no identity row")?;
    let get = |i: usize| r.get(i).cloned().flatten().unwrap_or_default();
    Ok((get(0), get(1).parse()?))
}

pub fn binlog_on(c: &mut Conn) -> Result<bool> {
    Ok(c.value("SELECT @@log_bin")?.as_deref() == Some("1"))
}

/// Binary log files the server still has.
pub fn binlogs(c: &mut Conn) -> Result<Vec<String>> {
    Ok(c.query("SHOW BINARY LOGS")?
        .into_iter()
        .filter_map(|r| r.into_iter().next().flatten())
        .collect())
}

pub struct Report {
    pub state: State,
    pub summary: String,
    pub meta: serde_json::Value,
}

/// Backup of the server: incremental on top of the previous snapshot if possible, else full.
pub fn backup(
    ctx: &Ctx,
    sink: &mut Sink,
    o: &Opts,
    ssh: impl FnOnce() -> Result<Ssh>,
    full_days: u64,
) -> Result<Report> {
    let mut c = Conn::connect(o)?;
    if !binlog_on(&mut c)? {
        bail!(
            "binary logging is off on {}: a server backup needs log_bin (logical dumps work without)",
            o.host
        );
    }
    let (server, _) = identity(&mut c)?;
    let prev: Option<State> = ctx
        .state
        .as_deref()
        .filter(|_| sink.has_base())
        .and_then(|s| serde_json::from_slice(s).ok());
    if let Some(p) = prev {
        if p.server != server {
            ctx.info(format!("another server ({} → {server}): full backup", p.server));
        } else if now().saturating_sub(p.full_time) >= full_days * 86400 {
            ctx.info(format!("base backup older than {full_days} days: full backup"));
        } else if !binlogs(&mut c)?.contains(&p.next_file) {
            ctx.warn(format!(
                "binlog {} was purged on the server before it was backed up: full backup (raise \
                 binlog_expire_logs_seconds above the backup interval)",
                p.next_file
            ));
        } else {
            return incremental(ctx, sink, &mut c, p);
        }
    }
    full(ctx, sink, &mut c, o, &ssh()?, server)
}

fn incremental(ctx: &Ctx, sink: &mut Sink, c: &mut Conn, mut st: State) -> Result<Report> {
    sink.entry(b"base", meta(Kind::Dir, 0, st.full_time))?;
    for i in 0..st.base_pieces {
        let len = if i + 1 == st.base_pieces {
            st.base_last
        } else {
            PIECE as u64
        };
        sink.unchanged(base_path(i).as_bytes(), meta(Kind::File, len, st.full_time))?;
    }
    sink.entry(b"binlog", meta(Kind::Dir, 0, st.full_time))?;
    let mut dir = String::new();
    for p in &st.binlog {
        if p.file != dir {
            dir = p.file.clone();
            sink.entry(format!("binlog/{dir}").as_bytes(), meta(Kind::Dir, 0, st.full_time))?;
        }
        sink.unchanged(piece_path(p).as_bytes(), meta(Kind::File, p.len, p.mtime))?;
    }
    let before = st.binlog.len();
    let bytes = pull_into(ctx, sink, c, &mut st, Some(dir))?;
    let state_len = serde_json::to_vec(&st)?.len();
    if state_len > MAX_STATE {
        ctx.warn("too many binlog pieces for the state: the next backup is a new base backup");
        st.full_time = 0;
    }
    Ok(Report {
        summary: format!(
            "incremental: binlog to {}:{} (+{} pieces, {bytes} bytes) on the base backup of {}",
            st.next_file,
            st.next_pos,
            st.binlog.len() - before,
            crate::pitr::fmt_time(st.full_time)
        ),
        meta: range(&st),
        state: st,
    })
}

/// Parses `… binlog position: filename 'mysql-bin.000002', position '342'` of the tool's stderr.
pub fn parse_position(stderr: &str) -> Option<(String, u64)> {
    let l = stderr
        .lines()
        .rev()
        .find(|l| l.contains("binlog position: filename '"))?;
    let rest = &l[l.find("filename '")? + 10..];
    let file = &rest[..rest.find('\'')?];
    let rest = &rest[rest.find("position '")? + 10..];
    let pos = rest[..rest.find('\'')?].parse().ok()?;
    Some((file.to_owned(), pos))
}

/// Cuts a reader into `base/<n>` pieces; (pieces, length of the last).
fn send_pieces(sink: &mut Sink, r: &mut impl Read, t0: u64) -> Result<(u64, u64, u64)> {
    let mut buf = vec![0u8; PIECE];
    let (mut n, mut last, mut total) = (0u64, 0u64, 0u64);
    loop {
        let mut len = 0;
        while len < PIECE {
            let k = r.read(&mut buf[len..])?;
            if k == 0 {
                break;
            }
            len += k;
        }
        if len == 0 && n > 0 {
            return Ok((n, last, total));
        }
        sink.file(
            base_path(n).as_bytes(),
            meta(Kind::File, len as u64, t0),
            &mut &buf[..len],
        )?;
        n += 1;
        last = len as u64;
        total += len as u64;
        if len < PIECE {
            return Ok((n, last, total));
        }
    }
}

fn full(ctx: &Ctx, sink: &mut Sink, c: &mut Conn, o: &Opts, ssh: &Ssh, server: String) -> Result<Report> {
    let (tool, label) = if c.mariadb {
        ("t=$(command -v mariadb-backup || command -v mariabackup) || { echo 'mariadb-backup not found' >&2; exit 127; }", "mariadb-backup")
    } else {
        (
            "t=$(command -v xtrabackup) || { echo 'xtrabackup (Percona XtraBackup) not found' >&2; exit 127; }",
            "xtrabackup",
        )
    };
    ctx.info(format!(
        "base backup of {} {} with {label} over SSH",
        if c.mariadb { "MariaDB" } else { "MySQL" },
        c.server_version
    ));
    let t0 = now();
    let cnf = defaults_file(&o.user, &o.password);
    let mut e = ssh.exec(&with_defaults(
        cnf.len(),
        &format!("{tool}; \"$t\" --defaults-extra-file=\"$f\" --backup --stream=xbstream --target-dir=\"$d\""),
    ))?;
    e.write_all(cnf.as_bytes())?;
    e.close_stdin()?;
    sink.entry(b"base", meta(Kind::Dir, 0, t0))?;
    let (pieces, last, bytes) = send_pieces(sink, &mut e, t0)?;
    let stderr = e.finish().with_context(|| format!("{label} failed"))?;
    let tail = || stderr.lines().rev().take(5).collect::<Vec<_>>().join(" / ");
    if !stderr.contains("completed OK!") {
        bail!("{label} did not report success: {}", tail());
    }
    let (base_file, base_pos) =
        parse_position(&stderr).with_context(|| format!("{label} reported no binlog position: {}", tail()))?;
    // a fresh connection: the old one idled through the whole backup (wait_timeout)
    let mut c = Conn::connect(o)?;
    let (_, base_time) = identity(&mut c)?;
    let mut st = State {
        v: 1,
        mariadb: c.mariadb,
        server,
        server_version: c.server_version.clone(),
        full_time: t0,
        base_pieces: pieces,
        base_last: last,
        base_file: base_file.clone(),
        base_pos,
        base_time: base_time + 1,
        binlog: Vec::new(),
        // the whole file of the base position: the restore needs its start (format description)
        next_file: base_file,
        next_pos: 4,
        to_time: 0,
    };
    sink.entry(b"binlog", meta(Kind::Dir, 0, t0))?;
    let logged = pull_into(ctx, sink, &mut c, &mut st, None)?;
    Ok(Report {
        summary: format!(
            "full: base backup ({label}, {bytes} bytes, binlog position {}:{}) + binlog to {}:{} ({logged} bytes)",
            st.base_file, st.base_pos, st.next_file, st.next_pos
        ),
        meta: range(&st),
        state: st,
    })
}

/// Pulls the binlog from `st.next_*` into new pieces; `dir`: the last `binlog/<file>` entry sent.
fn pull_into(ctx: &Ctx, sink: &mut Sink, c: &mut Conn, st: &mut State, mut dir: Option<String>) -> Result<u64> {
    let (_, t) = identity(c)?;
    let t0 = now();
    let mut bytes = 0u64;
    let mut new = Vec::new();
    let end = pull(c, &st.next_file, st.next_pos, |file, start, data| {
        if dir.as_deref() != Some(file) {
            sink.entry(format!("binlog/{file}").as_bytes(), meta(Kind::Dir, 0, t0))?;
            dir = Some(file.to_owned());
        }
        let p = Piece {
            file: file.to_owned(),
            start,
            len: data.len() as u64,
            mtime: t0,
        };
        sink.file(piece_path(&p).as_bytes(), meta(Kind::File, p.len, t0), &mut &data[..])?;
        bytes += p.len;
        new.push(p);
        Ok(())
    })?;
    if !new.is_empty() {
        ctx.info(format!("binlog {}:{} → {}:{}", st.next_file, st.next_pos, end.0, end.1));
    }
    st.binlog.extend(new);
    (st.next_file, st.next_pos) = end;
    st.to_time = t;
    Ok(bytes)
}

// binlog event header: timestamp(4) type(1) server_id(4) event_size(4) log_pos(4) flags(2)
const ROTATE: u8 = 4;
const FORMAT_DESCRIPTION: u8 = 15;
const HEARTBEAT: u8 = 27;
const HEARTBEAT_V2: u8 = 41;
const ARTIFICIAL: u16 = 0x20;

fn le32(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as u64
}

/// COM_BINLOG_DUMP from (file, pos) to the server's current end. `emit(file, start,
/// bytes)` gets contiguous byte ranges of the server's binlog files (≤ PIECE each,
/// never across files). Returns where the next pull starts.
pub fn pull(
    c: &mut Conn,
    file: &str,
    pos: u64,
    mut emit: impl FnMut(&str, u64, Vec<u8>) -> Result<()>,
) -> Result<(String, u64)> {
    let crc = c.value("SELECT @@global.binlog_checksum")?.unwrap_or_default();
    let crc = if crc.eq_ignore_ascii_case("NONE") { 0 } else { 4 };
    c.exec("SET @master_binlog_checksum = @@global.binlog_checksum")?;
    c.exec("SET @source_binlog_checksum = @@global.binlog_checksum")?;
    // MariaDB: send its own events (GTID, annotate …) as they are, not replaced by dummies
    c.exec("SET @mariadb_slave_capability = 4")?;
    let mut body = (pos as u32).to_le_bytes().to_vec();
    // BINLOG_DUMP_NON_BLOCK; MariaDB: BINLOG_SEND_ANNOTATE_ROWS_EVENT (else they are left out)
    let flags: u16 = if c.mariadb { 1 | 2 } else { 1 };
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // server_id 0: a client, not a replica
    body.extend_from_slice(file.as_bytes());
    c.command(0x12, &body)?;
    let (mut cur, mut off) = (file.to_owned(), pos);
    let (mut buf, mut start): (Vec<u8>, u64) = (Vec::new(), pos);
    loop {
        let b = c.recv()?;
        match b.first() {
            Some(0xfe) if b.len() < 9 => break,
            Some(0xff) => return Err(crate::my::err_packet(&b).into()),
            Some(0) => {}
            x => bail!("binlog dump: unexpected packet {x:?}"),
        }
        let ev = &b[1..];
        if ev.len() < 19 {
            bail!("binlog dump: short event");
        }
        let (ty, size, log_pos) = (ev[4], le32(ev, 9), le32(ev, 13));
        let flags = u16::from_le_bytes([ev[17], ev[18]]);
        if size as usize != ev.len() {
            bail!("binlog dump: event size {size} != {}", ev.len());
        }
        if ty == ROTATE && (log_pos == 0 || flags & ARTIFICIAL != 0) {
            // which file the following events belong to
            let name = ev.get(27..ev.len().saturating_sub(crc)).context("rotate event")?;
            let name = String::from_utf8_lossy(name).into_owned();
            let p = u64::from_le_bytes(ev[19..27].try_into()?);
            if name != cur || p != off {
                if !buf.is_empty() {
                    emit(&cur, start, std::mem::take(&mut buf))?;
                }
                (cur, off, start) = (name, p, p);
            }
            continue;
        }
        // not in the file: heartbeats, artificial events, the format description resent for a pull from inside a file
        if flags & ARTIFICIAL != 0 || ty == HEARTBEAT || ty == HEARTBEAT_V2 || (ty == FORMAT_DESCRIPTION && off != 4) {
            continue;
        }
        // MariaDB 11 writes end position 0 into the events inside a transaction: checked by the next one with a position
        if log_pos != 0 && (log_pos < size || log_pos - size != off) {
            bail!(
                "binlog dump: event at {cur}:{} does not continue {cur}:{off}",
                log_pos.saturating_sub(size)
            );
        }
        buf.extend_from_slice(ev);
        off += size;
        if buf.len() >= PIECE {
            emit(&cur, start, std::mem::take(&mut buf))?;
            start = off;
        }
    }
    if !buf.is_empty() {
        emit(&cur, start, buf)?;
    }
    Ok((cur, off))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_position() {
        let mariadb = "[00] 2026-10-13 06:37:29 Streaming mariadb_backup_binlog_info\n\
                       [00] 2026-10-13 06:37:29 MySQL binlog position: filename 'mysql-bin.000002', position '342', GTID of the last change '0-1-2'\n\
                       [00] 2026-10-13 06:37:29 completed OK!";
        assert_eq!(parse_position(mariadb), Some(("mysql-bin.000002".into(), 342)));
        let pxb = "2026-10-13T06:37:31.462592-00:00 0 [Note] [MY-011825] [Xtrabackup] MySQL binlog position: \
                   filename 'binlog.000004', position '158'";
        assert_eq!(parse_position(pxb), Some(("binlog.000004".into(), 158)));
        assert_eq!(parse_position("nothing"), None);
    }

    #[test]
    fn paths_and_range() {
        let p = Piece {
            file: "mysql-bin.000003".into(),
            start: 4,
            len: 10,
            mtime: 1,
        };
        assert_eq!(piece_path(&p), "binlog/mysql-bin.000003/0000000004");
        assert_eq!(base_path(7), "base/000007");
        let st = State {
            v: 1,
            mariadb: true,
            server: "id-1".into(),
            server_version: "11.8".into(),
            full_time: 100,
            base_pieces: 1,
            base_last: 5,
            base_file: "b.1".into(),
            base_pos: 342,
            base_time: 101,
            binlog: vec![p],
            next_file: "b.2".into(),
            next_pos: 99,
            to_time: 90,
        };
        let r = range(&st);
        assert_eq!(r["recoverable"]["from_lsn"], "b.1:342");
        assert_eq!(r["recoverable"]["to_lsn"], "b.2:99");
        assert_eq!(r["recoverable"]["to_time"], 101);
    }
}
