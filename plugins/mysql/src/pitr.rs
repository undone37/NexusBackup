//! Physical / point-in-time restore over SSH into a new directory on the SSH host:
//! the `base/` pieces into `mbstream -x` (MariaDB) / `xbstream -x` (XtraBackup),
//! `--prepare`, then (unless `base_only`) the binlog files rebuilt from their pieces
//! into `<dir>/.nexus-binlog/`, a temporary server on the directory (socket only,
//! `--skip-grant-tables`, no binlog) and `mysqlbinlog --start-position=<base
//! position> [--stop-datetime | --stop-position] … | mysql`, then a shutdown. The
//! result is a stopped data directory of the target time, owned by the SSH user.

use crate::physical::{piece_path, Piece, State, BINLOG_MAGIC};
use crate::ssh::{sh_quote, Ssh};
use anyhow::{bail, Context, Result};
use plugin_sdk::{error, Ctx, Source};
use std::io::{BufWriter, Write};

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `YYYY-MM-DD HH:MM:SS` (UTC) of unix seconds.
pub fn fmt_time(t: u64) -> String {
    let (days, s) = ((t / 86400) as i64, t % 86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

/// Unix seconds of `YYYY-MM-DD[ T]HH:MM[:SS[.ffffff]][ ][Z|±HH[[:]MM]]` (no zone = UTC).
pub fn parse_time(s: &str) -> Result<u64> {
    let s = s.trim();
    let bad = || error(22, format!("target_time {s:?}: expected YYYY-MM-DD HH:MM:SS[+00]"));
    let num = |a: usize, b: usize| s.get(a..b).and_then(|x| x.parse::<i64>().ok()).ok_or_else(bad);
    let (y, mo, d, h, mi) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?);
    if !matches!(s.as_bytes().get(10), Some(b' ' | b'T')) || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    let mut rest = &s[16..];
    let mut sec = 0;
    if let Some(r) = rest.strip_prefix(':') {
        sec = r.get(..2).and_then(|x| x.parse::<i64>().ok()).ok_or_else(bad)?;
        rest = &r[2..];
        if let Some(r) = rest.strip_prefix('.') {
            rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
        }
    }
    let rest = rest.trim_start();
    let off = match rest {
        "" | "Z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return Err(bad()),
            };
            let z = rest[1..].replace(':', "");
            let (hh, mm) = (z.get(..2), z.get(2..).filter(|m| !m.is_empty()).unwrap_or("00"));
            let hh: i64 = hh.and_then(|x| x.parse().ok()).ok_or_else(bad)?;
            let mm: i64 = mm.parse().map_err(|_| bad())?;
            sign * (hh * 3600 + mm * 60)
        }
    };
    let t = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec - off;
    u64::try_from(t).map_err(|_| bad())
}

/// `file:pos` of a binlog position.
pub fn parse_position(s: &str) -> Result<(String, u64)> {
    let bad = || error(22, format!("target_position {s:?}: expected <binlog file>:<position>"));
    let (f, p) = s.trim().rsplit_once(':').ok_or_else(bad)?;
    if f.is_empty() || !f.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
        return Err(bad());
    }
    Ok((f.to_owned(), p.parse().map_err(|_| bad())?))
}

/// The binlog files to replay: from the base file to the target file (all without one).
pub fn files_to_replay(st: &State, target_file: Option<&str>) -> Result<Vec<String>> {
    let mut files: Vec<String> = Vec::new();
    for p in &st.binlog {
        if files.last() != Some(&p.file) {
            files.push(p.file.clone());
        }
    }
    if files.first() != Some(&st.base_file) {
        bail!("the snapshot's binlog does not start with {}", st.base_file);
    }
    if let Some(t) = target_file {
        let i = files
            .iter()
            .position(|f| f == t)
            .ok_or_else(|| error(22, format!("target_position: binlog {t} is not in this snapshot ({})", files.join(", "))))?;
        files.truncate(i + 1);
    }
    Ok(files)
}

/// Checks that a file's pieces are contiguous from offset 4 (the magic).
pub fn check_pieces(file: &str, pieces: &[&Piece]) -> Result<()> {
    let mut at = BINLOG_MAGIC.len() as u64;
    for p in pieces {
        if p.start != at {
            bail!("binlog {file}: gap at {at} (next piece starts at {})", p.start);
        }
        at += p.len;
    }
    Ok(())
}

const DIR_PATTERN: &str = "[A-Za-z0-9._/-]";

pub fn pitr(ctx: &Ctx, src: &mut Source, ssh: &Ssh) -> Result<String> {
    let st: State = ctx
        .state
        .as_deref()
        .and_then(|s| serde_json::from_slice(s).ok())
        .context("this snapshot holds no server backup (restore a database snapshot with \"to_target\")")?;
    let p = &ctx.params["params"];
    let dir = p["directory"].as_str().unwrap_or_default().trim_end_matches('/').to_owned();
    if !dir.starts_with('/')
        || dir.len() < 2
        || dir.split('/').any(|c| c == "..")
        || !dir.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
    {
        return Err(error(22, format!("params.directory: an absolute path of {DIR_PATTERN}")));
    }
    let base_only = p["base_only"].as_bool().unwrap_or(false);
    let time = p["target_time"].as_str().filter(|s| !s.trim().is_empty()).map(parse_time).transpose()?;
    let pos = p["target_position"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(parse_position)
        .transpose()?;
    if time.is_some() && pos.is_some() {
        return Err(error(22, "give either target_time or target_position"));
    }
    if base_only && (time.is_some() || pos.is_some()) {
        return Err(error(22, "base_only restores the base backup only: no target"));
    }
    if let Some(t) = time {
        if t < st.base_time || t > st.to_time.max(st.base_time) {
            return Err(error(
                22,
                format!(
                    "target_time {} is outside the recoverable range {} – {} (UTC)",
                    fmt_time(t),
                    fmt_time(st.base_time),
                    fmt_time(st.to_time)
                ),
            ));
        }
    }
    let files = if base_only { Vec::new() } else { files_to_replay(&st, pos.as_ref().map(|p| p.0.as_str()))? };
    let q = sh_quote(&dir);
    let (extract, tool, server, client, binlog, admin) = if st.mariadb {
        ("mbstream -x", "$(command -v mariadb-backup || command -v mariabackup)", "mariadbd", "mariadb", "mariadb-binlog", "mariadb-admin")
    } else {
        ("xbstream -x", "xtrabackup", "mysqld", "mysql", "mysqlbinlog", "mysqladmin")
    };

    // 1. unpack the base backup into the new directory
    ctx.info(format!("unpacking the base backup into {dir}"));
    ssh.run(&format!("umask 077 && mkdir -p -- \"$(dirname -- {q})\" && mkdir -- {q}"))
        .map_err(|e| error(17, format!("directory {dir}: {e:#}")))?;
    let mut e = ssh.exec(&format!("cd -- {q} && exec {extract}"))?;
    {
        let mut w = BufWriter::with_capacity(1 << 20, &mut e);
        let mut n = 0u64;
        src.files(&[b"base".to_vec()], |item, data| {
            if item.meta.kind == Some(plugin_sdk::Kind::File) {
                n += std::io::copy(data, &mut w)?;
            }
            Ok(())
        })?;
        w.flush()?;
        ctx.info(format!("{n} bytes of backup stream sent"));
    }
    e.finish().context("unpacking the backup stream")?;
    ctx.info("preparing (applying the redo log)");
    ssh.run(&format!("t={tool} && \"$t\" --prepare --target-dir={q}"))
        .context("--prepare")?;
    if files.is_empty() {
        return Ok(format!(
            "base backup of {} prepared in {dir} (binlog position {}:{}); start a {} server of the same version on it",
            fmt_time(st.full_time),
            st.base_file,
            st.base_pos,
            if st.mariadb { "MariaDB" } else { "MySQL" }
        ));
    }

    // 2. the binlog files
    let bdir = format!("{dir}/.nexus-binlog");
    ssh.run(&format!("mkdir -m 700 -- {}", sh_quote(&bdir)))?;
    for f in &files {
        let pieces: Vec<&Piece> = st.binlog.iter().filter(|p| &p.file == f).collect();
        check_pieces(f, &pieces)?;
        let mut e = ssh.exec(&format!("cat > {}", sh_quote(&format!("{bdir}/{f}"))))?;
        e.write_all(BINLOG_MAGIC)?;
        let paths: Vec<Vec<u8>> = pieces.iter().map(|p| piece_path(p).into_bytes()).collect();
        src.files(&paths, |item, data| {
            if item.meta.kind == Some(plugin_sdk::Kind::File) {
                std::io::copy(data, &mut e)?;
            }
            Ok(())
        })?;
        e.finish().with_context(|| format!("writing binlog {f}"))?;
    }

    // 3. replay on a temporary server
    let sock = sh_quote(&format!("{dir}/.nexus-pitr.sock"));
    let mut opts = format!("--start-position={}", st.base_pos);
    let target = match (&time, &pos) {
        (Some(t), _) => {
            opts += &format!(" --stop-datetime={}", sh_quote(&fmt_time(*t)));
            format!("time {} UTC", fmt_time(*t))
        }
        (_, Some((f, p))) => {
            opts += &format!(" --stop-position={p}");
            format!("position {f}:{p}")
        }
        _ => format!("the end of the snapshot ({}:{})", st.next_file, st.next_pos),
    };
    if !st.mariadb {
        // the temporary server runs without GTID mode
        opts += " --skip-gtids";
    }
    let list: Vec<String> = files.iter().map(|f| sh_quote(&format!("{bdir}/{f}"))).collect();
    ctx.info(format!("replaying the binlog to {target}"));
    let script = format!(
        "cd -- {q} || exit 1\n\
         srv=$(command -v {server} || ls /usr/sbin/{server} /usr/libexec/{server} 2>/dev/null | head -1)\n\
         [ -n \"$srv\" ] || {{ echo '{server} not found' >&2; exit 127; }}\n\
         \"$srv\" --no-defaults --datadir={q} --socket={sock} --pid-file=.nexus-pitr.pid --log-error=.nexus-pitr.err \
           --skip-networking --skip-grant-tables --skip-log-bin --loose-mysqlx=0 --secure-file-priv={bq} \
           >.nexus-pitr.out 2>&1 </dev/null &\n\
         pid=$!\n\
         for i in $(seq 600); do {admin} --no-defaults --socket={sock} ping >/dev/null 2>&1 && break; \
           kill -0 $pid 2>/dev/null || {{ tail -20 .nexus-pitr.out .nexus-pitr.err >&2; exit 1; }}; sleep 1; done\n\
         set -o pipefail 2>/dev/null\n\
         TZ=UTC {binlog} --no-defaults {opts} {} | {client} --no-defaults --socket={sock} --binary-mode\n\
         rc=$?\n\
         {admin} --no-defaults --socket={sock} shutdown\n\
         while kill -0 $pid 2>/dev/null; do sleep 1; done\n\
         [ $rc = 0 ] || {{ tail -20 .nexus-pitr.err >&2; exit $rc; }}\n\
         rm -rf -- .nexus-binlog .nexus-pitr.err .nexus-pitr.out .nexus-pitr.pid\n",
        list.join(" "),
        bq = sh_quote(&bdir),
    );
    ssh.run(&format!("bash -c {}", sh_quote(&script))).context("binlog replay")?;
    Ok(format!(
        "{dir}: base backup of {} recovered to {target}; start a {} server of the same version on it",
        fmt_time(st.full_time),
        if st.mariadb { "MariaDB" } else { "MySQL" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(parse_time("1970-01-01 00:00:00").unwrap(), 0);
        assert_eq!(parse_time("2026-10-10 14:30:00+00").unwrap(), 1_791_642_600);
        assert_eq!(parse_time("2026-10-10T16:30:00+02:00").unwrap(), 1_791_642_600);
        assert_eq!(parse_time("2026-10-10 14:30:00.123Z").unwrap(), 1_791_642_600);
        assert_eq!(parse_time("2026-10-10 14:30").unwrap(), 1_791_642_600);
        assert!(parse_time("2026-13-10 14:30").is_err());
        assert!(parse_time("yesterday").is_err());
        assert_eq!(fmt_time(1_791_642_600), "2026-10-10 14:30:00");
        assert_eq!(fmt_time(951_782_400), "2000-02-29 00:00:00");
        for t in [0, 951_782_400, 1_791_642_659, 4_102_444_800] {
            assert_eq!(parse_time(&fmt_time(t)).unwrap(), t);
        }
    }

    #[test]
    fn positions_and_files() {
        assert_eq!(parse_position("mysql-bin.000004:1234").unwrap(), ("mysql-bin.000004".into(), 1234));
        assert!(parse_position("x;rm:1").is_err());
        assert!(parse_position("1234").is_err());
        let pc = |f: &str, start, len| Piece {
            file: f.into(),
            start,
            len,
            mtime: 0,
        };
        let st = State {
            v: 1,
            mariadb: false,
            server: String::new(),
            server_version: String::new(),
            full_time: 0,
            base_pieces: 1,
            base_last: 1,
            base_file: "b.1".into(),
            base_pos: 158,
            base_time: 0,
            binlog: vec![pc("b.1", 4, 100), pc("b.1", 104, 50), pc("b.2", 4, 10), pc("b.3", 4, 10)],
            next_file: "b.3".into(),
            next_pos: 14,
            to_time: 0,
        };
        assert_eq!(files_to_replay(&st, None).unwrap(), ["b.1", "b.2", "b.3"]);
        assert_eq!(files_to_replay(&st, Some("b.2")).unwrap(), ["b.1", "b.2"]);
        assert!(files_to_replay(&st, Some("b.9")).is_err());
        let b1: Vec<&Piece> = st.binlog.iter().filter(|p| p.file == "b.1").collect();
        check_pieces("b.1", &b1).unwrap();
        assert!(check_pieces("b.1", &b1[1..]).is_err());
    }
}
