//! The backup chain of one database: which backup a run takes, which files a snapshot keeps, the recoverable range,
//! and which files a restore applies in which order. No I/O here.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Full,
    Diff,
    Log,
}

impl Kind {
    pub fn tag(self) -> &'static str {
        match self {
            Kind::Full => "full",
            Kind::Diff => "diff",
            Kind::Log => "log",
        }
    }
    pub fn ext(self) -> &'static str {
        match self {
            Kind::Log => "trn",
            _ => "bak",
        }
    }
}

/// One backup file of the snapshot with what `msdb.dbo.backupset` said about it. LSNs are decimal numerals
/// (numeric(25,0)): compared as numbers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Piece {
    pub name: String,
    pub kind: Kind,
    pub len: u64,
    pub mtime: u64,
    pub first_lsn: u128,
    pub last_lsn: u128,
    pub checkpoint_lsn: u128,
    /// differential: the checkpoint LSN of the full it is based on
    pub diff_base: u128,
    /// UTC unix seconds
    pub started: u64,
    pub finished: u64,
    /// full backups: the database files (`msdb.dbo.backupfile`), for MOVE on a restore under another name
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<DbFile>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DbFile {
    /// logical name, physical name, type (D data, L log, F full-text, S filestream)
    pub l: String,
    pub p: String,
    pub t: String,
}

fn lsn(v: &Value, k: &str) -> Result<u128> {
    match &v[k] {
        Value::Null => Ok(0),
        Value::String(s) => s.trim().parse().with_context(|| format!("{k}: {s:?}")),
        Value::Number(n) => n.to_string().parse().with_context(|| format!("{k}: {n}")),
        x => bail!("{k}: {x}"),
    }
}

impl Piece {
    /// From the backupset row (`first_lsn`, `last_lsn`, `checkpoint_lsn`, `differential_base_lsn`, `started`,
    /// `finished`, `size`).
    pub fn from_backupset(name: String, kind: Kind, r: &Value) -> Result<Piece> {
        Ok(Piece {
            name,
            kind,
            len: r["size"].as_u64().context("backup file size")?,
            mtime: r["finished"].as_u64().unwrap_or_default(),
            first_lsn: lsn(r, "first_lsn")?,
            last_lsn: lsn(r, "last_lsn")?,
            checkpoint_lsn: lsn(r, "checkpoint_lsn")?,
            diff_base: lsn(r, "differential_base_lsn")?,
            started: r["started"].as_u64().unwrap_or_default(),
            finished: r["finished"].as_u64().unwrap_or_default(),
            files: if kind == Kind::Full {
                serde_json::from_value(r["files"].clone()).unwrap_or_default()
            } else {
                Vec::new()
            },
        })
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    /// sys.database_recovery_status.database_guid: changes when the database is recreated or restored over
    pub guid: String,
    /// time of the run with the full
    pub base_time: u64,
    /// end of the recoverable range: the moment right before the last log backup started
    pub to_time: u64,
    pub pieces: Vec<Piece>,
}

impl State {
    /// The state for a run on top of this one (same full).
    pub fn keep(&self) -> State {
        State {
            guid: self.guid.clone(),
            base_time: self.base_time,
            to_time: self.to_time,
            pieces: self.pieces.clone(),
        }
    }

    pub fn absorb(&mut self, new: &[Piece], model: &str) {
        self.pieces.extend(new.iter().cloned());
        if model == "SIMPLE" {
            // no log: the range is the newest full or differential
            self.to_time = self.newest_base().map_or(0, |p| p.finished);
        }
    }

    fn full(&self) -> Option<&Piece> {
        self.pieces.iter().find(|p| p.kind == Kind::Full)
    }

    fn newest_base(&self) -> Option<&Piece> {
        self.pieces.iter().rev().find(|p| p.kind != Kind::Log)
    }

    /// The last LSN the chain has (the newest log backup, else the newest full/differential).
    pub fn last_lsn(&self) -> u128 {
        self.pieces.last().map_or(0, |p| p.last_lsn)
    }

    /// `{from_time, from_lsn, to_time, to_lsn, unit}` for the snapshot meta.
    pub fn range(&self) -> Value {
        let from = self.full().map_or(0, |p| p.finished);
        let from_lsn = self.full().map_or(0, |p| p.last_lsn);
        json!({"from_time": from, "from_lsn": from_lsn.to_string(),
            "to_time": self.to_time.max(from), "to_lsn": self.last_lsn().max(from_lsn).to_string(), "unit": "lsn"})
    }
}

/// What the database looks like before the run.
pub struct DbState {
    pub model: String,
    pub guid: String,
    /// sys.database_recovery_status.last_log_backup_lsn (NULL: no log backup since the log chain started or broke)
    pub last_log: Option<String>,
    /// sys.master_files.differential_base_lsn of the primary file: the full a differential would be based on
    pub diff_base: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Decision {
    Full,
    Diff,
    Log,
    /// a log run of a database in the SIMPLE model: nothing to back up, the snapshot re-references the previous one
    Nothing,
}

impl Decision {
    pub fn what(self) -> &'static str {
        match self {
            Decision::Full => "full backup",
            Decision::Diff => "differential backup",
            Decision::Log => "log backup",
            Decision::Nothing => "nothing new (SIMPLE recovery model: no log backups)",
        }
    }
}

pub struct Decided {
    pub decision: Decision,
    pub chain_break: Option<String>,
    pub why: String,
}

fn num(s: &Option<String>) -> Option<u128> {
    s.as_deref().and_then(|s| s.trim().parse().ok())
}

pub fn decide(prev: Option<&State>, db: &DbState, log_run: bool, full_days: u64, now: u64) -> Decided {
    let d = |decision, brk: Option<String>, why: String| Decided {
        decision,
        chain_break: brk,
        why,
    };
    let Some(p) = prev.filter(|p| p.full().is_some()) else {
        return d(Decision::Full, None, "first backup: full".into());
    };
    if p.guid != db.guid {
        return d(
            Decision::Full,
            None,
            "the database was recreated or restored over (new database GUID): full".into(),
        );
    }
    let has_log = p.pieces.iter().any(|x| x.kind == Kind::Log);
    if db.model != "SIMPLE" && has_log {
        // our log backups own the chain: SQL Server's last log backup must be ours
        match num(&db.last_log) {
            Some(l) if l == p.last_lsn() => {}
            Some(_) => {
                let why = "another log backup was taken outside NexusBackup (another tool or a native job)";
                return d(Decision::Full, Some(why.into()), format!("{why}: full"));
            }
            None => {
                let why = "the log chain was broken (recovery model switched to SIMPLE and back, or the log rebuilt)";
                return d(Decision::Full, Some(why.into()), format!("{why}: full"));
            }
        }
    }
    if log_run {
        return if db.model == "SIMPLE" {
            d(Decision::Nothing, None, Decision::Nothing.what().into())
        } else {
            d(Decision::Log, None, "log backup".into())
        };
    }
    if now.saturating_sub(p.base_time) >= full_days * 86400 {
        return d(
            Decision::Full,
            None,
            format!("full backup older than {full_days} days: full"),
        );
    }
    let full = p.full().map_or(0, |f| f.checkpoint_lsn);
    if num(&db.diff_base) != Some(full) {
        return d(
            Decision::Full,
            None,
            "another full backup moved the differential base (take other tools' fulls WITH COPY_ONLY): full".into(),
        );
    }
    d(Decision::Diff, None, "differential backup".into())
}

/// The files a restore applies, in order: the full, the newest differential that finished before the target, the
/// log backups after it up to the first one that reaches the target (all of them without a target).
pub fn restore_sequence(pieces: &[Piece], target: Option<u64>) -> Result<Vec<Piece>> {
    let full = pieces
        .iter()
        .find(|p| p.kind == Kind::Full)
        .context("the snapshot holds no full backup")?;
    if let Some(t) = target {
        if t < full.finished {
            bail!(
                "{} is before the end of the full backup ({}): not recoverable from this snapshot",
                fmt_time(t),
                fmt_time(full.finished)
            );
        }
    }
    let mut out = vec![full.clone()];
    let diff = pieces
        .iter()
        .filter(|p| p.kind == Kind::Diff && p.diff_base == full.checkpoint_lsn)
        .filter(|p| target.is_none_or(|t| p.finished <= t))
        .max_by_key(|p| p.last_lsn);
    let base = diff.unwrap_or(full);
    if let Some(d) = diff {
        out.push(d.clone());
    }
    let mut logs: Vec<&Piece> = pieces
        .iter()
        .filter(|p| p.kind == Kind::Log && p.last_lsn > base.last_lsn)
        .collect();
    logs.sort_by_key(|p| p.first_lsn);
    let mut at = base.last_lsn;
    for l in logs {
        if l.first_lsn > at {
            bail!("log backups missing between LSN {at} and {}", l.first_lsn);
        }
        at = l.last_lsn;
        out.push(l.clone());
        if target.is_some_and(|t| l.finished >= t) {
            return Ok(out);
        }
    }
    if let Some(t) = target {
        let end = out.last().map_or(0, |p| p.finished);
        if t > end {
            bail!(
                "{} is after the end of this snapshot ({}): pick a later snapshot",
                fmt_time(t),
                fmt_time(end)
            );
        }
    }
    Ok(out)
}

/// `YYYY-MM-DD[ T]HH:MM[:SS][Z|+00|+00:00|+0000]` (UTC offsets of whole minutes) -> unix seconds.
pub fn parse_time(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = (s.get(..10)?, s.get(11..)?);
    let mut d = date.split('-').map(str::parse::<i64>);
    let (y, mo, da) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let tz_at = rest.find(['Z', '+', '-', ' ']).unwrap_or(rest.len());
    let (time, tz) = rest.split_at(tz_at);
    let mut t = time.split(':').map(str::parse::<i64>);
    let (h, mi) = (t.next()?.ok()?, t.next()?.ok()?);
    let sec = match t.next() {
        Some(x) => x.ok()?,
        None => 0,
    };
    let tz = tz.trim();
    let off = match tz {
        "" | "Z" => 0,
        _ => {
            let sign = if tz.starts_with('-') { -1 } else { 1 };
            let digits: String = tz[1..].chars().filter(char::is_ascii_digit).collect();
            let (oh, om) = match digits.len() {
                2 => (digits.parse::<i64>().ok()?, 0),
                4 => (digits[..2].parse::<i64>().ok()?, digits[2..].parse::<i64>().ok()?),
                _ => return None,
            };
            sign * (oh * 3600 + om * 60)
        }
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // days from civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86400 + h * 3600 + mi * 60 + sec - off).ok()
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn fmt_time(t: u64) -> String {
    let days = (t / 86400) as i64;
    let s = t % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(name: &str, kind: Kind, first: u128, last: u128, ckpt: u128, base: u128, fin: u64) -> Piece {
        Piece {
            name: name.into(),
            kind,
            len: 1,
            mtime: fin,
            first_lsn: first,
            last_lsn: last,
            checkpoint_lsn: ckpt,
            diff_base: base,
            started: fin - 1,
            finished: fin,
            files: Vec::new(),
        }
    }

    fn chain() -> Vec<Piece> {
        vec![
            piece("f", Kind::Full, 100, 200, 150, 0, 1000),
            piece("l1", Kind::Log, 100, 300, 0, 0, 1100),
            piece("d1", Kind::Diff, 300, 350, 320, 150, 1150),
            piece("l2", Kind::Log, 300, 400, 0, 0, 1200),
            piece("l3", Kind::Log, 400, 500, 0, 0, 1300),
        ]
    }

    fn names(v: &[Piece]) -> Vec<&str> {
        v.iter().map(|p| p.name.as_str()).collect()
    }

    #[test]
    fn restore_sequences() {
        let c = chain();
        assert_eq!(names(&restore_sequence(&c, None).unwrap()), ["f", "d1", "l2", "l3"]);
        // before the differential: full + the first log
        assert_eq!(names(&restore_sequence(&c, Some(1050)).unwrap()), ["f", "l1"]);
        assert_eq!(names(&restore_sequence(&c, Some(1180)).unwrap()), ["f", "d1", "l2"]);
        assert_eq!(
            names(&restore_sequence(&c, Some(1300)).unwrap()),
            ["f", "d1", "l2", "l3"]
        );
        assert!(restore_sequence(&c, Some(999)).is_err());
        assert!(restore_sequence(&c, Some(1301)).is_err());
        // a missing log
        let gap: Vec<Piece> = c.iter().filter(|p| p.name != "l2").cloned().collect();
        assert!(restore_sequence(&gap, None)
            .unwrap_err()
            .to_string()
            .contains("missing"));
        // a differential of another full is ignored
        let mut other = c.clone();
        other[2].diff_base = 7;
        assert_eq!(names(&restore_sequence(&other, Some(1180)).unwrap()), ["f", "l1", "l2"]);
    }

    fn st() -> State {
        State {
            guid: "g".into(),
            base_time: 1000,
            to_time: 1300,
            pieces: chain(),
        }
    }

    fn db(model: &str, last_log: Option<&str>, diff_base: &str) -> DbState {
        DbState {
            model: model.into(),
            guid: "g".into(),
            last_log: last_log.map(str::to_owned),
            diff_base: Some(diff_base.into()),
        }
    }

    #[test]
    fn decisions() {
        let s = st();
        let dd = |db: &DbState, log, now| decide(Some(&s), db, log, 7, now);
        assert_eq!(
            decide(None, &db("FULL", None, "150"), true, 7, 2000).decision,
            Decision::Full
        );
        assert_eq!(dd(&db("FULL", Some("500"), "150"), true, 2000).decision, Decision::Log);
        assert_eq!(
            dd(&db("FULL", Some("500"), "150"), false, 2000).decision,
            Decision::Diff
        );
        // a foreign log backup moved last_log_backup_lsn
        let x = dd(&db("FULL", Some("650"), "150"), true, 2000);
        assert_eq!(x.decision, Decision::Full);
        assert!(x.chain_break.unwrap().contains("outside"));
        // log chain broken (SIMPLE and back)
        assert!(dd(&db("FULL", None, "150"), true, 2000).chain_break.is_some());
        // another full moved the differential base: full, not a break
        let x = dd(&db("FULL", Some("500"), "999"), false, 2000);
        assert_eq!((x.decision, x.chain_break), (Decision::Full, None));
        // age
        assert_eq!(
            dd(&db("FULL", Some("500"), "150"), false, 1000 + 7 * 86400).decision,
            Decision::Full
        );
        assert_eq!(
            dd(&db("FULL", Some("500"), "150"), true, 1000 + 7 * 86400).decision,
            Decision::Log
        );
        // SIMPLE: log runs do nothing
        let simple = State {
            pieces: vec![chain()[0].clone()],
            ..st()
        };
        let x = decide(Some(&simple), &db("SIMPLE", None, "150"), true, 7, 2000);
        assert_eq!(x.decision, Decision::Nothing);
        // recreated database
        let mut other = db("FULL", Some("500"), "150");
        other.guid = "h".into();
        assert_eq!(dd(&other, true, 2000).decision, Decision::Full);
    }

    #[test]
    fn range_and_times() {
        let r = st().range();
        assert_eq!(
            (r["from_time"].as_u64(), r["to_time"].as_u64()),
            (Some(1000), Some(1300))
        );
        assert_eq!(r["to_lsn"], "500");
        assert_eq!(parse_time("2026-11-02 10:46:04+00"), Some(1_793_616_364));
        assert_eq!(parse_time("2026-11-02T10:46:04Z"), Some(1_793_616_364));
        assert_eq!(parse_time("2026-11-02 11:46:04+01:00"), Some(1_793_616_364));
        assert_eq!(parse_time("2026-11-02 10:46"), Some(1_793_616_360));
        assert_eq!(parse_time("2026-13-02 10:46"), None);
        assert_eq!(fmt_time(1_793_616_364), "2026-11-02 10:46:04 UTC");
    }
}
