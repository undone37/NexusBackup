//! RMAN over SSH: backups into a staging directory on the database host, streamed into the snapshot, and the
//! point-in-time restore from the snapshot's pieces.
//!
//! Snapshot layout: `rman/<run>_<type>_<%U>` backup pieces (`db` level 0/1 data files, `al` archived logs, `cf`
//! control file, `sp` spfile; `<run>` = unix time of the run) and `rman/nexus.json` (what the restore needs: the
//! newest control file piece, the end SCN). A later run re-references the `db` and `al` pieces of the previous
//! snapshot (`Unchanged`) and adds its own; `cf` and `sp` only from the newest run.
//!
//! The level: 0 without a previous snapshot, on another database or incarnation (resetlogs), when a needed
//! archived log is gone (chain break) and every `full_every_days` (not for log runs, #43); else 1 for policy runs
//! and only the archived logs for log runs. The recoverable range: the end of the level 0's data file backup → the
//! moment right before this run's log switch (everything committed before it is in the backed-up logs).

use crate::ssh::{sh_quote, tail, Ssh};
use anyhow::{anyhow, bail, Context, Result};
use plugin_sdk::{error, Ctx, Kind, Meta, Sink, Source};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key: String,
    pub host_key: String,
    pub sid: String,
    pub home: Option<String>,
    pub staging: String,
    pub full_days: u64,
    pub delete_input: bool,
}

fn path_ok(p: &str) -> bool {
    p.starts_with('/')
        && p.len() < 1024
        && !p.split('/').any(|c| c == "..")
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
}

impl Config {
    pub fn of(c: &Value) -> Result<Config> {
        let s = |k: &str| c[k].as_str().unwrap_or_default().to_owned();
        let sid = s("sid");
        if sid.is_empty() || sid.len() > 30 || !sid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(error(22, "config: sid must be [A-Za-z0-9_]{1,30}"));
        }
        let home = Some(s("oracle_home")).filter(|h| !h.is_empty());
        let staging = Some(s("staging"))
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "/opt/oracle/nexus-rman".into());
        for p in home.iter().chain([&staging]) {
            if !path_ok(p) {
                return Err(error(
                    22,
                    format!("config: {p:?} is not an absolute path of [A-Za-z0-9._/-]"),
                ));
            }
        }
        Ok(Config {
            host: s("host"),
            port: c["port"].as_u64().unwrap_or(22) as u16,
            user: Some(s("user"))
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| "oracle".into()),
            key: s("ssh_key"),
            host_key: s("ssh_host_key"),
            staging: format!("{}/{sid}", staging.trim_end_matches('/')),
            sid,
            home,
            full_days: c["full_every_days"].as_u64().unwrap_or(7).max(1),
            delete_input: c["delete_archived_logs"].as_bool().unwrap_or(false),
        })
    }

    pub fn ssh(&self) -> Result<Ssh> {
        if self.host.is_empty() {
            return Err(error(22, "config: host missing"));
        }
        Ssh::connect(&self.host, self.port, &self.user, &self.key, &self.host_key)
    }

    /// Shell prefix: the instance's environment (ORACLE_HOME from the config, else /etc/oratab).
    fn env(&self) -> String {
        let home = match &self.home {
            Some(h) => sh_quote(h),
            None => format!("\"$(awk -F: '$1 == \"{}\" {{print $2}}' /etc/oratab)\"", self.sid),
        };
        format!(
            "export ORACLE_SID={sid} ORACLE_HOME={home} NLS_LANG=AMERICAN_AMERICA.AL32UTF8 \
             NLS_DATE_FORMAT='YYYY-MM-DD HH24:MI:SS'; [ -x \"$ORACLE_HOME/bin/rman\" ] || \
             {{ echo \"no ORACLE_HOME for {sid} (oracle_home or /etc/oratab)\" >&2; exit 2; }}; \
             export PATH=\"$ORACLE_HOME/bin:$PATH\"; ",
            sid = self.sid
        )
    }
}

/// Runs SQL as sysdba; the rows of `a||'|'||b` selects, split at `|`.
pub fn sql(ssh: &Ssh, cfg: &Config, q: &str) -> Result<Vec<Vec<String>>> {
    let input = format!(
        "set heading off feedback off pagesize 0 linesize 32767 trimspool on tab off verify off\n\
         whenever sqlerror exit failure\nwhenever oserror exit failure\n{q}\nexit\n"
    );
    let out = ssh
        .output(&format!("{}sqlplus -S -L / as sysdba", cfg.env()), input.as_bytes())
        .context("sqlplus")?;
    if out.contains("ORA-") || out.contains("SP2-") {
        bail!("sqlplus: {}", tail(&out, 10));
    }
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.split('|').map(|f| f.trim().to_owned()).collect())
        .collect())
}

/// Runs an RMAN script; its output (Err with the end of it when RMAN fails).
fn rman(ctx: &Ctx, ssh: &Ssh, cfg: &Config, script: &str) -> Result<String> {
    let out = ssh
        .output(
            &format!("{}rman target / ", cfg.env()),
            format!("{script}\nexit\n").as_bytes(),
        )
        .map_err(|e| anyhow!("rman: {e:#}"))?;
    for l in out.lines().filter(|l| l.starts_with("RMAN-") || l.starts_with("ORA-")) {
        ctx.warn(format!("rman: {l}"));
    }
    Ok(out)
}

pub struct Db {
    pub dbid: String,
    pub resetlogs: u64,
    pub log_mode: String,
}

pub fn database(ssh: &Ssh, cfg: &Config) -> Result<Db> {
    let r = sql(
        ssh,
        cfg,
        "select dbid||'|'||resetlogs_change#||'|'||log_mode from v$database;",
    )?;
    let r = r.first().filter(|r| r.len() == 3).context("v$database: no row")?;
    Ok(Db {
        dbid: r[0].clone(),
        resetlogs: r[1].parse()?,
        log_mode: r[2].clone(),
    })
}

/// (current SCN, UTC unix time) of the database.
fn now_db(ssh: &Ssh, cfg: &Config) -> Result<(u64, u64)> {
    let r = sql(
        ssh,
        cfg,
        "select current_scn||'|'||round((cast(sys_extract_utc(systimestamp) as date) - date '1970-01-01') * 86400) \
         from v$database;",
    )?;
    let r = r.first().filter(|r| r.len() == 2).context("current_scn: no row")?;
    Ok((r[0].parse()?, r[1].parse()?))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Piece {
    pub name: String,
    pub len: u64,
    pub mtime: u64,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    pub dbid: String,
    pub resetlogs: u64,
    /// time of the level 0 run
    pub base_time: u64,
    /// the recoverable range starts here (end of the level 0's data file backup)
    pub from_scn: u64,
    pub from_time: u64,
    /// ... and ends here (right before the last run's log switch)
    pub to_scn: u64,
    pub to_time: u64,
    /// per redo thread the first archived log sequence not yet backed up
    pub next_seq: BTreeMap<u32, u64>,
    /// the pieces of the snapshot
    pub pieces: Vec<Piece>,
}

pub struct Report {
    pub state: State,
    pub meta: Value,
    pub summary: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn meta(kind: Kind, size: u64, mtime: u64) -> Meta {
    Meta {
        kind: Some(kind),
        mode: if kind == Kind::Dir { 0o700 } else { 0o600 },
        size,
        mtime_ns: mtime as i64 * 1_000_000_000,
        ..Default::default()
    }
}

/// One `v$archived_log` row: thread, sequence, available (status A).
type LogRow = (u32, u64, bool);

/// Why the archived logs from `next_seq` on are not complete (a gap or a log deleted outside the backup), if they
/// are not. Several rows of one sequence (more than one archive destination): one available is enough.
pub fn chain_gap(next_seq: &BTreeMap<u32, u64>, rows: &[LogRow]) -> Option<String> {
    let mut have: BTreeMap<u32, BTreeMap<u64, bool>> = BTreeMap::new();
    for &(t, s, a) in rows {
        *have.entry(t).or_default().entry(s).or_default() |= a;
    }
    for (t, seqs) in &have {
        let Some(&from) = next_seq.get(t) else { continue };
        let Some(&last) = seqs.keys().next_back() else { continue };
        for s in from..=last {
            match seqs.get(&s) {
                Some(true) => {}
                Some(false) => {
                    return Some(format!(
                        "archived log thread {t} sequence {s} was deleted before it was backed up"
                    ))
                }
                None => return Some(format!("archived log thread {t} sequence {s} is missing")),
            }
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Level {
    Zero,
    One,
    Logs,
}

/// What this run backs up, and the chain break (for the snapshot meta) if there is one.
pub fn decide(
    prev: Option<&State>,
    db: &Db,
    log_run: bool,
    full_days: u64,
    now: u64,
    gap: impl FnOnce(&State) -> Result<Option<String>>,
) -> Result<(Level, Option<String>, String)> {
    let Some(p) = prev else {
        return Ok((Level::Zero, None, "first backup: level 0".into()));
    };
    if p.dbid != db.dbid {
        let why = format!("another database (DBID {} -> {})", p.dbid, db.dbid);
        return Ok((Level::Zero, Some(why.clone()), why));
    }
    if p.resetlogs != db.resetlogs {
        // a restore with RESETLOGS: expected after a point-in-time restore, not a broken chain
        return Ok((Level::Zero, None, "new incarnation (RESETLOGS): level 0".into()));
    }
    if let Some(why) = gap(p)? {
        return Ok((Level::Zero, Some(why.clone()), format!("{why}: level 0")));
    }
    if log_run {
        return Ok((Level::Logs, None, "archived logs".into()));
    }
    if now.saturating_sub(p.base_time) >= full_days * 86400 {
        return Ok((
            Level::Zero,
            None,
            format!("level 0 older than {full_days} days: level 0"),
        ));
    }
    Ok((Level::One, None, "level 1".into()))
}

const DIR: &[u8] = b"rman";

pub fn backup(ctx: &Ctx, sink: &mut Sink, ssh: &Ssh, cfg: &Config) -> Result<Report> {
    let db = database(ssh, cfg)?;
    if db.log_mode != "ARCHIVELOG" {
        return Err(error(
            22,
            format!("{} runs in {}: RMAN backups need ARCHIVELOG mode", cfg.sid, db.log_mode),
        ));
    }
    let prev: Option<State> = ctx
        .state
        .as_deref()
        .filter(|_| sink.has_base())
        .and_then(|s| serde_json::from_slice(s).ok());
    let log_run = ctx.params["mode"].as_str() == Some("log");
    let (level, brk, why) = decide(prev.as_ref(), &db, log_run, cfg.full_days, now(), |p| {
        // archived logs deleted from disk outside RMAN are only known after a crosscheck
        rman(ctx, ssh, cfg, "crosscheck archivelog all;")?;
        let rows = sql(
            ssh,
            cfg,
            &format!(
                "select thread#||'|'||sequence#||'|'||status from v$archived_log \
                 where resetlogs_change# = {} and standby_dest = 'NO' and name is not null \
                 and name not in (select member from v$logfile) and sequence# >= {} order by 1;",
                db.resetlogs,
                p.next_seq.values().min().copied().unwrap_or(0)
            ),
        )?;
        let rows: Vec<LogRow> = rows
            .iter()
            .filter(|r| r.len() == 3)
            .filter_map(|r| Some((r[0].parse().ok()?, r[1].parse().ok()?, r[2] == "A")))
            .collect();
        Ok(chain_gap(&p.next_seq, &rows))
    })?;
    if brk.is_some() {
        ctx.warn(&why);
    } else {
        ctx.info(&why);
    }
    let run = now();
    let tag = format!("NEXUS_{run}");
    let fmt = |t: &str| sh_quote(&format!("{}/{run}_{t}_%U", cfg.staging));
    ssh.run(&format!("mkdir -p {s} && chmod 700 {s}", s = sh_quote(&cfg.staging)))
        .context("staging directory")?;

    let mut st = match (&prev, level) {
        (Some(p), Level::One | Level::Logs) => State {
            pieces: p
                .pieces
                .iter()
                .filter(|x| kind_of(&x.name) == "db" || kind_of(&x.name) == "al")
                .cloned()
                .collect(),
            next_seq: p.next_seq.clone(),
            ..State {
                dbid: db.dbid.clone(),
                resetlogs: db.resetlogs,
                base_time: p.base_time,
                from_scn: p.from_scn,
                from_time: p.from_time,
                ..Default::default()
            }
        },
        _ => State {
            dbid: db.dbid.clone(),
            resetlogs: db.resetlogs,
            base_time: run,
            ..Default::default()
        },
    };
    let res = (|| -> Result<()> {
        // archived logs from these sequences on (per thread) belong to this snapshot
        let first = match level {
            Level::Zero => {
                // the online logs being written now hold the start of the data file backup
                let mut cur = BTreeMap::new();
                for r in sql(
                    ssh,
                    cfg,
                    "select thread#||'|'||sequence# from v$log where status = 'CURRENT';",
                )?
                .iter()
                .filter(|r| r.len() == 2)
                {
                    cur.insert(r[0].parse::<u32>()?, r[1].parse::<u64>()?);
                }
                rman(
                    ctx,
                    ssh,
                    cfg,
                    &format!("backup incremental level 0 database format {} tag '{tag}';", fmt("db")),
                )?;
                let (s, t) = now_db(ssh, cfg)?;
                (st.from_scn, st.from_time) = (s, t);
                cur
            }
            Level::One => {
                rman(
                    ctx,
                    ssh,
                    cfg,
                    &format!("backup incremental level 1 database format {} tag '{tag}';", fmt("db")),
                )?;
                st.next_seq.clone()
            }
            Level::Logs => st.next_seq.clone(),
        };
        let (to_scn, to_time) = now_db(ssh, cfg)?;
        (st.to_scn, st.to_time) = (to_scn, to_time);
        sql(ssh, cfg, "alter system archive log current;")?;
        // the logs up to the switch, by sequence: per thread everything below the log that holds to_scn + 1
        let rows = sql(
            ssh,
            cfg,
            &format!(
                "select thread#||'|'||max(sequence#) from v$archived_log where resetlogs_change# = {} \
                 and first_change# <= {to_scn} group by thread#;",
                db.resetlogs
            ),
        )?;
        let mut last = BTreeMap::new();
        for r in rows.iter().filter(|r| r.len() == 2) {
            last.insert(r[0].parse::<u32>()?, r[1].parse::<u64>()?);
        }
        let until: Vec<String> = last
            .iter()
            .filter_map(|(t, s)| {
                let from = first.get(t).copied().unwrap_or(1);
                (from <= *s).then(|| {
                    format!(
                        "backup archivelog sequence between {from} and {s} thread {t} format {} tag '{tag}'{};",
                        fmt("al"),
                        if cfg.delete_input { " delete input" } else { "" }
                    )
                })
            })
            .collect();
        rman(
            ctx,
            ssh,
            cfg,
            &format!(
                "{}\nbackup current controlfile format {} tag '{tag}';\nbackup spfile format {} tag '{tag}';",
                until.join("\n"),
                fmt("cf"),
                fmt("sp")
            ),
        )?;
        for (t, s) in &last {
            st.next_seq.insert(*t, s + 1);
        }
        Ok(())
    })();
    if let Err(e) = res {
        cleanup(ctx, ssh, cfg, run);
        return Err(e);
    }

    // the pieces: the previous ones re-referenced, the new ones streamed and removed from staging
    sink.entry(DIR, meta(Kind::Dir, 0, run))?;
    for p in &st.pieces {
        sink.unchanged(format!("rman/{}", p.name).as_bytes(), meta(Kind::File, p.len, p.mtime))?;
    }
    let listing = ssh.output(
        &format!(
            "find {} -maxdepth 1 -type f -name '{run}_*' -printf '%s %f\\n'",
            sh_quote(&cfg.staging)
        ),
        b"",
    )?;
    let mut new = Vec::new();
    for l in listing.lines() {
        let Some((len, name)) = l.split_once(' ') else { continue };
        new.push(Piece {
            name: name.to_owned(),
            len: len.parse()?,
            mtime: run,
        });
    }
    new.sort_by(|a, b| a.name.cmp(&b.name));
    if !new.iter().any(|p| kind_of(&p.name) == "cf") {
        cleanup(ctx, ssh, cfg, run);
        bail!("RMAN left no control file piece in {}", cfg.staging);
    }
    let total: u64 = new.iter().map(|p| p.len).sum();
    let mut done = 0;
    let res = (|| -> Result<()> {
        for p in &new {
            ctx.progress(done, total, format!("rman/{}", p.name));
            let path = format!("{}/{}", cfg.staging, p.name);
            let mut e = ssh.exec(&format!("cat {}", sh_quote(&path)))?;
            e.close_stdin();
            sink.file(
                format!("rman/{}", p.name).as_bytes(),
                meta(Kind::File, p.len, p.mtime),
                &mut e,
            )?;
            e.finish().with_context(|| format!("reading {path}"))?;
            done += p.len;
        }
        Ok(())
    })();
    cleanup(ctx, ssh, cfg, run);
    res?;
    st.pieces.extend(new.iter().cloned());
    let cf = new.iter().find(|p| kind_of(&p.name) == "cf").map(|p| p.name.clone());
    let info = serde_json::to_vec_pretty(&json!({
        "sid": cfg.sid, "dbid": st.dbid, "resetlogs": st.resetlogs, "controlfile": cf,
        "from_scn": st.from_scn, "from_time": st.from_time, "to_scn": st.to_scn, "to_time": st.to_time,
    }))?;
    sink.file(
        b"rman/nexus.json",
        meta(Kind::File, info.len() as u64, run),
        &mut info.as_slice(),
    )?;

    let mut m = json!({"recoverable": {
        "from_time": st.from_time, "from_lsn": st.from_scn.to_string(),
        "to_time": st.to_time.max(st.from_time), "to_lsn": st.to_scn.max(st.from_scn).to_string(),
        "unit": "scn",
    }});
    if let Some(b) = brk {
        m["chain_break"] = json!(b);
    }
    let what = match level {
        Level::Zero => "level 0",
        Level::One => "level 1",
        Level::Logs => "archived logs",
    };
    Ok(Report {
        summary: format!(
            "{what}: {} new pieces ({total} bytes), {} in the snapshot; recoverable to SCN {}",
            new.len(),
            st.pieces.len() + 1,
            st.to_scn
        ),
        meta: m,
        state: st,
    })
}

/// `db`, `al`, `cf` or `sp` of `<run>_<type>_<%U>`.
fn kind_of(name: &str) -> &str {
    name.split('_').nth(1).unwrap_or_default()
}

/// Removes the run's files from staging. Their records stay AVAILABLE in the control file: a level 1 needs its
/// level 0 there as the parent (an expired one makes RMAN take a new level 0); a restore crosschecks them.
fn cleanup(ctx: &Ctx, ssh: &Ssh, cfg: &Config, run: u64) {
    if let Err(e) = ssh.run(&format!("rm -f {}/{run}_*", sh_quote(&cfg.staging))) {
        ctx.warn(format!("staging not emptied: {e:#}"));
    }
}

/// Point-in-time restore on the source host: the snapshot's pieces into `<staging>/restore-<time>`, the control
/// file from its newest piece, the pieces cataloged, RESTORE / RECOVER UNTIL, OPEN RESETLOGS. Replaces the
/// running database: the params must name its SID (`confirm`).
pub fn pitr(ctx: &Ctx, src: &mut Source, ssh: &Ssh, cfg: &Config) -> Result<String> {
    let p = &ctx.params["params"];
    if p["confirm"].as_str() != Some(cfg.sid.as_str()) {
        return Err(error(
            22,
            format!(
                "the restore replaces database {} on {}: type its SID to confirm",
                cfg.sid, cfg.host
            ),
        ));
    }
    let dir = format!(
        "{}/restore-{}",
        cfg.staging,
        ctx.params["snapshot"]["time"].as_u64().unwrap_or_else(now)
    );
    let qdir = sh_quote(&dir);
    ssh.run(&format!("rm -rf {qdir} && mkdir -p {qdir} && chmod 700 {qdir}"))?;
    let mut info = Value::Null;
    let (mut n, mut bytes) = (0u64, 0u64);
    let res = src.files(&[DIR.to_vec()], |item, data| {
        if item.meta.kind != Some(Kind::File) {
            return Ok(());
        }
        let name = String::from_utf8_lossy(&item.path)
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        if name == "nexus.json" {
            let mut b = Vec::new();
            data.read_to_end(&mut b)?;
            info = serde_json::from_slice(&b)?;
            return Ok(());
        }
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
            bail!("unexpected piece name {name:?}");
        }
        let mut e = ssh.exec(&format!("cat > {}", sh_quote(&format!("{dir}/{name}"))))?;
        bytes += std::io::copy(data, &mut e)?;
        e.finish()?;
        n += 1;
        Ok(())
    });
    let res = res.and_then(|()| {
        let cf = info["controlfile"]
            .as_str()
            .context("rman/nexus.json: no control file piece")?;
        if info["sid"].as_str() != Some(cfg.sid.as_str()) {
            bail!("the snapshot is of {:?}, the source is {}", info["sid"], cfg.sid);
        }
        let until = until(ssh, p, &info)?;
        ctx.info(format!(
            "{n} pieces ({bytes} bytes) in {dir}; restoring {}, {until}",
            cfg.sid
        ));
        rman(
            ctx,
            ssh,
            cfg,
            &format!(
                "startup force nomount;\nrestore controlfile from '{dir}/{cf}';\nalter database mount;\n\
                 crosscheck backup;\ncatalog start with '{dir}/' noprompt;\n\
                 run {{ {until}; restore database; recover database; }}\nalter database open resetlogs;\n\
                 sql 'alter pluggable database all open';"
            ),
        )?;
        Ok(until)
    });
    if let Err(e) = ssh.run(&format!("rm -rf {qdir}")) {
        ctx.warn(format!("{dir} not removed: {e:#}"));
    }
    let until = res?;
    Ok(format!(
        "{} restored on {} ({until}), opened with RESETLOGS: the next backup is a level 0",
        cfg.sid, cfg.host
    ))
}

/// The RMAN `set until` of the params: a time (converted to the host's local time, as RMAN reads it), an SCN, or
/// the end of the snapshot.
fn until(ssh: &Ssh, p: &Value, info: &Value) -> Result<String> {
    if let Some(scn) = p["target_scn"].as_str().filter(|s| !s.is_empty()) {
        let scn: u64 = scn.parse().map_err(|_| error(22, "target_scn: a number"))?;
        return Ok(format!("set until scn {scn}"));
    }
    if let Some(t) = p["target_time"].as_str().filter(|s| !s.is_empty()) {
        if !t.bytes().all(|b| b.is_ascii_digit() || b" -:+.TZ".contains(&b)) {
            return Err(error(22, "target_time: YYYY-MM-DD HH:MM:SS+00"));
        }
        let local = ssh
            .output(&format!("date -d {} '+%Y-%m-%d %H:%M:%S'", sh_quote(t)), b"")
            .context("target_time")?;
        return Ok(format!(
            "set until time \"to_date('{}', 'YYYY-MM-DD HH24:MI:SS')\"",
            local.trim()
        ));
    }
    let end = info["to_scn"].as_u64().context("rman/nexus.json: no end SCN")?;
    // UNTIL SCN stops before the given SCN
    Ok(format!("set until scn {}", end + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(dbid: &str, reset: u64) -> Db {
        Db {
            dbid: dbid.into(),
            resetlogs: reset,
            log_mode: "ARCHIVELOG".into(),
        }
    }

    #[test]
    fn gaps_in_the_archived_logs() {
        let next = BTreeMap::from([(1, 10)]);
        assert_eq!(chain_gap(&next, &[(1, 10, true), (1, 11, true)]), None);
        // two destinations: one copy is enough
        assert_eq!(chain_gap(&next, &[(1, 10, false), (1, 10, true), (1, 11, true)]), None);
        assert!(chain_gap(&next, &[(1, 10, true), (1, 12, true)])
            .unwrap()
            .contains("sequence 11 is missing"));
        assert!(chain_gap(&next, &[(1, 10, false), (1, 11, true)])
            .unwrap()
            .contains("sequence 10 was deleted"));
        // nothing archived since: no gap
        assert_eq!(chain_gap(&next, &[]), None);
    }

    #[test]
    fn levels() {
        let p = State {
            dbid: "1".into(),
            resetlogs: 5,
            base_time: 1000,
            ..Default::default()
        };
        let ok = |_: &State| Ok(None);
        let d = |prev, db: &Db, log, now| decide(prev, db, log, 7, now, ok).unwrap();
        assert_eq!(d(None, &db("1", 5), false, 2000).0, Level::Zero);
        assert_eq!(d(Some(&p), &db("1", 5), false, 2000).0, Level::One);
        assert_eq!(d(Some(&p), &db("1", 5), true, 2000).0, Level::Logs);
        // age: policy runs get a new level 0, log runs never
        assert_eq!(d(Some(&p), &db("1", 5), false, 1000 + 7 * 86400).0, Level::Zero);
        assert_eq!(d(Some(&p), &db("1", 5), true, 1000 + 7 * 86400).0, Level::Logs);
        // resetlogs: level 0 without a chain break; another database: a break
        let (l, b, _) = d(Some(&p), &db("1", 6), true, 2000);
        assert_eq!((l, b), (Level::Zero, None));
        let (l, b, _) = d(Some(&p), &db("2", 5), true, 2000);
        assert_eq!(l, Level::Zero);
        assert!(b.unwrap().contains("another database"));
        let (l, b, _) = decide(Some(&p), &db("1", 5), true, 7, 2000, |_| Ok(Some("gap".into()))).unwrap();
        assert_eq!((l, b.as_deref()), (Level::Zero, Some("gap")));
    }

    #[test]
    fn config_paths() {
        let c = Config::of(&json!({"host": "h", "sid": "FREE"})).unwrap();
        assert_eq!(c.staging, "/opt/oracle/nexus-rman/FREE");
        assert_eq!(c.user, "oracle");
        assert!(Config::of(&json!({"sid": "FR EE"})).is_err());
        assert!(Config::of(&json!({"sid": "FREE", "staging": "/a/../b"})).is_err());
        assert!(Config::of(&json!({"sid": "FREE", "oracle_home": "relative"})).is_err());
        assert!(c.env().contains("/etc/oratab"));
        assert_eq!(kind_of("1792000000_al_0b3a5j3k_1_1"), "al");
    }
}
