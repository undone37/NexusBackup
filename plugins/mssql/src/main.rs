//! SQL Server plugin (#41, docs/database-logs-design.md, plugins/mssql/README.md).
//!
//! The appliance logs in to the SQL Server host over SSH and runs T-SQL there: on Windows through PowerShell with
//! integrated security as the SSH account (`sql.ps1`), on Linux through `sqlcmd` with a SQL login, inside the
//! container (`docker exec`) when SQL Server runs in Docker or Podman. Guests are databases; each gets its own
//! snapshot. SQL Server writes full, differential and log backups into a staging folder (as SQL Server sees it);
//! the plugin streams each file into the snapshot and deletes it. Every snapshot holds the newest full, the
//! differentials and all log backups since it: restorable on its own, to any time of its recoverable range.

mod chain;

use anyhow::{bail, Context, Result};
use chain::{Decision, Kind as BKind, Piece, State};
use plugin_sdk::{error, BackupResult, Ctx, Guest, Kind, Meta, Plugin, Sink, Source, Validation};
use plugin_ssh::{sh_quote, tail, Exec, Ssh};
use serde_json::{json, Value};
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

const RUNNER: &str = include_str!("sql.ps1");
/// Answers of our own queries start with this (anything else on stdout is ignored).
const MARK: &str = "#NEXUS#";

enum Platform {
    /// SQL Server on Windows: PowerShell, integrated security
    Windows,
    /// SQL Server on Linux: sqlcmd with a SQL login; `prefix` runs a command in the container (empty: on the host)
    Linux {
        prefix: String,
        sqlcmd: String,
        login: String,
        password: String,
    },
}

struct Config {
    host: String,
    port: u16,
    user: String,
    key: String,
    host_key: String,
    platform: Platform,
    /// `.` or `.\NAME` (Windows)
    server: String,
    /// the staging folder as SQL Server sees it
    staging: String,
    full_days: u64,
}

/// A Windows path of letters, digits and `\ : . _ -` (it goes into command lines).
fn win_path_ok(p: &str) -> bool {
    p.len() > 3
        && p.len() < 200
        && p.as_bytes()[1] == b':'
        && p.as_bytes()[2] == b'\\'
        && !p.contains("..")
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"\\:._-".contains(&b))
}

fn unix_path_ok(p: &str) -> bool {
    p.starts_with('/')
        && p.len() < 200
        && !p.contains("..")
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
}

fn name_ok(n: &str, extra: &[u8]) -> bool {
    !n.is_empty() && n.len() <= 128 && n.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

impl Config {
    fn of(c: &Value) -> Result<Config> {
        let s = |k: &str| c[k].as_str().unwrap_or_default().to_owned();
        let inst = s("instance");
        if !inst.is_empty() && !name_ok(&inst, b"_") {
            return Err(error(22, "config: instance must be [A-Za-z0-9_]"));
        }
        let linux = s("platform") == "linux";
        let staging = Some(s("staging")).filter(|x| !x.is_empty()).unwrap_or_else(|| {
            if linux {
                "/var/opt/mssql/nexus-staging".into()
            } else {
                "C:\\NexusBackup\\staging".into()
            }
        });
        if (linux && !unix_path_ok(&staging)) || (!linux && !win_path_ok(&staging)) {
            return Err(error(
                22,
                "config: staging must be an absolute path of letters, digits and . _ - (Windows: C:\\..., Linux: /...)",
            ));
        }
        let platform = if linux {
            let container = s("container");
            let cli = Some(s("container_cli"))
                .filter(|x| !x.is_empty())
                .unwrap_or_else(|| "docker".into());
            if !container.is_empty() && !name_ok(&container, b"._-") {
                return Err(error(22, "config: container must be a container name or id"));
            }
            if !matches!(cli.as_str(), "docker" | "podman" | "sudo docker" | "sudo podman") {
                return Err(error(
                    22,
                    "config: container_cli must be docker or podman (optionally with sudo)",
                ));
            }
            let sqlcmd = Some(s("sqlcmd"))
                .filter(|x| !x.is_empty())
                .unwrap_or_else(|| "/opt/mssql-tools18/bin/sqlcmd".into());
            if !unix_path_ok(&sqlcmd) {
                return Err(error(22, "config: sqlcmd must be an absolute path"));
            }
            let login = s("sql_user");
            if !name_ok(&login, b"_.-") {
                return Err(error(
                    22,
                    "config: sql_user is required on Linux (a SQL login, e.g. sa)",
                ));
            }
            Platform::Linux {
                prefix: if container.is_empty() {
                    String::new()
                } else {
                    format!("{cli} exec -i -e SQLCMDPASSWORD {container} ")
                },
                sqlcmd,
                login,
                password: s("sql_password"),
            }
        } else {
            Platform::Windows
        };
        Ok(Config {
            host: s("host"),
            port: c["port"].as_u64().unwrap_or(22) as u16,
            user: s("user"),
            key: s("ssh_key"),
            host_key: s("ssh_host_key"),
            server: if inst.is_empty() || inst == "MSSQLSERVER" {
                ".".into()
            } else {
                format!(".\\{inst}")
            },
            staging: staging.trim_end_matches(['\\', '/']).to_owned(),
            platform,
            full_days: c["full_every_days"].as_u64().unwrap_or(7).max(1),
        })
    }

    fn connect(self) -> Result<Host> {
        if self.host.is_empty() || self.user.is_empty() {
            return Err(error(22, "config: host and user are required"));
        }
        let ssh = Ssh::connect(&self.host, self.port, &self.user, &self.key, &self.host_key)?;
        let h = Host { ssh, cfg: self };
        if matches!(h.cfg.platform, Platform::Windows) {
            h.put(&h.runner(), &mut RUNNER.as_bytes())
                .context("uploading the T-SQL runner into the staging folder")?;
        }
        Ok(h)
    }
}

/// The SSH session to the SQL Server host.
struct Host {
    ssh: Ssh,
    cfg: Config,
}

/// `N'...'`
fn lit(s: &str) -> String {
    format!("N'{}'", s.replace('\'', "''"))
}

/// `[...]`
fn br(s: &str) -> String {
    format!("[{}]", s.replace(']', "]]"))
}

impl Host {
    fn sep(&self) -> char {
        match self.cfg.platform {
            Platform::Windows => '\\',
            Platform::Linux { .. } => '/',
        }
    }

    fn path(&self, name: &str) -> String {
        format!("{}{}{name}", self.cfg.staging, self.sep())
    }

    fn runner(&self) -> String {
        self.path("nexus-sql.ps1")
    }

    /// A one-line PowerShell command (no double quotes) through cmd.exe.
    fn ps(ps: &str) -> String {
        format!("powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"{ps}\"")
    }

    /// A shell command on the host or in the container.
    fn sh(&self, cmd: &str) -> String {
        match &self.cfg.platform {
            Platform::Linux { prefix, .. } if !prefix.is_empty() => format!("{prefix}sh -c {}", sh_quote(cmd)),
            _ => cmd.to_owned(),
        }
    }

    /// Runs a T-SQL batch; the rows of its result sets, fields split at tabs.
    fn sql(&self, batch: &str) -> Result<Vec<Vec<String>>> {
        let out = match &self.cfg.platform {
            Platform::Windows => self.ssh.output(
                &format!(
                    "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {} {}",
                    self.runner(),
                    self.cfg.server
                ),
                batch.as_bytes(),
            ),
            Platform::Linux {
                prefix,
                sqlcmd,
                login,
                password,
            } => {
                // the password is the first line of stdin, never on a command line
                let cmd = format!(
                    "IFS= read -r p; SQLCMDPASSWORD=$p; export SQLCMDPASSWORD; exec {prefix}{sqlcmd} -S localhost -U {login} \
                     -C -b -m 1 -y 0 -s \"$(printf '\\t')\" -i /dev/stdin"
                );
                // -y 0 (no width limit for the JSON answers) cannot drop the column headers (-h -1)
                self.ssh
                    .output(&cmd, format!("{password}\n{batch}\n").as_bytes())
                    .map(|o| without_headers(&o))
            }
        }
        .map_err(|e| anyhow::anyhow!("T-SQL: {e:#}"))?;
        Ok(out
            .lines()
            .map(|l| l.trim_end_matches('\r'))
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.split('\t').map(|f| f.trim().to_owned()).collect())
            .collect())
    }

    /// A batch ending in `SELECT N'#NEXUS#' + (SELECT ... FOR JSON ...)`: that JSON.
    fn json(&self, batch: &str) -> Result<Value> {
        let rows = self.sql(&format!("SET NOCOUNT ON;\n{batch}"))?;
        let line = rows
            .iter()
            .filter_map(|r| r.first())
            .find_map(|f| f.strip_prefix(MARK))
            .with_context(|| {
                format!(
                    "no answer from SQL Server: {}",
                    tail(&rows.iter().map(|r| r.join(" ")).collect::<Vec<_>>().join("\n"), 5)
                )
            })?;
        if line.trim().is_empty() || line.trim() == "NULL" {
            return Ok(Value::Null);
        }
        serde_json::from_str(line).with_context(|| format!("unexpected answer: {line:.200}"))
    }

    /// Writes `data` into `path`; the bytes written. Windows: the folder by PowerShell, the file over SFTP
    /// (PowerShell 5.1 cannot read a binary stdin stream over OpenSSH: it stalls after 128 KiB).
    fn put(&self, path: &str, data: &mut dyn Read) -> Result<u64> {
        match self.cfg.platform {
            Platform::Windows => {
                let (dir, _) = path.rsplit_once('\\').context("put: not a Windows path")?;
                self.ssh.run(&Self::ps(&format!(
                    "New-Item -ItemType Directory -Force '{dir}' | Out-Null"
                )))?;
                self.ssh.upload(&format!("/{}", path.replace('\\', "/")), data)
            }
            Platform::Linux { .. } => {
                let mut e = self.ssh.exec(&self.sh(&format!(
                    "mkdir -p {d} && cat > {p}",
                    d = sh_quote(path.rsplit_once('/').map_or("/", |x| x.0)),
                    p = sh_quote(path)
                )))?;
                let n = std::io::copy(data, &mut e)?;
                e.finish()?;
                Ok(n)
            }
        }
    }

    /// The raw bytes of `path` on stdout.
    fn get(&self, path: &str) -> Result<Exec<'_>> {
        let mut e = match self.cfg.platform {
            Platform::Windows => self.ssh.exec(&Self::ps(&format!(
                "$o = [Console]::OpenStandardOutput(); $f = [IO.File]::OpenRead('{path}'); $f.CopyTo($o); $o.Flush(); $f.Close()"
            )))?,
            Platform::Linux { .. } => self.ssh.exec(&self.sh(&format!("cat {}", sh_quote(path))))?,
        };
        e.close_stdin();
        Ok(e)
    }

    fn size(&self, path: &str) -> Result<u64> {
        let out = match self.cfg.platform {
            Platform::Windows => self
                .ssh
                .output(&Self::ps(&format!("(Get-Item '{path}').Length")), b"")?,
            Platform::Linux { .. } => self
                .ssh
                .output(&self.sh(&format!("stat -c %s {}", sh_quote(path))), b"")?,
        };
        out.trim().parse().with_context(|| format!("size of {path}: {out:?}"))
    }

    /// Removes the staging files `<prefix>*` (and directories).
    fn remove(&self, prefix: &str) -> Result<()> {
        let p = self.path(prefix);
        match self.cfg.platform {
            Platform::Windows => self.ssh.run(&Self::ps(&format!(
                "Remove-Item -Force -Recurse -ErrorAction SilentlyContinue '{p}*'"
            ))),
            Platform::Linux { .. } => self.ssh.run(&self.sh(&format!("rm -rf -- {}*", sh_quote(&p)))),
        }
    }

    fn mkdir_staging(&self) -> Result<()> {
        match self.cfg.platform {
            Platform::Windows => self.ssh.run(&Self::ps(&format!(
                "New-Item -ItemType Directory -Force '{}' | Out-Null",
                self.cfg.staging
            ))),
            Platform::Linux { .. } => self
                .ssh
                .run(&self.sh(&format!("mkdir -p {}", sh_quote(&self.cfg.staging)))),
        }
    }
}

/// sqlcmd output without the header of each result set (the line of column names and the line of dashes under it).
fn without_headers(out: &str) -> String {
    let lines: Vec<&str> = out.lines().collect();
    let dashes = |l: &str| !l.trim().is_empty() && l.chars().all(|c| c == '-' || c.is_whitespace());
    let mut keep = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if dashes(l) || lines.get(i + 1).is_some_and(|n| dashes(n)) {
            continue;
        }
        keep.push(*l);
    }
    keep.join("\n")
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

/// Database names usable as guest ids (and in file names).
fn db_ok(n: &str) -> bool {
    plugin_sdk::proto::valid_guest_id(n) && !n.starts_with('.')
}

/// UTC unix seconds of a server-local datetime expression.
fn utc(expr: &str) -> String {
    format!(
        "DATEDIFF_BIG(second, '19700101', DATEADD(minute, DATEDIFF(minute, SYSDATETIME(), SYSUTCDATETIME()), {expr}))"
    )
}

fn info(h: &Host) -> Result<Value> {
    h.json(&format!(
        "SELECT {} + (SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(64)) AS version, \
         CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition, IS_SRVROLEMEMBER('sysadmin') AS sysadmin, \
         (SELECT d.name, d.recovery_model_desc AS model, d.state_desc AS state, \
            (SELECT SUM(CAST(f.size AS bigint)) * 8192 FROM sys.master_files f WHERE f.database_id = d.database_id) AS size \
          FROM sys.databases d WHERE d.database_id > 4 ORDER BY d.name FOR JSON PATH) AS databases \
         FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES);",
        lit(MARK)
    ))
}

struct Mssql;

fn invalid(field: &str, message: impl Into<String>) -> Validation {
    Validation::Invalid {
        field: field.into(),
        message: message.into(),
    }
}

impl Plugin for Mssql {
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
        let cfg = match Config::of(&ctx.config) {
            Ok(c) => c,
            Err(e) => return Ok(invalid("platform", format!("{e:#}"))),
        };
        let user = cfg.user.clone();
        let h = match cfg.connect() {
            Ok(h) => h,
            Err(e) => return Ok(invalid("host", format!("{e:#}"))),
        };
        let i = match info(&h) {
            Ok(i) => i,
            Err(e) => {
                let f = if matches!(h.cfg.platform, Platform::Windows) {
                    "instance"
                } else {
                    "sql_user"
                };
                return Ok(invalid(f, format!("{e:#}")));
            }
        };
        if i["sysadmin"].as_i64() != Some(1) {
            let who = match &h.cfg.platform {
                Platform::Windows => user,
                Platform::Linux { login, .. } => login.clone(),
            };
            return Ok(invalid(
                "user",
                format!("{who} is not sysadmin on the instance (backups and restores need it)"),
            ));
        }
        if let Err(e) = h.mkdir_staging() {
            return Ok(invalid("staging", format!("staging folder: {e:#}")));
        }
        Ok(Validation::Valid)
    }

    fn list_guests(&mut self, ctx: &Ctx) -> Result<Vec<Guest>> {
        let i = info(&Config::of(&ctx.config)?.connect()?)?;
        let mut out = Vec::new();
        for d in i["databases"].as_array().into_iter().flatten() {
            let name = d["name"].as_str().unwrap_or_default();
            if !db_ok(name) {
                ctx.warn(format!(
                    "database {name:?} skipped: names must be [A-Za-z0-9._-]{{1,64}}"
                ));
                continue;
            }
            out.push(Guest {
                id: name.into(),
                title: format!("{name} ({})", d["model"].as_str().unwrap_or("?")),
                size: d["size"].as_u64(),
            });
        }
        Ok(out)
    }

    fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
        let Some(db) = ctx.guest().map(str::to_owned) else {
            return Err(error(
                22,
                "select the databases of the group (each gets its own snapshot)",
            ));
        };
        let h = Config::of(&ctx.config)?.connect()?;
        let (st, m, summary) = backup(ctx, sink, &h, &db)?;
        sink.snapshot_meta(&m)?;
        Ok(BackupResult {
            state: Some(serde_json::to_vec(&st)?),
            consistent: true,
            summary,
        })
    }

    fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String> {
        let h = Config::of(&ctx.config)?.connect()?;
        match ctx.params["restore"].as_str() {
            Some("pitr") => restore(ctx, src, &h, false),
            Some("verify") => restore(ctx, src, &h, true),
            r => Err(error(95, format!("unknown restore {r:?}"))),
        }
    }
}

const DIR: &[u8] = b"mssql";

/// One backup of `db` into the staging folder; the backupset row with the file's size.
fn take(h: &Host, db: &str, kind: BKind, name: &str, run: u64) -> Result<Piece> {
    let path = h.path(name);
    let desc = format!("nexusbackup {run}");
    let what = if kind == BKind::Log { "LOG" } else { "DATABASE" };
    let diff = if kind == BKind::Diff { "DIFFERENTIAL, " } else { "" };
    let r = h.json(&format!(
        "BACKUP {what} {db_} TO DISK = {p} WITH {diff}CHECKSUM, NO_COMPRESSION, NAME = N'nexusbackup', DESCRIPTION = {d};\n\
         SELECT {m} + (SELECT TOP 1 CAST(first_lsn AS nvarchar(40)) AS first_lsn, CAST(last_lsn AS nvarchar(40)) AS last_lsn, \
         CAST(checkpoint_lsn AS nvarchar(40)) AS checkpoint_lsn, CAST(differential_base_lsn AS nvarchar(40)) AS differential_base_lsn, \
         {s} AS started, {f} AS finished, \
         (SELECT logical_name AS l, physical_name AS p, file_type AS t FROM msdb.dbo.backupfile bf WHERE bf.backup_set_id = b.backup_set_id FOR JSON PATH) AS files \
         FROM msdb.dbo.backupset b WHERE database_name = {dbl} AND description = {d} ORDER BY backup_set_id DESC \
         FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES);",
        db_ = br(db),
        p = lit(&path),
        d = lit(&desc),
        m = lit(MARK),
        dbl = lit(db),
        s = utc("backup_start_date"),
        f = utc("backup_finish_date"),
    ))?;
    let mut r = r;
    r["size"] = json!(h.size(&path)?);
    Piece::from_backupset(name.to_owned(), kind, &r)
}

/// One backup run of database `db`: (state, snapshot meta, summary).
fn backup(ctx: &Ctx, sink: &mut Sink, h: &Host, db: &str) -> Result<(State, Value, String)> {
    let prev: Option<State> = ctx
        .state
        .as_deref()
        .filter(|_| sink.has_base())
        .and_then(|s| serde_json::from_slice(s).ok());
    let state = |h: &Host| -> Result<Value> {
        let v = h.json(&format!(
            "SELECT {} + (SELECT d.recovery_model_desc AS model, CAST(s.database_guid AS nvarchar(36)) AS guid, \
             CAST(s.last_log_backup_lsn AS nvarchar(40)) AS last_log, CAST(f.differential_base_lsn AS nvarchar(40)) AS diff_base, \
             {} AS now FROM sys.databases d JOIN sys.database_recovery_status s ON s.database_id = d.database_id \
             JOIN sys.master_files f ON f.database_id = d.database_id AND f.file_id = 1 WHERE d.name = {} \
             FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES);",
            lit(MARK),
            utc("SYSDATETIME()"),
            lit(db)
        ))?;
        if v.is_null() {
            return Err(error(2, format!("database {db} not found on the instance")));
        }
        Ok(v)
    };
    let s0 = state(h)?;
    let s = |k: &str| s0[k].as_str().map(str::to_owned);
    let dbs = chain::DbState {
        model: s("model").unwrap_or_default(),
        guid: s("guid").unwrap_or_default(),
        last_log: s("last_log"),
        diff_base: s("diff_base"),
    };
    let log_run = ctx.params["mode"].as_str() == Some("log");
    let d = chain::decide(prev.as_ref(), &dbs, log_run, h.cfg.full_days, now());
    match &d.chain_break {
        Some(_) => ctx.warn(format!("{db}: {}", d.why)),
        None => ctx.info(format!("{db}: {}", d.why)),
    }
    let run = now();
    let mut st = match (&prev, d.decision) {
        (Some(p), Decision::Diff | Decision::Log | Decision::Nothing) => p.keep(),
        _ => State {
            guid: dbs.guid.clone(),
            base_time: run,
            ..Default::default()
        },
    };
    h.mkdir_staging()?;
    let mut new: Vec<Piece> = Vec::new();
    let res = (|| -> Result<()> {
        let mut add = |kind: BKind| -> Result<()> {
            let name = format!("{run}_{}_{}.{}", kind.tag(), new.len(), kind.ext());
            new.push(take(h, db, kind, &name, run)?);
            Ok(())
        };
        match d.decision {
            Decision::Full => add(BKind::Full)?,
            Decision::Diff => add(BKind::Diff)?,
            Decision::Log | Decision::Nothing => {}
        }
        if dbs.model != "SIMPLE" && d.decision != Decision::Nothing {
            // the end of the range: everything committed before the log backup starts is in it
            st.to_time = state(h)?["now"].as_u64().unwrap_or(run);
            add(BKind::Log)?;
        }
        Ok(())
    })();
    if let Err(e) = res {
        let _ = h.remove(&format!("{run}_"));
        return Err(e);
    }
    st.absorb(&new, &dbs.model);

    sink.entry(DIR, meta(Kind::Dir, 0, run))?;
    for p in st.pieces.iter().filter(|p| !new.contains(p)) {
        sink.unchanged(format!("mssql/{}", p.name).as_bytes(), meta(Kind::File, p.len, p.mtime))?;
    }
    let total: u64 = new.iter().map(|p| p.len).sum();
    let mut done = 0;
    let res = (|| -> Result<()> {
        for p in &new {
            ctx.progress(done, total, format!("{db}: {}", p.name));
            let mut e = h.get(&h.path(&p.name))?;
            sink.file(
                format!("mssql/{}", p.name).as_bytes(),
                meta(Kind::File, p.len, p.mtime),
                &mut e,
            )?;
            e.finish().with_context(|| format!("reading {}", p.name))?;
            done += p.len;
        }
        Ok(())
    })();
    let _ = h.remove(&format!("{run}_"));
    res?;
    let info = serde_json::to_vec_pretty(&json!({"database": db, "pieces": st.pieces}))?;
    sink.file(
        b"mssql/nexus.json",
        meta(Kind::File, info.len() as u64, run),
        &mut info.as_slice(),
    )?;

    let mut m = json!({"recoverable": st.range()});
    if let Some(b) = d.chain_break {
        m["chain_break"] = json!(b);
    }
    let summary = format!(
        "{db}: {} ({} new files, {total} bytes), {} files in the snapshot, recoverable to {}",
        d.decision.what(),
        new.len(),
        st.pieces.len() + 1,
        chain::fmt_time(st.to_time)
    );
    Ok((st, m, summary))
}

/// Point-in-time restore (`pitr`) into a new database (or over an existing one with `replace` and the name typed
/// again), or a restore test (`verify`): into `nexus_verify_<time>`, checked, dropped.
fn restore(ctx: &Ctx, src: &mut Source, h: &Host, verify: bool) -> Result<String> {
    let p = &ctx.params["params"];
    let snap = ctx.params["snapshot"]["time"].as_u64().unwrap_or_else(now);
    let target = if verify {
        format!("nexus_verify_{snap}")
    } else {
        p["database"].as_str().unwrap_or_default().to_owned()
    };
    if !db_ok(&target) {
        return Err(error(22, "params.database: [A-Za-z0-9._-]{1,64}"));
    }
    let replace = !verify && p["replace"].as_bool().unwrap_or(false);
    if replace && p["confirm"].as_str() != Some(target.as_str()) {
        return Err(error(22, format!("replacing {target}: type its name to confirm")));
    }
    let stopat = match p["target_time"].as_str().filter(|s| !s.is_empty()) {
        Some(t) => Some(chain::parse_time(t).ok_or_else(|| error(22, "target_time: YYYY-MM-DD HH:MM:SS+00"))?),
        None => None,
    };
    let mut info = Value::Null;
    src.files(&[b"mssql/nexus.json".to_vec()], |_, data| {
        let mut b = Vec::new();
        data.read_to_end(&mut b)?;
        info = serde_json::from_slice(&b)?;
        Ok(())
    })?;
    let pieces: Vec<Piece> = serde_json::from_value(info["pieces"].clone()).context("mssql/nexus.json")?;
    let seq = chain::restore_sequence(&pieces, stopat).map_err(|e| error(22, format!("{e:#}")))?;
    let source_db = info["database"].as_str().unwrap_or_default().to_owned();
    let dir = format!("restore-{snap}-{}", now());
    let res = (|| -> Result<Value> {
        let paths: Vec<Vec<u8>> = seq.iter().map(|p| format!("mssql/{}", p.name).into_bytes()).collect();
        let mut bytes = 0;
        src.files(&paths, |item, data| {
            let name = String::from_utf8_lossy(&item.path)
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned();
            if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
                bail!("unexpected file name {name:?}");
            }
            bytes += h.put(&h.path(&format!("{dir}{}{name}", h.sep())), data)?;
            Ok(())
        })?;
        ctx.info(format!(
            "{} files ({bytes} bytes) uploaded; restoring {source_db} into {target}{}",
            seq.len(),
            stopat
                .map(|t| format!(" as of {}", chain::fmt_time(t)))
                .unwrap_or_default()
        ));
        h.json(&restore_batch(h, &seq, &target, &source_db, &dir, stopat, replace)?)
    })();
    let _ = h.remove(&dir);
    let r = res?;
    if verify {
        let check = p["sql"].as_str().filter(|s| !s.trim().is_empty()).map(|q| {
            h.sql(&format!("SET NOCOUNT ON; USE {};\n{q}", br(&target)))
                .map(|rows| rows.first().and_then(|r| r.first()).cloned().unwrap_or_default())
        });
        let drop = h.sql(&format!(
            "ALTER DATABASE {t} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {t};",
            t = br(&target)
        ));
        let v = match check {
            Some(Ok(v)) if truthy(&v) => format!(", the SQL check returned {v}"),
            Some(Ok(v)) => bail!("the SQL check returned {v:?}, not true"),
            Some(Err(e)) => bail!("the SQL check failed: {e:#}"),
            None => String::new(),
        };
        drop.context("dropping the test database")?;
        return Ok(format!(
            "restore test passed: {} files restored into {target} ({} tables, CHECKDB clean){v}, dropped again",
            seq.len(),
            r["tables"]
        ));
    }
    Ok(format!(
        "{source_db} restored into {target}{}: {} files, {} tables",
        stopat
            .map(|t| format!(" as of {}", chain::fmt_time(t)))
            .unwrap_or_default(),
        seq.len(),
        r["tables"]
    ))
}

/// The T-SQL of a restore: the files in order, NORECOVERY until the last, STOPAT on the logs, the data and log
/// files moved to the instance's default paths under the target's name when it is not the source database.
fn restore_batch(
    h: &Host,
    seq: &[Piece],
    target: &str,
    source_db: &str,
    dir: &str,
    stopat: Option<u64>,
    replace: bool,
) -> Result<String> {
    let t = br(target);
    let file = |p: &Piece| lit(&h.path(&format!("{dir}{}{}", h.sep(), p.name)));
    let mut b = String::new();
    if let Some(s) = stopat {
        b += &format!(
            "DECLARE @stop datetime2 = DATEADD(minute, DATEDIFF(minute, SYSUTCDATETIME(), SYSDATETIME()), \
             DATEADD(second, {}, DATEADD(day, {}, '19700101')));\n",
            s % 86400,
            s / 86400
        );
    }
    if replace {
        b += &format!(
            "IF DB_ID({}) IS NOT NULL ALTER DATABASE {t} SET SINGLE_USER WITH ROLLBACK IMMEDIATE;\n",
            lit(target)
        );
    }
    let mut mv = String::new();
    if target != source_db {
        let files = seq.first().map(|p| p.files.clone()).unwrap_or_default();
        if files.is_empty() {
            bail!("the full backup's file list is missing (snapshot from an older plugin): restore under the source's name");
        }
        b += "DECLARE @d nvarchar(400) = CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(400)), \
              @l nvarchar(400) = CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(400));\n";
        for (i, f) in files.iter().enumerate() {
            let ext = f.p.rsplit_once('.').map_or("dat", |x| x.1);
            let ext: String = ext.chars().filter(char::is_ascii_alphanumeric).take(8).collect();
            let dirv = if f.t == "L" { "@l" } else { "@d" };
            b += &format!(
                "DECLARE @m{i} nvarchar(800) = {dirv} + {};\n",
                lit(&format!("{target}_{i}.{ext}"))
            );
            mv += &format!(", MOVE {} TO @m{i}", lit(&f.l));
        }
    }
    for (i, p) in seq.iter().enumerate() {
        let rec = if i + 1 == seq.len() { "RECOVERY" } else { "NORECOVERY" };
        b += &match (i, p.kind) {
            (_, BKind::Log) => format!(
                "RESTORE LOG {t} FROM DISK = {} WITH {rec}{};\n",
                file(p),
                if stopat.is_some() { ", STOPAT = @stop" } else { "" }
            ),
            (0, _) => format!(
                "RESTORE DATABASE {t} FROM DISK = {} WITH {rec}{}{mv};\n",
                file(p),
                if replace { ", REPLACE" } else { "" }
            ),
            _ => format!("RESTORE DATABASE {t} FROM DISK = {} WITH {rec};\n", file(p)),
        };
    }
    if replace {
        b += &format!("ALTER DATABASE {t} SET MULTI_USER;\n");
    }
    b += &format!("DBCC CHECKDB ({}) WITH NO_INFOMSGS;\n", lit(target));
    b += &format!(
        "SELECT {} + (SELECT COUNT(*) AS tables FROM {t}.sys.tables WHERE is_ms_shipped = 0 FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);",
        lit(MARK)
    );
    Ok(b)
}

fn truthy(v: &str) -> bool {
    let v = v.trim();
    matches!(v, "t" | "true" | "True") || v.parse::<f64>().is_ok_and(|n| n != 0.0)
}

fn main() {
    plugin_sdk::run(Mssql)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config() {
        let c = Config::of(&json!({"host": "h", "user": "u", "instance": "SQLEXPRESS"})).unwrap();
        assert_eq!(c.server, ".\\SQLEXPRESS");
        assert_eq!(c.staging, "C:\\NexusBackup\\staging");
        assert!(Config::of(&json!({"instance": "a;b"})).is_err());
        for bad in ["C:\\a b", "C:\\a'b", "relative", "C:\\a\\..\\b", "\\\\srv\\share"] {
            assert!(!win_path_ok(bad), "{bad}");
        }
        assert!(win_path_ok("D:\\sql-staging\\nexus"));
        let l = Config::of(&json!({"platform": "linux", "container": "mssql1", "sql_user": "sa"})).unwrap();
        assert_eq!(l.staging, "/var/opt/mssql/nexus-staging");
        let Platform::Linux { prefix, .. } = &l.platform else {
            panic!()
        };
        assert_eq!(prefix, "docker exec -i -e SQLCMDPASSWORD mssql1 ");
        assert!(Config::of(&json!({"platform": "linux", "sql_user": "sa", "container": "a;b"})).is_err());
        assert!(Config::of(&json!({"platform": "linux", "sql_user": "sa", "container_cli": "rm -rf"})).is_err());
        assert!(Config::of(&json!({"platform": "linux"})).is_err());
        assert!(truthy("1") && truthy("True") && !truthy("0"));
        assert_eq!(lit("a'b"), "N'a''b'");
        assert_eq!(br("a]b"), "[a]]b]");
        assert_eq!(
            without_headers("n\tm\n-----\t---\n1\t2\n\n\n------\n#NEXUS#{}"),
            "1\t2\n\n#NEXUS#{}"
        );
    }
}
