//! MySQL / MariaDB plugin (docs/mysql.md).
//!
//! Guests are databases: a group with databases gets one logical dump per database
//! (stream `<db>.sql`, restorable to the source or an alternate server), made by
//! mysqldump / mariadb-dump on the database host over SSH or generated over the
//! connection (TLS, `dump.rs`); a group without guests backs up the whole server
//! physically (mariadb-backup / XtraBackup over SSH) plus its binary log pulled over
//! the connection, for point-in-time restores over SSH (`physical.rs`, `pitr.rs`).
//! The SQL connection is the client protocol in Rust (`my.rs`): the sandbox can
//! only run what the appliance image ships.

mod dump;
mod my;
mod physical;
mod pitr;
mod ssh;

use anyhow::{Context, Result};
use my::{ident, lit_str, Conn, Opts, SslMode};
use plugin_sdk::sink::glob;
use plugin_sdk::{error, BackupResult, Ctx, Guest, Plugin, Sink, Source, Validation};
use std::io::{BufReader, Write};

struct Mysql;

/// A PEM block pasted into a single-line (password) field loses its line breaks: rebuild them.
pub(crate) fn rewrap_pem(s: &str) -> String {
    if s.contains('\n') {
        return s.to_owned();
    }
    let mut out = String::new();
    let mut rest = s.trim();
    while let Some(b) = rest.find("-----BEGIN ") {
        let after = &rest[b + 11..];
        let Some(l) = after.find("-----") else { break };
        let label = &after[..l];
        let footer = format!("-----END {label}-----");
        let Some(e) = after.find(&footer) else { break };
        let body: String = after[l + 5..e].split_whitespace().collect();
        out += &format!("-----BEGIN {label}-----\n");
        for c in body.as_bytes().chunks(64) {
            out += std::str::from_utf8(c).unwrap_or_default();
            out.push('\n');
        }
        out += &footer;
        out.push('\n');
        rest = &after[e + footer.len()..];
    }
    if out.is_empty() {
        s.to_owned()
    } else {
        out
    }
}

/// Connection options for the source (`prefix` "") or the alternate restore server ("restore_").
fn opts(ctx: &Ctx, prefix: &str, dbname: &str) -> Result<Opts> {
    let c = &ctx.config;
    let get = |k: &str| c[format!("{prefix}{k}")].as_str().unwrap_or_default().to_owned();
    let host = get("host");
    if host.is_empty() {
        return Err(error(22, format!("config: {prefix}host missing")));
    }
    Ok(Opts {
        host,
        port: c[format!("{prefix}port")].as_u64().unwrap_or(3306) as u16,
        user: get("user"),
        password: get("password"),
        dbname: dbname.into(),
        ssl: match c["sslmode"].as_str().unwrap_or("require") {
            "disable" => SslMode::Disable,
            "verify-full" => SslMode::VerifyFull,
            _ => SslMode::Require,
        },
        ca_cert: c["ca_cert"].as_str().map(str::to_owned),
    })
}

fn strings(ctx: &Ctx, key: &str) -> Vec<String> {
    ctx.config[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

fn has_ssh(ctx: &Ctx) -> bool {
    ctx.config["ssh_host"].as_str().is_some_and(|h| !h.is_empty())
}

fn ssh_of(ctx: &Ctx) -> Result<ssh::Ssh> {
    let c = &ctx.config;
    if !has_ssh(ctx) {
        return Err(error(
            22,
            "server backups and physical restores need SSH to the database host (ssh_host …) in the source",
        ));
    }
    ssh::Ssh::connect(
        c["ssh_host"].as_str().unwrap_or_default(),
        c["ssh_port"].as_u64().unwrap_or(22) as u16,
        c["ssh_user"].as_str().unwrap_or("mysql"),
        c["ssh_key"].as_str().unwrap_or_default(),
        c["ssh_host_key"].as_str().unwrap_or_default(),
    )
}

/// Dumps over SSH (`dump_via`: auto = SSH when configured).
fn dump_over_ssh(ctx: &Ctx) -> bool {
    match ctx.config["dump_via"].as_str().unwrap_or("auto") {
        "ssh" => true,
        "connection" => false,
        _ => has_ssh(ctx),
    }
}

fn dump_tool(c: &Conn) -> &'static str {
    if c.mariadb {
        "t=$(command -v mariadb-dump || command -v mysqldump) || { echo 'mariadb-dump not found' >&2; exit 127; }"
    } else {
        "t=$(command -v mysqldump) || { echo 'mysqldump not found' >&2; exit 127; }"
    }
}

fn invalid(field: &str, message: impl Into<String>) -> Validation {
    Validation::Invalid {
        field: field.into(),
        message: message.into(),
    }
}

/// The config field a connection error is about.
fn field_of(e: &anyhow::Error, prefix: &str) -> String {
    let f = match my::code(e) {
        Some(1045) => "password",
        Some(1044 | 1227 | 1251) => "user",
        Some(_) => "host",
        None if format!("{e:#}").contains("TLS") || format!("{e:#}").to_lowercase().contains("certificate") => {
            return "sslmode".into()
        }
        None if format!("{e:#}").contains("authentication") => "user",
        None => "host",
    };
    format!("{prefix}{f}")
}

/// Tables of non-transactional engines in the connection's database.
fn non_transactional(c: &mut Conn) -> Result<Vec<String>> {
    Ok(c
        .query(
            "SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() \
             AND TABLE_TYPE = 'BASE TABLE' AND ENGINE NOT IN ('InnoDB', 'ROCKSDB') ORDER BY TABLE_NAME",
        )?
        .into_iter()
        .map(|r| {
            let get = |i: usize| r.get(i).cloned().flatten().unwrap_or_default();
            format!("{} ({})", get(0), get(1))
        })
        .collect())
}

/// Current binlog position (`SHOW BINARY LOG STATUS` on MySQL 8.4, `SHOW MASTER STATUS` before).
fn binlog_status(c: &mut Conn) -> Result<Option<(String, u64)>> {
    let r = match c.query("SHOW BINARY LOG STATUS") {
        Ok(r) => r,
        Err(_) => c.query("SHOW MASTER STATUS")?,
    };
    Ok(r.into_iter().next().and_then(|r| {
        let f = r.first().cloned().flatten()?;
        let p = r.get(1).cloned().flatten()?.parse().ok()?;
        Some((f, p))
    }))
}

impl Plugin for Mysql {
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
        let mut c = match Conn::connect(&opts(ctx, "", "")?) {
            Ok(c) => c,
            Err(e) => return Ok(invalid(&field_of(&e, ""), format!("{e:#}"))),
        };
        let (major, minor) = c.version;
        if (c.mariadb && (major, minor) < (10, 6)) || (!c.mariadb && major < 8) {
            return Ok(invalid(
                "host",
                format!("{} is not supported (MySQL 8.0 / MariaDB 10.6 or newer)", c.server_version),
            ));
        }
        if let Err(e) = c.query("SHOW DATABASES") {
            return Ok(invalid("user", format!("{e:#}")));
        }
        if physical::binlog_on(&mut c)? {
            // what a server backup needs: list the binlogs and pull from the current end
            let pos = match binlog_status(&mut c).and_then(|p| p.context("no binlog status")) {
                Ok(p) => p,
                Err(e) => {
                    return Ok(invalid(
                        "user",
                        format!("binlog status refused (REPLICATION CLIENT / BINLOG MONITOR): {e:#}"),
                    ))
                }
            };
            if let Err(e) = physical::pull(&mut c, &pos.0, pos.1, |_, _, _| Ok(())) {
                return Ok(invalid(
                    "user",
                    format!("binlog pull refused (the account needs REPLICATION SLAVE): {e:#}"),
                ));
            }
        }
        c.close();
        if ctx.config["restore_host"].as_str().is_some_and(|h| !h.is_empty()) {
            if let Err(e) = Conn::connect(&opts(ctx, "restore_", "")?) {
                return Ok(invalid(&field_of(&e, "restore_"), format!("{e:#}")));
            }
        }
        if has_ssh(ctx) {
            if let Err(e) = ssh_of(ctx).and_then(|s| s.run("true")) {
                return Ok(invalid("ssh_host", format!("{e:#}")));
            }
        } else if ctx.config["dump_via"].as_str() == Some("ssh") {
            return Ok(invalid("dump_via", "dumps over SSH need the SSH settings (ssh_host …)"));
        }
        Ok(Validation::Valid)
    }

    fn list_guests(&mut self, ctx: &Ctx) -> Result<Vec<Guest>> {
        let mut c = Conn::connect(&opts(ctx, "", "")?)?;
        let rows = c.query(
            "SELECT s.SCHEMA_NAME, SUM(t.DATA_LENGTH + t.INDEX_LENGTH) FROM information_schema.SCHEMATA s \
             LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = s.SCHEMA_NAME \
             WHERE s.SCHEMA_NAME NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys') \
             GROUP BY s.SCHEMA_NAME ORDER BY s.SCHEMA_NAME",
        )?;
        let (inc, exc) = (strings(ctx, "databases_include"), strings(ctx, "databases_exclude"));
        let mut out = Vec::new();
        for r in rows {
            let name = r.first().cloned().flatten().unwrap_or_default();
            let m = |p: &String| glob(p.as_bytes(), name.as_bytes());
            if (!inc.is_empty() && !inc.iter().any(m)) || exc.iter().any(m) {
                continue;
            }
            if !plugin_sdk::proto::valid_guest_id(&name) || name.starts_with('-') {
                ctx.warn(format!(
                    "database {name:?} skipped: names must be [A-Za-z0-9._-]{{1,64}} (not starting with -)"
                ));
                continue;
            }
            let size = r.get(1).cloned().flatten().and_then(|s| s.parse().ok());
            out.push(Guest {
                title: name.clone(),
                id: name,
                size,
            });
        }
        Ok(out)
    }

    fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
        let Some(db) = ctx.guest() else {
            let days = ctx.config["full_every_days"].as_u64().unwrap_or(7).max(1);
            let r = physical::backup(ctx, sink, &opts(ctx, "", "")?, || ssh_of(ctx), days)?;
            sink.snapshot_meta(&r.meta)?;
            return Ok(BackupResult {
                state: Some(serde_json::to_vec(&r.state)?),
                consistent: true,
                summary: r.summary,
            });
        };
        if db.starts_with('-') {
            return Err(error(22, format!("database name {db:?}")));
        }
        let mut c = Conn::connect(&opts(ctx, "", db)?)?;
        let mut s = sink.stream(&format!("{db}.sql"))?;
        let (summary, mut nt) = if dump_over_ssh(ctx) {
            let nt = non_transactional(&mut c)?;
            s.write_all(dump::header(&mut c, db)?.as_bytes())?;
            let ssh = ssh_of(ctx)?;
            let cnf = ssh::defaults_file(&ctx.config["user"].as_str().unwrap_or_default(), ctx.config["password"].as_str().unwrap_or_default());
            let extra = if c.mariadb { "" } else { " --set-gtid-purged=OFF" };
            let mut e = ssh.exec(&ssh::with_defaults(
                cnf.len(),
                &format!(
                    "{}; \"$t\" --defaults-extra-file=\"$f\" --single-transaction --routines --triggers --events \
                     --hex-blob --no-tablespaces{extra} {}",
                    dump_tool(&c),
                    ssh::sh_quote(db)
                ),
            ))?;
            e.write_all(cnf.as_bytes())?;
            e.close_stdin()?;
            let n = std::io::copy(&mut e, &mut s)?;
            e.finish().context("dump over SSH")?;
            (format!("dump of {db} over SSH: {n} bytes"), nt)
        } else {
            let st = dump::dump(&mut c, db, &mut s)?;
            if !st.skipped.is_empty() {
                ctx.warn(format!("not in the dump (no privilege to read the definition): {}", st.skipped.join(", ")));
            }
            (
                format!(
                    "dump of {db}: {} tables, {} rows, {} views, {} routines, {} triggers, {} events",
                    st.tables, st.rows, st.views, st.routines, st.triggers, st.events
                ),
                st.non_transactional,
            )
        };
        s.finish()?;
        c.close();
        nt.dedup();
        if !nt.is_empty() {
            ctx.warn(format!(
                "tables of non-transactional engines are not dumped consistently with the rest: {}",
                nt.join(", ")
            ));
        }
        Ok(BackupResult {
            state: None,
            consistent: nt.is_empty(),
            summary,
        })
    }

    fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String> {
        match ctx.params["restore"].as_str() {
            Some("to_target") => restore_dump(ctx, src),
            Some("pitr") => pitr::pitr(ctx, src, &ssh_of(ctx)?),
            r => Err(error(95, format!("unknown restore {r:?}"))),
        }
    }
}

/// A logical dump into a (new) database on the source or the alternate server.
fn restore_dump(ctx: &Ctx, src: &mut Source) -> Result<String> {
    let p = &ctx.params["params"];
    let db = p["database"].as_str().unwrap_or_default().to_owned();
    if db.is_empty() || db.len() > 64 {
        return Err(error(22, "params.database: 1..64 characters"));
    }
    let prefix = match p["server"].as_str().unwrap_or("source") {
        "alternate" => "restore_",
        _ => "",
    };
    let stream = ctx.params["streams"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["name"].as_str())
        .find(|n| n.ends_with(".sql"))
        .context("this snapshot holds no database dump (restore a server snapshot point-in-time)")?
        .to_owned();
    let into_existing = p["into_existing"].as_bool().unwrap_or(false);
    let admin_opts = opts(ctx, prefix, "")?;
    let mut admin = Conn::connect(&admin_opts)?;
    let exists = !admin
        .query(&format!(
            "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = {}",
            lit_str(&db)
        ))?
        .is_empty();
    if exists && !into_existing {
        return Err(error(
            17,
            format!("database {db:?} exists on the target (choose another name or restore into it)"),
        ));
    }
    let mut summary = None;
    src.streams(std::slice::from_ref(&stream), |_, data| {
        let mut r = BufReader::with_capacity(1 << 20, data);
        let h = dump::read_header(&mut r)?;
        if !exists {
            let mut sql = format!("CREATE DATABASE {}", ident(&db));
            let cs = |k: &str| h[k].as_str().filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            if let Some(v) = cs("charset") {
                sql += &format!(" CHARACTER SET {v}");
            }
            if let Some(v) = cs("collation") {
                sql += &format!(" COLLATE {v}");
            }
            admin.exec(&sql)?;
        }
        let o = Opts {
            dbname: db.clone(),
            ..admin_opts.clone()
        };
        let res = Conn::connect(&o).and_then(|mut c| dump::restore(&mut c, &mut r));
        if res.is_err() && !exists {
            // leave nothing half-restored behind
            let _ = admin.exec(&format!("DROP DATABASE IF EXISTS {}", ident(&db)));
        }
        summary = Some(res?);
        Ok(())
    })?;
    let st = summary.context("the dump stream is missing from the snapshot")?;
    Ok(format!(
        "{stream} restored into {db} on {}: {} statements",
        if prefix.is_empty() {
            "the source server"
        } else {
            "the alternate server"
        },
        st.statements
    ))
}

fn main() {
    plugin_sdk::run(Mysql)
}

#[cfg(test)]
mod tests {
    use super::rewrap_pem;

    #[test]
    fn pem_without_line_breaks() {
        let one = "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW QyNTUxOQ== -----END OPENSSH PRIVATE KEY-----";
        assert_eq!(
            rewrap_pem(one),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\nc2gtZWQyNTUxOQ==\n-----END OPENSSH PRIVATE KEY-----\n"
        );
        assert_eq!(rewrap_pem("a\nb"), "a\nb");
    }
}
