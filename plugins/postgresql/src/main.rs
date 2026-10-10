//! PostgreSQL reference plugin (docs/plugin-system.md "Milestone M9", plugins/postgresql/README.md).
//!
//! Guests are databases: a group with databases gets one logical dump per database
//! (stream `<db>.sql`, restorable to the source or an alternate server); a group
//! without guests backs up the whole cluster physically (base backup + WAL from a
//! replication slot, point-in-time restore over SSH). Everything speaks the wire
//! protocol in Rust (`pg.rs`): the sandbox can only run what the appliance image
//! ships, and pg_dump/pg_basebackup must match the server's major version anyway.

mod dump;
mod pg;
mod physical;
mod ssh;

use anyhow::{Context, Result};
use pg::{ident, lit, Conn, Opts, SslMode};
use plugin_sdk::sink::glob;
use plugin_sdk::{error, BackupResult, Ctx, Guest, Plugin, Sink, Source, Validation};
use std::io::BufReader;

struct Postgres;

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
fn opts(ctx: &Ctx, prefix: &str, dbname: &str, replication: bool) -> Result<Opts> {
    let c = &ctx.config;
    let get = |k: &str| c[format!("{prefix}{k}")].as_str().unwrap_or_default().to_owned();
    let host = get("host");
    if host.is_empty() {
        return Err(error(22, format!("config: {prefix}host missing")));
    }
    Ok(Opts {
        host,
        port: c[format!("{prefix}port")].as_u64().unwrap_or(5432) as u16,
        user: get("user"),
        password: get("password"),
        dbname: dbname.into(),
        ssl: match c["sslmode"].as_str().unwrap_or("require") {
            "disable" => SslMode::Disable,
            "verify-full" => SslMode::VerifyFull,
            _ => SslMode::Require,
        },
        ca_cert: c["ca_cert"].as_str().map(str::to_owned),
        replication,
    })
}

fn slot(ctx: &Ctx) -> Result<String> {
    let s = ctx.config["slot"].as_str().unwrap_or("nexusbackup");
    if s.is_empty()
        || s.len() > 63
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(error(22, "config: slot must be [a-z0-9_]{1,63}"));
    }
    Ok(s.into())
}

fn strings(ctx: &Ctx, key: &str) -> Vec<String> {
    ctx.config[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

fn ssh_of(ctx: &Ctx) -> Result<ssh::Ssh> {
    let c = &ctx.config;
    let host = c["ssh_host"].as_str().unwrap_or_default();
    if host.is_empty() {
        return Err(error(
            22,
            "point-in-time restore needs the restore host's SSH settings (ssh_host …) in the source",
        ));
    }
    ssh::Ssh::connect(
        host,
        c["ssh_port"].as_u64().unwrap_or(22) as u16,
        c["ssh_user"].as_str().unwrap_or("postgres"),
        c["ssh_key"].as_str().unwrap_or_default(),
        c["ssh_host_key"].as_str().unwrap_or_default(),
    )
}

fn invalid(field: &str, message: impl Into<String>) -> Validation {
    Validation::Invalid {
        field: field.into(),
        message: message.into(),
    }
}

/// The config field a connection error is about.
fn field_of(e: &anyhow::Error, prefix: &str) -> String {
    let f = match pg::sqlstate(e) {
        Some("28P01") => "password",
        Some(c) if c.starts_with("28") => "user",
        Some(_) => "host",
        None if format!("{e:#}").contains("TLS") || format!("{e:#}").to_lowercase().contains("certificate") => {
            return "sslmode".into()
        }
        None => "host",
    };
    format!("{prefix}{f}")
}

impl Plugin for Postgres {
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
        if let Err(e) = slot(ctx) {
            return Ok(invalid("slot", e.to_string()));
        }
        let mut c = match Conn::connect(&opts(ctx, "", "postgres", false)?) {
            Ok(c) => c,
            Err(e) => return Ok(invalid(&field_of(&e, ""), format!("{e:#}"))),
        };
        if c.major < 14 {
            return Ok(invalid(
                "host",
                format!("PostgreSQL {} is not supported (14 or newer)", c.server_version),
            ));
        }
        let r = c.query(
            "SELECT rolsuper, rolreplication, pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') \
             FROM pg_roles WHERE rolname = current_user",
        )?;
        let flag = |i: usize| r.first().and_then(|r| r.get(i).cloned().flatten()).as_deref() == Some("t");
        if !flag(0) && !flag(1) {
            return Ok(invalid(
                "user",
                "the role needs the REPLICATION attribute (base backup + WAL)",
            ));
        }
        if !flag(0) && !flag(2) {
            return Ok(invalid("user", "the role needs pg_read_all_data (logical dumps)"));
        }
        c.close();
        match Conn::connect(&opts(ctx, "", "", true)?).and_then(|mut r| r.exec("IDENTIFY_SYSTEM")) {
            Ok(()) => {}
            Err(e) => {
                return Ok(invalid(
                    "user",
                    format!("replication connection refused (pg_hba.conf needs a `replication` entry): {e:#}"),
                ))
            }
        }
        if ctx.config["restore_host"].as_str().is_some_and(|h| !h.is_empty()) {
            if let Err(e) = Conn::connect(&opts(ctx, "restore_", "postgres", false)?) {
                return Ok(invalid(&field_of(&e, "restore_"), format!("{e:#}")));
            }
        }
        if ctx.config["ssh_host"].as_str().is_some_and(|h| !h.is_empty()) {
            if let Err(e) = ssh_of(ctx).and_then(|s| s.run("true")) {
                return Ok(invalid("ssh_host", format!("{e:#}")));
            }
        }
        Ok(Validation::Valid)
    }

    fn list_guests(&mut self, ctx: &Ctx) -> Result<Vec<Guest>> {
        let mut c = Conn::connect(&opts(ctx, "", "postgres", false)?)?;
        let rows = c.query(
            "SELECT datname, CASE WHEN has_database_privilege(datname, 'CONNECT') THEN pg_database_size(datname) END \
             FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname",
        )?;
        let (inc, exc) = (strings(ctx, "databases_include"), strings(ctx, "databases_exclude"));
        let mut out = Vec::new();
        for r in rows {
            let name = r.first().cloned().flatten().unwrap_or_default();
            let m = |p: &String| glob(p.as_bytes(), name.as_bytes());
            if (!inc.is_empty() && !inc.iter().any(m)) || exc.iter().any(m) {
                continue;
            }
            if !plugin_sdk::proto::valid_guest_id(&name) {
                ctx.warn(format!(
                    "database {name:?} skipped: names must be [A-Za-z0-9._-]{{1,64}}"
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
            let r = physical::backup(ctx, sink, &opts(ctx, "", "", true)?, &slot(ctx)?, days)?;
            return Ok(BackupResult {
                state: Some(serde_json::to_vec(&r.state)?),
                consistent: true,
                summary: r.summary,
            });
        };
        let mut c = Conn::connect(&opts(ctx, "", db, false)?)?;
        let mut s = sink.stream(&format!("{db}.sql"))?;
        let st = dump::dump(&mut c, &mut s)?;
        s.finish()?;
        c.close();
        if !st.unsupported.is_empty() {
            ctx.warn(format!("not in the logical dump: {}", st.unsupported.join(", ")));
        }
        Ok(BackupResult::consistent(format!(
            "dump of {db}: {} statements, {} tables, {} rows",
            st.statements, st.tables, st.rows
        )))
    }

    fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String> {
        match ctx.params["restore"].as_str() {
            Some("to_target") => restore_dump(ctx, src),
            Some("pitr") => physical::pitr(ctx, src, &ssh_of(ctx)?),
            r => Err(error(95, format!("unknown restore {r:?}"))),
        }
    }
}

/// A logical dump into a (new) database on the source or the alternate server.
fn restore_dump(ctx: &Ctx, src: &mut Source) -> Result<String> {
    let p = &ctx.params["params"];
    let db = p["database"].as_str().unwrap_or_default().to_owned();
    if db.is_empty() || db.len() > 63 {
        return Err(error(22, "params.database: 1..63 characters"));
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
        .context("this snapshot holds no database dump (restore a cluster snapshot point-in-time)")?
        .to_owned();
    let into_existing = p["into_existing"].as_bool().unwrap_or(false);
    let mut admin = Conn::connect(&opts(ctx, prefix, "postgres", false)?)?;
    let exists = !admin
        .query(&format!("SELECT 1 FROM pg_database WHERE datname = {}", lit(&db)))?
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
        let enc = dump::read_header(&mut r)?;
        if !exists {
            admin.exec(&format!(
                "CREATE DATABASE {} TEMPLATE template0 ENCODING {}",
                ident(&db),
                lit(&enc)
            ))?;
        }
        let res = Conn::connect(&opts(ctx, prefix, &db, false)?).and_then(|mut c| dump::restore(&mut c, &mut r));
        if res.is_err() && !exists {
            // leave nothing half-restored behind
            let _ = admin.exec(&format!("DROP DATABASE IF EXISTS {}", ident(&db)));
        }
        summary = Some(res?);
        Ok(())
    })?;
    let st = summary.context("the dump stream is missing from the snapshot")?;
    Ok(format!(
        "{stream} restored into {db} on {}: {} statements, {} tables, {} rows",
        if prefix.is_empty() {
            "the source server"
        } else {
            "the alternate server"
        },
        st.statements,
        st.tables,
        st.rows
    ))
}

fn main() {
    plugin_sdk::run(Postgres)
}

#[cfg(test)]
mod tests {
    use super::rewrap_pem;

    #[test]
    fn pem_without_line_breaks() {
        let one = "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW QyNTUxOQ== -----END OPENSSH PRIVATE KEY-----";
        let w = rewrap_pem(one);
        assert_eq!(
            w,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\nc2gtZWQyNTUxOQ==\n-----END OPENSSH PRIVATE KEY-----\n"
        );
        assert_eq!(rewrap_pem("a\nb"), "a\nb");
        assert_eq!(rewrap_pem("garbage"), "garbage");
    }
}
