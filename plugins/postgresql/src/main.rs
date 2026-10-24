//! PostgreSQL reference plugin (docs/plugin-system.md "Milestone M9", plugins/postgresql/README.md).
//!
//! Guests are databases: a group with databases gets one logical dump per database
//! (stream `<db>.sql`, restorable to the source or an alternate server); a group
//! without guests backs up the whole cluster physically (base backup + WAL from a
//! replication slot, point-in-time restore over SSH). Everything speaks the wire
//! protocol in Rust (`pg.rs`): the sandbox can only run what the appliance image
//! ships, and pg_dump/pg_basebackup must match the server's major version anyway.
//! With several servers (`hosts`, ha.rs) every backup runs against the primary.

mod dump;
mod ha;
mod pg;
mod physical;
mod pitr;
mod ssh;

use anyhow::{bail, Context, Result};
use pg::{ident, lit, Conn, Opts, SslMode};
use plugin_sdk::sink::glob;
use plugin_sdk::{error, BackupResult, Ctx, Guest, Plugin, Sink, Source, Validation};
use std::io::BufReader;

#[derive(Default)]
struct Postgres {
    /// the source server (with `hosts`: the primary), resolved once per run
    server: Option<(String, u16)>,
}

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

impl Postgres {
    /// The server to back up from: `host`, or with `hosts` the primary among them
    /// (`pg_is_in_recovery()` = false; logged with the state of every server).
    fn server(&mut self, ctx: &Ctx) -> Result<(String, u16)> {
        if let Some(s) = &self.server {
            return Ok(s.clone());
        }
        let cands = ha::candidates(&ctx.config);
        let s = match cands.as_slice() {
            [] => return Err(error(22, "config: host missing")),
            [one] => one.clone(),
            _ => {
                let (i, report) = ha::pick_primary(&cands, |(host, port)| {
                    let o = Opts {
                        host: host.clone(),
                        port: *port,
                        ..opts(ctx, "", "postgres", false)?
                    };
                    let mut c = Conn::connect(&o)?;
                    let v = c.value("SELECT pg_is_in_recovery()")?;
                    c.close();
                    Ok(v.as_deref() == Some("t"))
                })
                .map_err(|r| error(113, r))?;
                ctx.info(format!("servers: {report}"));
                cands[i].clone()
            }
        };
        self.server = Some(s.clone());
        Ok(s)
    }

    /// Connection options for the source server (see [`Postgres::server`]).
    fn src(&mut self, ctx: &Ctx, dbname: &str, replication: bool) -> Result<Opts> {
        let (host, port) = self.server(ctx)?;
        Ok(Opts {
            host,
            port,
            ..opts(ctx, "", dbname, replication)?
        })
    }
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
        let multi = ha::candidates(&ctx.config).len() > 1;
        let o = match self.src(ctx, "postgres", false) {
            Ok(o) => o,
            Err(e) if multi => return Ok(invalid("hosts", format!("{e:#}"))),
            Err(e) => return Err(e),
        };
        let mut c = match Conn::connect(&o) {
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
        match Conn::connect(&self.src(ctx, "", true)?).and_then(|mut r| r.exec("IDENTIFY_SYSTEM")) {
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
        let mut c = Conn::connect(&self.src(ctx, "postgres", false)?)?;
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
            let (repl, sql) = (self.src(ctx, "", true)?, self.src(ctx, "postgres", false)?);
            let r = physical::backup(ctx, sink, &repl, &sql, &slot(ctx)?, days)?;
            sink.snapshot_meta(&r.meta)?;
            let from = if ha::candidates(&ctx.config).len() > 1 {
                format!(" (from {})", ha::show(&(repl.host, repl.port)))
            } else {
                String::new()
            };
            return Ok(BackupResult {
                state: Some(serde_json::to_vec(&r.state)?),
                consistent: true,
                summary: format!("{}{from}", r.summary),
            });
        };
        let mut c = Conn::connect(&self.src(ctx, db, false)?)?;
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
            Some("to_target") => restore_dump(self, ctx, src),
            Some("pitr") => pitr::pitr(ctx, &ctx.params["params"], src, &ssh_of(ctx)?),
            // restore test (Phase 44): a dump into a throwaway database, a cluster snapshot
            // point-in-time into a throwaway directory; checked and removed again
            Some("verify") if ctx.guest().is_some() || has_dump(ctx) => restore_dump(self, ctx, src),
            Some("verify") => pitr::verify(ctx, src, &ssh_of(ctx)?),
            r => Err(error(95, format!("unknown restore {r:?}"))),
        }
    }
}

fn has_dump(ctx: &Ctx) -> bool {
    ctx.params["streams"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|s| s["name"].as_str().is_some_and(|n| n.ends_with(".sql")))
}

/// A logical dump into a (new) database on the source or the alternate server. As a
/// restore test (`verify`): into `nexus_verify_<time>` on the alternate server if there
/// is one (else the source), the rows of every table counted against the dump, dropped.
fn restore_dump(pg: &mut Postgres, ctx: &Ctx, src: &mut Source) -> Result<String> {
    let verify = ctx.params["restore"] == "verify";
    let p = &ctx.params["params"];
    let db = if verify {
        format!(
            "nexus_verify_{}",
            ctx.params["snapshot"]["time"].as_i64().unwrap_or_default()
        )
    } else {
        p["database"].as_str().unwrap_or_default().to_owned()
    };
    if db.is_empty() || db.len() > 63 {
        return Err(error(22, "params.database: 1..63 characters"));
    }
    let alternate = if verify {
        ctx.config["restore_host"].as_str().is_some_and(|h| !h.is_empty())
    } else {
        p["server"].as_str() == Some("alternate")
    };
    let prefix = if alternate { "restore_" } else { "" };
    let stream = ctx.params["streams"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["name"].as_str())
        .find(|n| n.ends_with(".sql"))
        .context("this snapshot holds no database dump (restore a cluster snapshot point-in-time)")?
        .to_owned();
    let into_existing = !verify && p["into_existing"].as_bool().unwrap_or(false);
    // the source server = its primary (HA)
    let admin_opts = if prefix.is_empty() {
        pg.src(ctx, "postgres", false)?
    } else {
        opts(ctx, prefix, "postgres", false)?
    };
    let mut admin = Conn::connect(&admin_opts)?;
    let exists = !admin
        .query(&format!("SELECT 1 FROM pg_database WHERE datname = {}", lit(&db)))?
        .is_empty();
    if exists && !into_existing {
        return Err(error(
            17,
            format!("database {db:?} exists on the target (choose another name or restore into it)"),
        ));
    }
    let (mut summary, mut sql_value) = (None, None);
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
        let o = Opts {
            dbname: db.clone(),
            ..admin_opts.clone()
        };
        let res = Conn::connect(&o).and_then(|mut c| {
            let st = dump::restore(&mut c, &mut r)?;
            if verify {
                dump::check_tables(&mut c, &st)?;
                if let Some(sql) = p["sql"].as_str() {
                    sql_value = Some(sql_check(&mut c, sql)?);
                }
            }
            Ok(st)
        });
        if (res.is_err() || verify) && !exists {
            // leave nothing half-restored behind
            let _ = admin.exec(&format!("DROP DATABASE IF EXISTS {}", ident(&db)));
        }
        summary = Some(res?);
        Ok(())
    })?;
    let st = summary.context("the dump stream is missing from the snapshot")?;
    if verify {
        return Ok(format!(
            "restore test passed: {stream} restored into {db} on the {} server, {} tables with {} rows compared \
             with the dump (counts and contents){}, dropped again",
            if alternate { "alternate" } else { "source" },
            st.tables,
            st.rows,
            sql_value
                .map(|v| format!(", the SQL check returned {v}"))
                .unwrap_or_default()
        ));
    }
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

/// The group's SQL check of a restore test (#45): one query in a read-only transaction on the restored
/// database; passes when the first value of its first row is true or not zero.
fn sql_check(c: &mut Conn, sql: &str) -> Result<String> {
    let q = sql.trim().trim_end_matches(';');
    if q.trim().is_empty() || q.contains(';') || sql.len() > 4000 {
        bail!("the SQL check must be one query of at most 4000 characters (a `;` only at the end)");
    }
    c.exec("BEGIN READ ONLY")?;
    let rows = c.query(q);
    c.exec("ROLLBACK")?;
    let v = rows
        .context("the SQL check failed")?
        .into_iter()
        .next()
        .and_then(|r| r.into_iter().next())
        .flatten();
    match v {
        Some(v) if truthy(&v) => Ok(v),
        v => bail!(
            "the SQL check returned {}, not true: {q}",
            v.as_deref().unwrap_or("no value")
        ),
    }
}

/// `t`/`true` or a number other than zero.
fn truthy(v: &str) -> bool {
    let v = v.trim();
    matches!(v, "t" | "true") || v.parse::<f64>().is_ok_and(|n| n != 0.0)
}

fn main() {
    plugin_sdk::run(Postgres::default())
}

#[cfg(test)]
mod tests {
    use super::rewrap_pem;

    #[test]
    fn sql_check_values() {
        for v in ["t", "true", "1", "412", "0.5"] {
            assert!(super::truthy(v), "{v}");
        }
        for v in ["f", "false", "0", "0.0", "", "yes"] {
            assert!(!super::truthy(v), "{v}");
        }
    }

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
