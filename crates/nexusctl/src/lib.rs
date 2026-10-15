//! `nexusctl`: a small command-line client for the appliance API (Phase 23a,
//! Veeam comparison row 10). It authenticates with an API token (`nxt_…`,
//! Account → API tokens) and reaches exactly what tokens may reach (the API
//! description: `nexusctl openapi`, or `/api/openapi.json`).
//!
//! Configuration: `--url` / `NEXUS_URL` (`https://backup.example.com[:port]`),
//! `--token` / `NEXUS_TOKEN`, `--ca` / `NEXUS_CA` (PEM file of a private CA or the
//! appliance's self-signed certificate; the system roots are used too). `http://`
//! only for loopback (tests, an SSH tunnel). Output: aligned columns, or the API's
//! JSON with `--json`.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

pub mod fleet;

pub const USAGE: &str = "nexusctl — NexusBackup appliance API client (API tokens)

usage: nexusctl [--url URL] [--token TOKEN] [--ca PEMFILE] [--json] <command> [options]

commands:
  jobs [--state S] [--kind K] [--tenant T] [--limit N]   list jobs, newest first
  job <id> [--log]                                        one job's status (and log)
  snapshots [--tenant T] [--source S]                     list snapshots
  sources                                                 list sources
  groups                                                  list protection groups
  run <group-id> [--keep-until YYYY-MM-DD]                back up a group now (operator token);
                                                          keep the new snapshots until that day
  usage [--month YYYY-MM] [--tenant T] [--csv]            usage per tenant (billing)
  files search <query> [--tenant T] [--source S] [--group N] [--kind K] [--ext E]
               [--deleted only|exclude] [--limit N] [--cursor C]
                                                          find files in all snapshots (file search
                                                          index): one line per file, its versions
  openapi                                                 print the API description
  fleet [--config FILE] [--hours N] [--html OUT] [--check]
                                                          read-only overview of several appliances
                                                          (dashboard, open alerts, failed jobs of the
                                                          last N hours, default 24); each appliance
                                                          with its own read token (token_file or
                                                          token_env in the JSON configuration);
                                                          --html writes a static report, --check
                                                          exits 2 when one needs attention

environment: NEXUS_URL, NEXUS_TOKEN, NEXUS_CA; fleet: NEXUS_FLEET (configuration file)";

/// Where and how to connect.
#[derive(Clone, Debug, Default)]
pub struct Conn {
    pub url: String,
    pub token: String,
    pub ca_pem: Option<String>,
}

/// Global options and the command with its arguments.
#[derive(Debug, PartialEq)]
pub struct Cli {
    pub url: Option<String>,
    pub token: Option<String>,
    pub ca: Option<String>,
    pub json: bool,
    pub cmd: Vec<String>,
}

pub fn parse_global(args: &[String]) -> Result<Cli> {
    let mut cli = Cli {
        url: None,
        token: None,
        ca: None,
        json: false,
        cmd: vec![],
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |what: &str| it.next().cloned().with_context(|| format!("{what} needs a value"));
        match a.as_str() {
            "--url" => cli.url = Some(val("--url")?),
            "--token" => cli.token = Some(val("--token")?),
            "--ca" => cli.ca = Some(val("--ca")?),
            "--json" => cli.json = true,
            _ => {
                cli.cmd.push(a.clone());
                cli.cmd.extend(it.by_ref().cloned());
            }
        }
    }
    // `--json` may also follow the command
    if let Some(i) = cli.cmd.iter().position(|a| a == "--json") {
        cli.cmd.remove(i);
        cli.json = true;
    }
    Ok(cli)
}

/// (positional arguments, `--name value` options; flags with an empty value)
type Args = (Vec<String>, Vec<(String, String)>);
/// A table column: the field of each row and how to show it.
type Col<'a> = (&'a str, fn(&Value) -> String);

/// `--name value` options of a command; the rest stay positional.
pub(crate) fn opts(args: &[String], names: &[&str], flags: &[&str]) -> Result<Args> {
    let (mut pos, mut out) = (vec![], vec![]);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(n) = a.strip_prefix("--") {
            if flags.contains(&n) {
                out.push((n.to_owned(), String::new()));
            } else if names.contains(&n) {
                let v = it.next().with_context(|| format!("--{n} needs a value"))?;
                out.push((n.to_owned(), v.clone()));
            } else {
                bail!("unknown option --{n}");
            }
        } else {
            pos.push(a.clone());
        }
    }
    Ok((pos, out))
}

fn query(o: &[(String, String)], skip: &[&str]) -> String {
    let q: Vec<String> = o
        .iter()
        .filter(|(k, _)| !skip.contains(&k.as_str()))
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect();
    if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Unix time of the end of `YYYY-MM-DD` (UTC): a lock "until" a day covers that day.
pub fn end_of_day(s: &str) -> Result<i64> {
    let p: Vec<&str> = s.split('-').collect();
    let bad = || format!("{s:?}: expected YYYY-MM-DD");
    let [y, m, d] = p[..] else { bail!(bad()) };
    let (y, m, d): (i64, i64, i64) = (
        y.parse().with_context(bad)?,
        m.parse().with_context(bad)?,
        d.parse().with_context(bad)?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || y < 1970 {
        bail!(bad());
    }
    // days from civil (H. Hinnant)
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok((days + 1) * 86400 - 1)
}

pub(crate) fn iso(t: Option<i64>) -> String {
    let Some(t) = t else { return "-".into() };
    let z = t.div_euclid(86400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let s = t.rem_euclid(86400);
    format!(
        "{:04}-{m:02}-{d:02} {:02}:{:02}",
        yoe + era * 400 + i64::from(m <= 2),
        s / 3600,
        s / 60 % 60
    )
}

fn bytes(v: &Value) -> String {
    let Some(n) = v.as_f64() else { return "-".into() };
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let (mut x, mut i) = (n, 0);
    while x >= 1024.0 && i + 1 < units.len() {
        x /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{x:.1} {}", units[i])
    }
}

pub(crate) fn cell(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    }
}

/// Aligned columns with a header line.
pub fn table(head: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut w: Vec<usize> = head.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let mut s = cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<width$}", width = w[i]))
            .collect::<Vec<_>>()
            .join("  ");
        s.truncate(s.trim_end().len());
        s
    };
    let mut out = vec![line(head.iter().map(|h| h.to_uppercase()).collect())];
    out.extend(rows.into_iter().map(line));
    out.join("\n") + "\n"
}

fn rows(v: &Value, cols: &[Col]) -> Vec<Vec<String>> {
    v.as_array()
        .into_iter()
        .flatten()
        .map(|r| cols.iter().map(|(k, f)| f(&r[*k])).collect())
        .collect()
}

/// Writes a local output file readable by the owner only (reports name customers and hosts).
pub(crate) fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("{}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

pub struct Client {
    http: reqwest::blocking::Client,
    conn: Conn,
}

impl Client {
    pub fn new(conn: Conn) -> Result<Client> {
        let url = reqwest::Url::parse(&conn.url).context("--url / NEXUS_URL: not a URL")?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            bail!("--url / NEXUS_URL: https:// (http:// only for localhost)");
        }
        if !conn.token.starts_with("nxt_") {
            bail!("--token / NEXUS_TOKEN: an API token (nxt_…), created under Account → API tokens");
        }
        let mut b = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("nexusctl/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = &conn.ca_pem {
            for c in reqwest::Certificate::from_pem_bundle(pem.as_bytes()).context("--ca: PEM certificates")? {
                b = b.add_root_certificate(c);
            }
        }
        Ok(Client { http: b.build()?, conn })
    }

    fn send(&self, req: reqwest::blocking::RequestBuilder) -> Result<(String, String)> {
        let r = req.bearer_auth(&self.conn.token).send()?;
        let status = r.status();
        let ctype = r
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let text = r.text()?;
        if !status.is_success() {
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_owned))
                .unwrap_or(text);
            bail!("HTTP {status}: {msg}");
        }
        Ok((ctype, text))
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.conn.url.trim_end_matches('/'))
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        let (_, t) = self.send(self.http.get(self.url(path)))?;
        Ok(serde_json::from_str(&t)?)
    }

    pub fn get_text(&self, path: &str) -> Result<String> {
        Ok(self.send(self.http.get(self.url(path)))?.1)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let (_, t) = self.send(self.http.post(self.url(path)).json(body))?;
        Ok(serde_json::from_str(&t)?)
    }
}

/// Runs one command; returns what to print.
pub fn run(c: &Client, cmd: &[String], as_json: bool) -> Result<String> {
    let Some((name, args)) = cmd.split_first() else {
        bail!("no command\n\n{USAGE}");
    };
    let out = |v: Value, f: &dyn Fn(&Value) -> String| -> String {
        if as_json {
            serde_json::to_string_pretty(&v).unwrap_or_default() + "\n"
        } else {
            f(&v)
        }
    };
    let s = |v: &Value| cell(v);
    let t = |v: &Value| iso(v.as_i64());
    let b = |v: &Value| bytes(v);
    Ok(match name.as_str() {
        "jobs" => {
            let (_, o) = opts(args, &["state", "kind", "tenant", "limit"], &[])?;
            let v = c.get(&format!("/jobs{}", query(&o, &[])))?;
            out(v, &|v| {
                table(
                    &["id", "kind", "tenant", "state", "created", "finished", "requested_by"],
                    rows(
                        v,
                        &[
                            ("id", s),
                            ("kind", s),
                            ("tenant", s),
                            ("state", s),
                            ("created", t),
                            ("finished", t),
                            ("requested_by", s),
                        ],
                    ),
                )
            })
        }
        "job" => {
            let (pos, o) = opts(args, &[], &["log"])?;
            let [id] = &pos[..] else {
                bail!("usage: nexusctl job <id> [--log]")
            };
            let id: i64 = id.parse().context("job id: a number")?;
            let v = c.get(&format!("/jobs/{id}"))?;
            let log = !o.is_empty();
            out(v, &|v| {
                let mut s = format!(
                    "job {} {} ({}): {}\ncreated {}  started {}  finished {}  by {}\n",
                    v["id"],
                    cell(&v["kind"]),
                    cell(&v["tenant"]),
                    cell(&v["state"]),
                    iso(v["created"].as_i64()),
                    iso(v["started"].as_i64()),
                    iso(v["finished"].as_i64()),
                    cell(&v["requested_by"])
                );
                if log {
                    s.push_str(v["log"].as_str().unwrap_or_default());
                }
                s
            })
        }
        "snapshots" => {
            let (_, o) = opts(args, &["tenant", "source"], &[])?;
            let v = c.get(&format!("/snapshots{}", query(&o, &[])))?;
            out(v, &|v| {
                table(
                    &["tenant", "source", "time", "size", "local", "offsite", "locked_until"],
                    rows(
                        v,
                        &[
                            ("tenant", s),
                            ("source", s),
                            ("time", t),
                            ("size", b),
                            ("local", s),
                            ("offsite", s),
                            ("lock_until", t),
                        ],
                    ),
                )
            })
        }
        "files" => {
            let Some((_, rest)) = args.split_first().filter(|(c, _)| *c == "search") else {
                bail!("usage: nexusctl files search <query> [options]")
            };
            let (pos, mut o) = opts(
                rest,
                &[
                    "tenant", "source", "group", "kind", "ext", "deleted", "limit", "cursor", "mode",
                ],
                &[],
            )?;
            o.push(("q".into(), pos.join(" ")));
            let v = c.get(&format!("/files/search{}", query(&o, &[])))?;
            out(v, &|v| {
                let mut rows_ = Vec::new();
                for h in v["hits"].as_array().into_iter().flatten() {
                    let newest = &h["versions"][0];
                    rows_.push(vec![
                        cell(&h["source"]),
                        cell(&h["path"]),
                        h["versions"].as_array().map_or(0, Vec::len).to_string(),
                        bytes(&newest["size"]),
                        iso(newest["mtime"].as_i64()),
                        match newest["gone"].as_i64() {
                            Some(g) => format!("gone {}", iso(Some(g))),
                            None => "present".into(),
                        },
                    ]);
                }
                let mut t = table(&["source", "path", "versions", "size", "modified", "state"], rows_);
                if let Some(n) = v["next"].as_str() {
                    t.push_str(&format!("more: --cursor {n}\n"));
                }
                t
            })
        }
        "sources" => {
            opts(args, &[], &[])?;
            let v = c.get("/sources")?;
            out(v, &|v| {
                table(
                    &["id", "tenant", "kind", "name"],
                    rows(v, &[("id", s), ("tenant", s), ("kind", s), ("name", s)]),
                )
            })
        }
        "groups" => {
            opts(args, &[], &[])?;
            let v = c.get("/groups")?;
            out(v, &|v| {
                table(
                    &["id", "tenant", "name", "source_id", "policy_id"],
                    rows(
                        v,
                        &[
                            ("id", s),
                            ("tenant", s),
                            ("name", s),
                            ("source_id", s),
                            ("policy_id", s),
                        ],
                    ),
                )
            })
        }
        "run" => {
            let (pos, o) = opts(args, &["keep-until"], &[])?;
            let [id] = &pos[..] else {
                bail!("usage: nexusctl run <group-id> [--keep-until YYYY-MM-DD]")
            };
            let id: i64 = id.parse().context("group id: a number")?;
            let groups = c.get("/groups")?;
            let g = groups
                .as_array()
                .into_iter()
                .flatten()
                .find(|g| g["id"] == id)
                .with_context(|| format!("no group {id}"))?;
            let mut params = json!({"group_id": id});
            if let Some((_, d)) = o.first() {
                params["keep_until"] = json!(end_of_day(d)?);
            }
            let body = json!({"kind": "backup", "tenant": g["tenant"], "params": params});
            let v = c.post("/jobs", &body)?;
            out(
                v,
                &|v| match (v["id"].as_i64(), v["quorum_id"].as_i64(), v["job_id"].as_i64()) {
                    (Some(j), ..) | (_, _, Some(j)) => format!("job {j} queued (nexusctl job {j})\n"),
                    (None, Some(q), None) => {
                        format!("approval request {q} created: the job starts once another administrator approves it\n")
                    }
                    _ => format!("{v}\n"),
                },
            )
        }
        "usage" => {
            let (_, o) = opts(args, &["month", "tenant"], &["csv"])?;
            let csv = o.iter().any(|(k, _)| k == "csv");
            let q = query(&o, &["csv"]);
            if csv {
                let sep = if q.is_empty() { "?" } else { "&" };
                return c.get_text(&format!("/usage{q}{sep}format=csv"));
            }
            let v = c.get(&format!("/usage{q}"))?;
            out(v, &|v| {
                let mut head = format!(
                    "usage {}{}\n",
                    cell(&v["month"]),
                    if v["complete"] == false {
                        " (month in progress)"
                    } else {
                        ""
                    }
                );
                head.push_str(&table(
                    &[
                        "tenant",
                        "objects",
                        "logical_avg",
                        "logical_peak",
                        "stored_avg",
                        "stored_peak",
                        "offsite_avg",
                        "days",
                    ],
                    rows(
                        &v["tenants"],
                        &[
                            ("tenant", s),
                            ("objects", s),
                            ("logical_avg", b),
                            ("logical_peak", b),
                            ("stored_avg", b),
                            ("stored_peak", b),
                            ("offsite_avg", b),
                            ("days_sampled", s),
                        ],
                    ),
                ));
                head
            })
        }
        "openapi" => c.get_text("/openapi.json")?,
        "help" | "--help" | "-h" => format!("{USAGE}\n"),
        other => bail!("unknown command {other:?}\n\n{USAGE}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn global_options_and_commands() {
        let c = parse_global(&v(&["--url", "https://x", "jobs", "--state", "failed", "--json"])).unwrap();
        assert_eq!(c.url.as_deref(), Some("https://x"));
        assert!(c.json);
        assert_eq!(c.cmd, v(&["jobs", "--state", "failed"]));
        assert!(parse_global(&v(&["--token"])).is_err());
        let (pos, o) = opts(&v(&["7", "--keep-until", "2027-01-31"]), &["keep-until"], &[]).unwrap();
        assert_eq!((pos, o), (v(&["7"]), vec![("keep-until".into(), "2027-01-31".into())]));
        assert!(opts(&v(&["--nope"]), &[], &[]).is_err());
        assert_eq!(
            query(
                &[("month".into(), "2026-10".into()), ("tenant".into(), "a b".into())],
                &[]
            ),
            "?month=2026-10&tenant=a%20b"
        );
    }

    #[test]
    fn dates_and_formatting() {
        assert_eq!(end_of_day("2026-10-12").unwrap(), 1_791_849_599);
        assert_eq!(end_of_day("2028-02-29").unwrap() % 86400, 86399);
        assert!(end_of_day("2026-13-01").is_err() && end_of_day("tomorrow").is_err());
        assert_eq!(iso(Some(1_791_763_200)), "2026-10-12 00:00");
        assert_eq!(bytes(&json!(1536)), "1.5 KiB");
        assert_eq!(bytes(&Value::Null), "-");
        assert_eq!(
            table(&["id", "name"], vec![v(&["1", "alpha"]), v(&["22", "b"])]),
            "ID  NAME\n1   alpha\n22  b\n"
        );
    }
}
