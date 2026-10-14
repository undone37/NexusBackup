//! `nexusctl fleet` (Phase 33, docs/commvault-comparison.md Tier 2
//! "Multi-appliance overview"): a read-only overview over several appliances,
//! for service providers running one appliance per customer. It runs on the
//! operator's workstation, never on an appliance, and pulls from each appliance
//! with its own read-scoped API token: `/auth/me` (token scope, incident mode),
//! `/dashboard` (protection, jobs, capacity, offsite), open alerts and the failed
//! jobs of the last hours. Nothing is written anywhere except the optional static
//! HTML report on the local disk.
//!
//! Configuration (`--config FILE` or `NEXUS_FLEET`), JSON:
//!
//! ```json
//! {"appliances": [
//!   {"name": "acme", "url": "https://backup.acme.example:8443", "token_file": "~/.config/nexusctl/acme.token",
//!    "ca": "~/.config/nexusctl/acme-ca.pem"},
//!   {"name": "globex", "url": "https://10.20.0.5:8443", "token_env": "NEXUS_TOKEN_GLOBEX"}]}
//! ```
//!
//! Tokens never sit in the file itself: `token_file` (must not be readable by
//! group or others) or `token_env`. A token that is not `read`-scoped is
//! refused (the overview must not hold write access to a customer's appliance).
//! Appliances are queried in parallel; one that cannot be reached is reported
//! as such, the others still are.

use crate::{Client, Conn};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// At most this many appliances in one configuration.
pub const MAX_APPLIANCES: usize = 200;
/// Failed jobs fetched per appliance (newest first).
const JOBS_LIMIT: u32 = 500;
/// Alerts / failed jobs listed per appliance in the text and HTML output.
const LISTED: usize = 20;

/// One appliance of the configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub url: String,
    pub token: TokenFrom,
    pub ca: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenFrom {
    File(PathBuf),
    Env(String),
}

fn home(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(h)) => Path::new(&h).join(rest),
        _ => PathBuf::from(p),
    }
}

/// Parses and checks the configuration (names unique, URLs https or loopback
/// http, a token source per appliance, no inline tokens).
pub fn parse_config(text: &str) -> Result<Vec<Entry>> {
    let v: Value = serde_json::from_str(text).context("fleet configuration: JSON")?;
    let list = v["appliances"]
        .as_array()
        .context("fleet configuration: {\"appliances\": [...]}")?;
    if list.is_empty() || list.len() > MAX_APPLIANCES {
        bail!("fleet configuration: 1..={MAX_APPLIANCES} appliances");
    }
    let mut out: Vec<Entry> = Vec::new();
    for (i, a) in list.iter().enumerate() {
        let o = a
            .as_object()
            .with_context(|| format!("appliance {}: an object", i + 1))?;
        if let Some(k) = o
            .keys()
            .find(|k| !["name", "url", "token_file", "token_env", "ca"].contains(&k.as_str()))
        {
            bail!(
                "appliance {}: unknown field {k:?} (tokens go into token_file or token_env)",
                i + 1
            );
        }
        let name = a["name"].as_str().unwrap_or_default();
        let ok_name =
            (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !ok_name {
            bail!("appliance {}: name: 1..=64 of [A-Za-z0-9._-]", i + 1);
        }
        if out.iter().any(|e| e.name == name) {
            bail!("appliance {name}: name used twice");
        }
        let url = a["url"]
            .as_str()
            .with_context(|| format!("appliance {name}: url missing"))?;
        let token = match (a["token_file"].as_str(), a["token_env"].as_str()) {
            (Some(f), None) => TokenFrom::File(home(f)),
            (None, Some(e)) if !e.is_empty() => TokenFrom::Env(e.to_owned()),
            _ => bail!("appliance {name}: exactly one of token_file or token_env"),
        };
        out.push(Entry {
            name: name.to_owned(),
            url: url.to_owned(),
            token,
            ca: a["ca"].as_str().map(home),
        });
    }
    Ok(out)
}

/// The token of `e`; a token file readable by group or others is refused (like an SSH key).
pub fn read_token(e: &Entry) -> Result<String> {
    let t = match &e.token {
        TokenFrom::Env(k) => std::env::var(k).with_context(|| format!("environment variable {k} is not set"))?,
        TokenFrom::File(p) => {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(p).with_context(|| format!("{}", p.display()))?;
            if meta.permissions().mode() & 0o077 != 0 {
                bail!(
                    "{}: readable by group or others (chmod 600 {})",
                    p.display(),
                    p.display()
                );
            }
            std::fs::read_to_string(p).with_context(|| format!("{}", p.display()))?
        }
    };
    Ok(t.trim().to_owned())
}

/// What one appliance answered (or why it could not).
#[derive(Debug, Clone)]
pub struct Report {
    pub name: String,
    pub url: String,
    pub result: Result<Value, String>,
}

/// Pulls one appliance: `{me, dashboard, alerts, failed_jobs}` (failed jobs that
/// finished in the last `hours`).
pub fn fetch(e: &Entry, hours: i64, now: i64) -> Result<Value> {
    let ca_pem =
        e.ca.as_ref()
            .map(|p| std::fs::read_to_string(p).with_context(|| format!("{}", p.display())))
            .transpose()?;
    let c = Client::new(Conn {
        url: e.url.clone(),
        token: read_token(e)?,
        ca_pem,
    })?;
    let me = c.get("/auth/me")?;
    match me["token"]["scope"].as_str() {
        Some("read") => {}
        Some(s) => bail!("the token has scope {s}: the fleet overview needs a read-only token"),
        None => bail!("the appliance did not report the token's scope (update it first)"),
    }
    let dashboard = c.get("/dashboard")?;
    let alerts = c.get("/alerts?state=open")?;
    let jobs = c.get(&format!("/jobs?state=failed&limit={JOBS_LIMIT}"))?;
    let since = now - hours * 3600;
    let failed: Vec<Value> = jobs
        .as_array()
        .into_iter()
        .flatten()
        .filter(|j| {
            j["finished"]
                .as_i64()
                .or(j["created"].as_i64())
                .is_some_and(|t| t >= since)
        })
        .cloned()
        .collect();
    Ok(json!({"me": me, "dashboard": dashboard, "alerts": alerts, "failed_jobs": failed}))
}

/// Every appliance at once (one thread each).
pub fn collect(entries: &[Entry], hours: i64, now: i64) -> Vec<Report> {
    std::thread::scope(|s| {
        let handles: Vec<_> = entries
            .iter()
            .map(|e| s.spawn(move || fetch(e, hours, now).map_err(|err| format!("{err:#}"))))
            .collect();
        entries
            .iter()
            .zip(handles)
            .map(|(e, h)| Report {
                name: e.name.clone(),
                url: e.url.clone(),
                result: h.join().unwrap_or_else(|_| Err("internal error".into())),
            })
            .collect()
    })
}

/// Key figures of one appliance's answer.
#[derive(Debug, Default, PartialEq)]
pub struct Figures {
    pub objects: i64,
    pub protected: i64,
    pub sla_breach: i64,
    pub never: i64,
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    pub failed_jobs: usize,
    pub used_pct: Option<f64>,
    pub offsite_lagging: i64,
    pub incident: bool,
}

pub fn figures(v: &Value) -> Figures {
    let d = &v["dashboard"];
    let alerts: Vec<&Value> = v["alerts"].as_array().into_iter().flatten().collect();
    let sev = |s: &str| alerts.iter().filter(|a| a["severity"] == s).count();
    let (total, used) = (d["capacity"]["total"].as_f64(), d["capacity"]["used"].as_f64());
    Figures {
        objects: d["protection"]["objects"].as_i64().unwrap_or(0),
        protected: d["protection"]["protected"].as_i64().unwrap_or(0),
        sla_breach: d["protection"]["sla_breach"].as_i64().unwrap_or(0),
        never: d["protection"]["never"].as_i64().unwrap_or(0),
        critical: sev("critical"),
        warning: sev("warning"),
        info: sev("info"),
        failed_jobs: v["failed_jobs"].as_array().map_or(0, Vec::len),
        used_pct: match (total, used) {
            (Some(t), Some(u)) if t > 0.0 => Some(u * 100.0 / t),
            _ => None,
        },
        offsite_lagging: d["offsite"]["lagging"].as_i64().unwrap_or(0),
        incident: !v["me"]["incident"].is_null() && v["me"]["incident"] != json!(false),
    }
}

/// Whether an appliance needs attention: unreachable, incident mode, a critical
/// alert, a failed job or an SLA breach (`--check` exits 2 then).
pub fn needs_attention(r: &Report) -> bool {
    match &r.result {
        Err(_) => true,
        Ok(v) => {
            let f = figures(v);
            f.incident || f.critical > 0 || f.failed_jobs > 0 || f.sla_breach > 0
        }
    }
}

fn one_line(s: &str, max: usize) -> String {
    let s: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if s.chars().count() > max {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    } else {
        s
    }
}

/// The text overview: one line per appliance, then its open critical/warning
/// alerts and failed jobs.
pub fn text(reports: &[Report], hours: i64) -> String {
    let mut rows = Vec::new();
    for r in reports {
        rows.push(match &r.result {
            Err(e) => vec![
                r.name.clone(),
                "UNREACHABLE".into(),
                "-".into(),
                "-".into(),
                "-".into(),
                "-".into(),
                "-".into(),
                one_line(e, 60),
            ],
            Ok(v) => {
                let f = figures(v);
                vec![
                    r.name.clone(),
                    if f.incident {
                        "INCIDENT".into()
                    } else if needs_attention(r) {
                        "ATTENTION".into()
                    } else {
                        "ok".into()
                    },
                    format!("{}/{}", f.protected, f.objects),
                    f.sla_breach.to_string(),
                    format!("{}/{}/{}", f.critical, f.warning, f.info),
                    f.failed_jobs.to_string(),
                    f.used_pct.map_or("-".into(), |p| format!("{p:.0} %")),
                    if f.offsite_lagging > 0 {
                        format!("offsite lagging: {}", f.offsite_lagging)
                    } else {
                        String::new()
                    },
                ]
            }
        });
    }
    let mut out = crate::table(
        &[
            "appliance",
            "state",
            "protected",
            "sla_breach",
            "alerts_c/w/i",
            &format!("failed_{hours}h"),
            "store",
            "note",
        ],
        rows,
    );
    for r in reports {
        let Ok(v) = &r.result else { continue };
        let alerts: Vec<&Value> = v["alerts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a["severity"] != "info")
            .collect();
        let jobs: Vec<&Value> = v["failed_jobs"].as_array().into_iter().flatten().collect();
        if alerts.is_empty() && jobs.is_empty() {
            continue;
        }
        out.push_str(&format!("\n{}:\n", r.name));
        for a in alerts.iter().take(LISTED) {
            out.push_str(&format!(
                "  alert {} {} {}{}: {}\n",
                crate::cell(&a["id"]),
                crate::cell(&a["severity"]),
                crate::cell(&a["kind"]),
                a["tenant"].as_str().map(|t| format!(" ({t})")).unwrap_or_default(),
                one_line(a["message"].as_str().unwrap_or_default(), 140)
            ));
        }
        if alerts.len() > LISTED {
            out.push_str(&format!("  … {} more alerts\n", alerts.len() - LISTED));
        }
        for j in jobs.iter().take(LISTED) {
            out.push_str(&format!(
                "  failed job {} {} ({}) {}\n",
                crate::cell(&j["id"]),
                crate::cell(&j["kind"]),
                crate::cell(&j["tenant"]),
                crate::iso(j["finished"].as_i64())
            ));
        }
        if jobs.len() > LISTED {
            out.push_str(&format!("  … {} more failed jobs\n", jobs.len() - LISTED));
        }
    }
    out
}

/// HTML-escapes text (alert messages come from the appliances: never trusted).
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// A static HTML report (no scripts, no external resources; the CSP forbids both).
pub fn html(reports: &[Report], hours: i64, now: i64) -> String {
    let mut h = String::from(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
         <title>NexusBackup fleet overview</title>\n<style>\n\
         body{font:14px/1.45 system-ui,sans-serif;margin:2rem;color:#1b2430}\n\
         table{border-collapse:collapse;margin:1rem 0}th,td{border-bottom:1px solid #d8dee6;padding:.35rem .7rem;text-align:left;vertical-align:top}\n\
         th{font-size:12px;text-transform:uppercase;color:#5b6675}.bad{color:#b42318;font-weight:600}.warn{color:#9a6700;font-weight:600}\n\
         .ok{color:#1a7f37}.muted{color:#5b6675}h2{margin-top:2rem}\n</style></head><body>\n",
    );
    h.push_str(&format!(
        "<h1>NexusBackup fleet overview</h1>\n<p class=\"muted\">Generated {} UTC by nexusctl fleet; failed jobs of the last {hours} hours; read-only.</p>\n",
        esc(&crate::iso(Some(now)))
    ));
    h.push_str("<table><thead><tr><th>Appliance</th><th>State</th><th>Protected</th><th>SLA breaches</th><th>Open alerts (critical / warning / info)</th><th>Failed jobs</th><th>Store used</th></tr></thead><tbody>\n");
    for r in reports {
        match &r.result {
            Err(e) => h.push_str(&format!(
                "<tr><td><strong>{}</strong><div class=\"muted\">{}</div></td><td class=\"bad\">unreachable</td><td colspan=\"5\">{}</td></tr>\n",
                esc(&r.name),
                esc(&r.url),
                esc(&one_line(e, 300))
            )),
            Ok(v) => {
                let f = figures(v);
                let (cls, state) = if f.incident {
                    ("bad", "incident mode")
                } else if needs_attention(r) {
                    ("warn", "attention")
                } else {
                    ("ok", "ok")
                };
                h.push_str(&format!(
                    "<tr><td><strong>{}</strong><div class=\"muted\">{}</div></td><td class=\"{cls}\">{state}</td><td>{} / {}</td><td>{}</td><td>{} / {} / {}</td><td>{}</td><td>{}</td></tr>\n",
                    esc(&r.name),
                    esc(&r.url),
                    f.protected,
                    f.objects,
                    f.sla_breach,
                    f.critical,
                    f.warning,
                    f.info,
                    f.failed_jobs,
                    f.used_pct.map_or("-".into(), |p| format!("{p:.0} %"))
                ));
            }
        }
    }
    h.push_str("</tbody></table>\n");
    for r in reports {
        let Ok(v) = &r.result else { continue };
        let alerts: Vec<&Value> = v["alerts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a["severity"] != "info")
            .collect();
        let jobs: Vec<&Value> = v["failed_jobs"].as_array().into_iter().flatten().collect();
        if alerts.is_empty() && jobs.is_empty() {
            continue;
        }
        h.push_str(&format!("<h2>{}</h2>\n", esc(&r.name)));
        if !alerts.is_empty() {
            h.push_str("<table><thead><tr><th>Alert</th><th>Severity</th><th>Kind</th><th>Tenant</th><th>Message</th></tr></thead><tbody>\n");
            for a in alerts.iter().take(LISTED) {
                let sev = a["severity"].as_str().unwrap_or_default();
                h.push_str(&format!(
                    "<tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    esc(&crate::cell(&a["id"])),
                    if sev == "critical" { "bad" } else { "warn" },
                    esc(sev),
                    esc(&crate::cell(&a["kind"])),
                    esc(&crate::cell(&a["tenant"])),
                    esc(&one_line(a["message"].as_str().unwrap_or_default(), 400))
                ));
            }
            h.push_str("</tbody></table>\n");
        }
        if !jobs.is_empty() {
            h.push_str("<table><thead><tr><th>Failed job</th><th>Kind</th><th>Tenant</th><th>Finished (UTC)</th></tr></thead><tbody>\n");
            for j in jobs.iter().take(LISTED) {
                h.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    esc(&crate::cell(&j["id"])),
                    esc(&crate::cell(&j["kind"])),
                    esc(&crate::cell(&j["tenant"])),
                    esc(&crate::iso(j["finished"].as_i64()))
                ));
            }
            h.push_str("</tbody></table>\n");
        }
    }
    h.push_str("</body></html>\n");
    h
}

/// The JSON output: per appliance its answer or its error.
pub fn json_out(reports: &[Report]) -> Value {
    Value::Array(
        reports
            .iter()
            .map(|r| match &r.result {
                Ok(v) => json!({"name": r.name, "url": r.url, "ok": true, "data": v}),
                Err(e) => json!({"name": r.name, "url": r.url, "ok": false, "error": e}),
            })
            .collect(),
    )
}

/// `nexusctl fleet [--config FILE] [--hours N] [--html OUT] [--check]`: what to
/// print and the exit code (`--check`: 2 when an appliance needs attention).
pub fn cli(args: &[String], as_json: bool) -> Result<(String, i32)> {
    let (pos, o) = crate::opts(args, &["config", "hours", "html"], &["check"])?;
    if !pos.is_empty() {
        bail!("usage: nexusctl fleet [--config FILE] [--hours N] [--html OUT] [--check]");
    }
    let get = |k: &str| o.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let path = get("config")
        .or_else(|| std::env::var("NEXUS_FLEET").ok().filter(|v| !v.is_empty()))
        .context("--config FILE or NEXUS_FLEET is required (see nexusctl help)")?;
    let hours: i64 = match get("hours") {
        Some(h) => h
            .parse()
            .ok()
            .filter(|h| (1..=24 * 31).contains(h))
            .context("--hours: 1..=744")?,
        None => 24,
    };
    let text_cfg = std::fs::read_to_string(home(&path)).with_context(|| path.clone())?;
    let entries = parse_config(&text_cfg)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let reports = collect(&entries, hours, now);
    if let Some(out) = get("html") {
        crate::write_private(Path::new(&out), html(&reports, hours, now).as_bytes())?;
    }
    let code = if o.iter().any(|(k, _)| k == "check") && reports.iter().any(needs_attention) {
        2
    } else {
        0
    };
    let shown = if as_json {
        serde_json::to_string_pretty(&json_out(&reports))? + "\n"
    } else {
        text(&reports, hours)
    };
    Ok((shown, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration() {
        let c = parse_config(
            r#"{"appliances": [{"name": "acme", "url": "https://a.example:8443", "token_file": "/etc/t", "ca": "/etc/ca.pem"},
                               {"name": "globex", "url": "https://g.example", "token_env": "NEXUS_TOKEN_G"}]}"#,
        )
        .unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].token, TokenFrom::File("/etc/t".into()));
        assert_eq!(c[1].token, TokenFrom::Env("NEXUS_TOKEN_G".into()));
        for (bad, why) in [
            (r#"{"appliances": []}"#, "1..="),
            (
                r#"{"appliances": [{"name": "a", "url": "https://x", "token": "nxt_x"}]}"#,
                "unknown field",
            ),
            (
                r#"{"appliances": [{"name": "a b", "url": "https://x", "token_env": "T"}]}"#,
                "name",
            ),
            (r#"{"appliances": [{"name": "a", "url": "https://x"}]}"#, "exactly one"),
            (
                r#"{"appliances": [{"name": "a", "url": "https://x", "token_env": "T", "token_file": "/t"}]}"#,
                "exactly one",
            ),
            (
                r#"{"appliances": [{"name": "a", "url": "https://x", "token_env": "T"}, {"name": "a", "url": "https://y", "token_env": "U"}]}"#,
                "twice",
            ),
        ] {
            let e = parse_config(bad).unwrap_err().to_string();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn token_files_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t");
        std::fs::write(&p, "nxt_0000aaaa_secret\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = Entry {
            name: "a".into(),
            url: "https://x".into(),
            token: TokenFrom::File(p.clone()),
            ca: None,
        };
        assert!(read_token(&e).unwrap_err().to_string().contains("chmod 600"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token(&e).unwrap(), "nxt_0000aaaa_secret");
    }

    #[test]
    fn rendering_escapes_and_flags() {
        let ok = Report {
            name: "acme".into(),
            url: "https://a".into(),
            result: Ok(
                json!({"me": {"incident": null}, "dashboard": {"protection": {"objects": 4, "protected": 3,
                "sla_breach": 1, "never": 0}, "capacity": {"total": 1000, "used": 250}, "offsite": {"lagging": 0}},
                "alerts": [{"id": 7, "severity": "critical", "kind": "job_failed", "tenant": "t",
                            "message": "<script>alert(1)</script>\nsecond line"}],
                "failed_jobs": [{"id": 9, "kind": "backup", "tenant": "t", "finished": 1791763200}]}),
            ),
        };
        let quiet = Report {
            name: "quiet".into(),
            url: "https://q".into(),
            result: Ok(
                json!({"me": {}, "dashboard": {"protection": {"objects": 1, "protected": 1}}, "alerts": [],
                              "failed_jobs": []}),
            ),
        };
        let down = Report {
            name: "down".into(),
            url: "https://d".into(),
            result: Err("connection refused".into()),
        };
        let f = figures(ok.result.as_ref().unwrap());
        assert_eq!((f.protected, f.objects, f.critical, f.failed_jobs), (3, 4, 1, 1));
        assert_eq!(f.used_pct, Some(25.0));
        assert!(needs_attention(&ok) && needs_attention(&down) && !needs_attention(&quiet));
        let t = text(&[ok.clone(), quiet.clone(), down.clone()], 24);
        assert!(t.contains("acme       ATTENTION"), "{t}");
        assert!(t.contains("quiet      ok"), "{t}");
        assert!(t.contains("down       UNREACHABLE"), "{t}");
        assert!(
            t.contains("alert 7 critical job_failed (t): <script>alert(1)</script> second line"),
            "{t}"
        );
        assert!(t.contains("failed job 9 backup (t) 2026-10-12 00:00"), "{t}");
        let h = html(&[ok, quiet, down], 24, 1791763200);
        assert!(!h.contains("<script>") && h.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(h.contains("default-src 'none'") && h.contains("unreachable"));
    }
}
