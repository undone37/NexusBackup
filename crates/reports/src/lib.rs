//! Reports (Phase 14e, docs/control-plane.md "Reports"): tables computed from the
//! catalog, shared by the web-api (`GET /reports/{type}.csv`) and the scheduler
//! (scheduled HTML mails with the CSVs attached, setting `reports`).
//!
//! - `protection`: per protected object (guest, host, share, dataset, plugin guest):
//!   last good backup, RPO status (the dashboard's rule: breach when older than
//!   RPO × 1.5), whether that snapshot is local / offsite / verified, consistency.
//!   State as of now (the range is not used).
//! - `failed`: failed jobs that finished in the range, with the first error line.
//! - `sla`: RPO breaches (gaps between good backups longer than RPO × 1.5) and
//!   `sla_missed` alerts (backup still running after the policy's SLA) in the range.
//! - `storage`: per tenant and group: logical, data in, stored, ratios, growth
//!   (current state, docs/storage-accounting.md; the range is not used).
//!
//! CSV: RFC 4180 (comma, CRLF, fields with `,` `"` CR LF quoted, `"` doubled),
//! UTF-8 without BOM, times ISO 8601 UTC (`2026-10-12T07:00:00Z`), bytes as
//! integers. Text cells starting with `=` `+` `-` `@` (or tab / CR) get a leading
//! `'` so spreadsheets do not evaluate them (CSV injection).

use catalog::rusqlite::{self, Connection};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

pub mod dr;
pub mod protection;
pub mod storage;

const DAY: i64 = 86400;
/// Rows of each report in the mail body (all rows are in the attachment).
pub const MAIL_ROWS: usize = 20;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Protection,
    Failed,
    Sla,
    Storage,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Protection, Kind::Failed, Kind::Sla, Kind::Storage];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Protection => "protection",
            Kind::Failed => "failed",
            Kind::Sla => "sla",
            Kind::Storage => "storage",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name() == s)
    }

    pub fn title(self) -> &'static str {
        match self {
            Kind::Protection => "Protection status",
            Kind::Failed => "Failed jobs",
            Kind::Sla => "SLA and RPO breaches",
            Kind::Storage => "Storage",
        }
    }

    /// Whether the report covers a time range (else it is the current state).
    pub fn ranged(self) -> bool {
        matches!(self, Kind::Failed | Kind::Sla)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    Text(String),
    Int(i64),
    /// ratio, rounded to 3 decimals
    Ratio(f64),
    /// unix time, written as ISO 8601 UTC
    Time(i64),
    Empty,
}

impl Cell {
    pub fn text(s: impl Into<String>) -> Cell {
        Cell::Text(s.into())
    }
    pub fn opt_time(t: Option<i64>) -> Cell {
        t.map_or(Cell::Empty, Cell::Time)
    }
    pub fn opt_int(n: Option<i64>) -> Cell {
        n.map_or(Cell::Empty, Cell::Int)
    }
    pub fn opt_ratio(r: Option<f64>) -> Cell {
        r.map_or(Cell::Empty, Cell::Ratio)
    }
    /// Hours with one decimal.
    pub fn hours(secs: i64) -> Cell {
        Cell::Ratio((secs as f64 / 360.0).round() / 10.0)
    }
}

impl std::fmt::Display for Cell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cell::Text(s) => f.write_str(s),
            Cell::Int(n) => write!(f, "{n}"),
            Cell::Ratio(r) => write!(f, "{}", (r * 1000.0).round() / 1000.0),
            Cell::Time(t) => f.write_str(&iso(*t)),
            Cell::Empty => Ok(()),
        }
    }
}

/// One report: column names and rows (each row has one cell per column).
#[derive(Clone, Debug, PartialEq)]
pub struct Table {
    pub kind: Kind,
    pub columns: &'static [&'static str],
    pub rows: Vec<Vec<Cell>>,
}

/// A CSV field: quoted when needed, formula-like text neutralised.
fn field(out: &mut String, c: &Cell) {
    let mut s = c.to_string();
    if matches!(c, Cell::Text(_)) && s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        s.insert(0, '\'');
    }
    if s.contains([',', '"', '\r', '\n']) {
        out.push('"');
        out.push_str(&s.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(&s);
    }
}

impl Table {
    /// RFC 4180 CSV with a header line.
    pub fn csv(&self) -> String {
        let mut out = String::new();
        let header: Vec<Cell> = self.columns.iter().map(|c| Cell::text(*c)).collect();
        for row in std::iter::once(&header).chain(&self.rows) {
            for (i, c) in row.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                field(&mut out, c);
            }
            out.push_str("\r\n");
        }
        out
    }
}

/// `YYYY-MM-DD` (UTC) of a unix time (civil-from-days, H. Hinnant).
pub fn day(ts: i64) -> String {
    let z = ts.div_euclid(DAY) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 of `YYYY-MM-DD` (inverse of [`day`]); `None` if malformed.
pub fn parse_day(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (yy, mm) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let n = era * 146_097 + doe - 719_468;
    // 2026-02-31 and the like
    (day(n * DAY) == s).then_some(n)
}

/// ISO 8601 UTC, seconds precision.
pub fn iso(ts: i64) -> String {
    let s = ts.rem_euclid(DAY);
    format!("{}T{:02}:{:02}:{:02}Z", day(ts), s / 3600, s / 60 % 60, s % 60)
}

/// The report `kind` for tenant `scope` (None = all) over `[from, to)`.
pub fn generate(
    c: &Connection,
    kind: Kind,
    scope: Option<&str>,
    from: i64,
    to: i64,
    now: i64,
) -> rusqlite::Result<Table> {
    match kind {
        Kind::Protection => protection::table(c, scope, now),
        Kind::Failed => failed(c, scope, from, to),
        Kind::Sla => protection::sla(c, scope, from, to, now),
        Kind::Storage => storage::table(c, scope, now),
    }
}

/// First line of a job log that names an error, else its last non-empty line.
pub fn error_line(log: &str) -> String {
    let lines = || log.lines().map(str::trim).filter(|l| !l.is_empty());
    let hit = lines().find(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("error") || l.contains("failed") || l.contains("fatal")
    });
    let line = hit.or_else(|| lines().next_back()).unwrap_or_default();
    line.chars().take(300).collect()
}

/// What a job worked on (`group <name>`, `source <name>`, `agent <id>`, `guest <vmid>`, …).
fn job_target(c: &Connection, p: &serde_json::Value) -> rusqlite::Result<String> {
    use rusqlite::OptionalExtension;
    if let Some(g) = p["group_id"].as_i64() {
        let n: Option<String> = c
            .query_row("SELECT name FROM groups WHERE id = ?1", [g], |r| r.get(0))
            .optional()?;
        return Ok(format!("group {}", n.unwrap_or_else(|| g.to_string())));
    }
    if let Some(s) = p["source_id"].as_i64() {
        let n: Option<String> = c
            .query_row("SELECT name FROM sources WHERE id = ?1", [s], |r| r.get(0))
            .optional()?;
        return Ok(format!("source {}", n.unwrap_or_else(|| s.to_string())));
    }
    for (k, what) in [
        ("agent_id", "agent"),
        ("replication_source_id", "replication source"),
        ("vmid", "guest"),
        ("source", "snapshot source"),
        ("name", ""),
    ] {
        match &p[k] {
            serde_json::Value::Null => {}
            serde_json::Value::String(s) => return Ok(format!("{what} {s}").trim().to_owned()),
            v => return Ok(format!("{what} {v}").trim().to_owned()),
        }
    }
    Ok(String::new())
}

pub const FAILED_COLUMNS: &[&str] = &[
    "job", "tenant", "kind", "target", "created", "finished", "attempt", "error",
];

/// Failed jobs that finished in `[from, to)`, oldest first.
#[allow(clippy::type_complexity)]
fn failed(c: &Connection, scope: Option<&str>, from: i64, to: i64) -> rusqlite::Result<Table> {
    let rows: Vec<(i64, String, String, String, i64, i64, i64, String)> = c
        .prepare(
            "SELECT id, tenant, kind, params, created, finished, attempt, log FROM jobs
             WHERE state = 'failed' AND finished >= ?1 AND finished < ?2 AND (?3 IS NULL OR tenant = ?3)
             ORDER BY finished, id",
        )?
        .query_map(rusqlite::params![from, to, scope], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for (id, tenant, kind, params, created, finished, attempt, log) in rows {
        let p: serde_json::Value = serde_json::from_str(&params).unwrap_or_default();
        out.push(vec![
            Cell::Int(id),
            Cell::Text(tenant),
            Cell::Text(kind),
            Cell::Text(job_target(c, &p)?),
            Cell::Time(created),
            Cell::Time(finished),
            Cell::Int(attempt),
            Cell::Text(error_line(&log)),
        ]);
    }
    Ok(Table {
        kind: Kind::Failed,
        columns: FAILED_COLUMNS,
        rows: out,
    })
}

// ---------------------------------------------------------------- scheduled reports

/// Catalog setting: JSON array of [`Scheduled`] (written by `PUT /settings/reports`).
pub const SETTING: &str = "reports";
pub const MAX_SCHEDULED: usize = 32;
pub const MAX_RECIPIENTS: usize = 16;

/// A report mailed on a schedule (weekdays or monthly form, in `timezone`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Scheduled {
    pub name: String,
    pub types: Vec<Kind>,
    /// `Mon 07:00`, `Mon,Thu 07:00`, `daily 07:00` or `monthly 1 07:00`
    pub schedule: String,
    #[serde(default = "utc")]
    pub timezone: String,
    pub recipients: Vec<String>,
    /// only this tenant's data (None = all tenants)
    #[serde(default)]
    pub tenant: Option<String>,
}

fn utc() -> String {
    "UTC".into()
}

/// `[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}` (also part of the attachment names).
pub fn valid_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Scheduled {
    /// The parsed schedule in its time zone; hourly forms are refused (a report
    /// covers at least a day).
    pub fn schedule(&self) -> anyhow::Result<catalog::schedule::Schedule> {
        use catalog::schedule::{Kind as S, Schedule};
        let s = Schedule::parse(&self.schedule)?.in_tz(&self.timezone)?;
        if let S::Hours { .. } = s.kind {
            anyhow::bail!(
                "schedule: a report runs on weekdays (`Mon 07:00`, `daily 07:00`) or monthly (`monthly 1 07:00`)"
            );
        }
        Ok(s)
    }

    /// Fields only; recipients' mail syntax and the tenant are checked by the web-api.
    pub fn check(&self) -> Result<(), String> {
        if !valid_name(&self.name) {
            return Err("name: [A-Za-z0-9._-]{1,64}".into());
        }
        let mut t = self.types.clone();
        t.sort();
        t.dedup();
        if t.is_empty() || t.len() != self.types.len() {
            return Err(format!(
                "report {}: types: one or more of protection, failed, sla, storage, each once",
                self.name
            ));
        }
        if self.recipients.is_empty() || self.recipients.len() > MAX_RECIPIENTS {
            return Err(format!(
                "report {}: recipients: 1..={MAX_RECIPIENTS} mail addresses",
                self.name
            ));
        }
        self.schedule().map_err(|e| format!("report {}: {e:#}", self.name))?;
        Ok(())
    }

    /// The range a run at slot `slot` covers: from the previous slot to this one.
    pub fn range_at(&self, slot: i64) -> anyhow::Result<(i64, i64)> {
        let s = self.schedule()?;
        Ok((s.last_slot(slot - 1), slot))
    }

    /// Attachment name of `kind` for a report ending at `to`.
    pub fn attachment(&self, kind: Kind, to: i64) -> String {
        format!("{}-{}-{}.csv", self.name, kind.name(), day(to - 1))
    }
}

pub fn load_scheduled(c: &Connection) -> rusqlite::Result<Vec<Scheduled>> {
    Ok(catalog::setting(c, SETTING)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

/// A composed scheduled report: subject, bodies and the CSV attachments.
pub struct Mail {
    pub subject: String,
    pub html: String,
    pub text: String,
    /// (file name, CSV)
    pub attachments: Vec<(String, String)>,
    pub rows: usize,
}

pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
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

/// Generates the report's tables over `[from, to)` and composes the mail
/// (inline-styled HTML summary, plain-text alternative, one CSV per type).
pub fn compose(c: &Connection, r: &Scheduled, host: &str, from: i64, to: i64, now: i64) -> rusqlite::Result<Mail> {
    let scope = r.tenant.as_deref();
    let range = format!("{} – {}", iso(from), iso(to));
    let who = scope.map_or("all tenants".to_owned(), |t| format!("tenant {t}"));
    let mut html = String::new();
    let mut text = format!("NexusBackup report {} ({who}), {range}\nappliance: {host}\n\n", r.name);
    let _ = write!(
        html,
        "<!DOCTYPE html><html><body style=\"font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1f2933\">\
         <h1 style=\"font-size:20px;margin:0 0 4px\">NexusBackup report {}</h1>\
         <p style=\"margin:0 0 16px;color:#52606d\">{} · {} · appliance {}</p>",
        escape(&r.name),
        escape(&who),
        escape(&range),
        escape(host)
    );
    let mut attachments = Vec::new();
    let mut rows = 0;
    for kind in &r.types {
        let t = generate(c, *kind, scope, from, to, now)?;
        rows += t.rows.len();
        let file = r.attachment(*kind, to);
        let _ = writeln!(text, "{}: {} rows ({file})", kind.title(), t.rows.len());
        let note = if kind.ranged() { "in the range" } else { "current state" };
        let _ = write!(
            html,
            "<h2 style=\"font-size:16px;margin:20px 0 4px\">{}</h2>\
             <p style=\"margin:0 0 8px;color:#52606d\">{} rows ({note}), all in the attachment {}</p>",
            escape(kind.title()),
            t.rows.len(),
            escape(&file)
        );
        if !t.rows.is_empty() {
            html.push_str("<table style=\"border-collapse:collapse;font-size:12px\"><tr>");
            for col in t.columns {
                let _ = write!(
                    html,
                    "<th style=\"text-align:left;border-bottom:2px solid #9aa5b1;padding:4px 8px\">{}</th>",
                    escape(col)
                );
            }
            html.push_str("</tr>");
            for row in t.rows.iter().take(MAIL_ROWS) {
                html.push_str("<tr>");
                for cell in row {
                    let _ = write!(
                        html,
                        "<td style=\"border-bottom:1px solid #e4e7eb;padding:4px 8px\">{}</td>",
                        escape(&cell.to_string())
                    );
                }
                html.push_str("</tr>");
            }
            html.push_str("</table>");
            if t.rows.len() > MAIL_ROWS {
                let _ = write!(
                    html,
                    "<p style=\"color:#52606d\">… {} more rows in the attachment.</p>",
                    t.rows.len() - MAIL_ROWS
                );
            }
        }
        attachments.push((file, t.csv()));
    }
    html.push_str(
        "<p style=\"margin-top:24px;color:#7b8794;font-size:12px\">Times are UTC. Sent by the NexusBackup appliance \
         (Reports page, Scheduled reports).</p></body></html>",
    );
    Ok(Mail {
        subject: format!(
            "[NexusBackup {host}] report {}: {} – {}",
            r.name,
            day(from),
            day(to - 1)
        ),
        html,
        text,
        attachments,
        rows,
    })
}

#[cfg(test)]
mod tests;
