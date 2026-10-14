//! PSA ticketing (Phase 33, docs/control-plane.md "PSA ticketing"): a
//! notification rule's `psa` channel opens one ticket per alert key in HaloPSA,
//! ConnectWise PSA or Autotask, adds a note when the open alert repeats (at
//! most hourly) or escalates, and closes the ticket once the alert is resolved
//! (by its success path or by a person). `psa_tickets` (catalog v46) remembers
//! the ticket per (rule, key); an alert raised again under the same key while
//! its ticket is still open continues that ticket.
//!
//! Authentication per vendor: HaloPSA OAuth2 client credentials (token cached
//! until shortly before it expires); ConnectWise PSA API member keys (Basic
//! `company+public:private` and the `clientId` header; ConnectWise offers no
//! client-credentials grant for API members); Autotask API user headers
//! (`UserName`, `Secret`, `ApiIntegrationCode`). Credentials are sealed to the
//! scheduler at `alerting::psa_location` and opened in `AlertsConfig::from_setting`.
//!
//! Runs on its own thread like the forwarder (one round every `psa_poll_secs`),
//! so a slow PSA never stalls the tick loop. A failing rule is retried every
//! round; after 15 minutes `Scheduler::check_psa` raises the `psa` alert.
//! Redirects are not followed (credentials go to the configured hosts only);
//! every PSA host is on the egress allow-list (`firewall::alert_targets`).

use crate::alerts::{Alert, AlertsConfig};
use crate::Scheduler;
use anyhow::{bail, Context, Result};
use base64::Engine;
use catalog::alerting::{self, Psa, Rule};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::secret::SchedulerKey;
use catalog::Catalog;
use reqwest::blocking::{Client, RequestBuilder};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// A repeat adds a note at most this often (an escalation at once).
pub const NOTE_EVERY_SECS: i64 = 3600;
/// `psa` alert after a rule has failed this long.
pub const ALERT_AFTER_SECS: i64 = 15 * 60;
/// Tickets opened, noted or closed per rule and round (the rest next round).
const OPS_PER_ROUND: usize = 50;
const TIMEOUT: Duration = Duration::from_secs(20);
/// Longest summary / title sent (ConnectWise limits it to 100 characters).
const SUMMARY_MAX: usize = 100;

fn http() -> Result<Client> {
    Ok(Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("nexus-scheduler/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

fn cut(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// `[NexusBackup <host>] <severity> <kind>: <message>` (cut to the summary limit).
pub fn summary(a: &Alert) -> String {
    let first = a.message.lines().next().unwrap_or_default();
    cut(
        &format!("[NexusBackup {}] {} {}: {first}", a.host, a.severity, a.kind),
        SUMMARY_MAX,
    )
}

/// The ticket text: message, what to do, the facts and the link to the alert.
pub fn details(a: &Alert) -> String {
    format!(
        "{}\n\nWhat to do: {}\n\nseverity: {}\nkind: {}\ncategory: {}\ntenant: {}\nalert id: {}\nfirst seen (unix): {}\nappliance: {}\n{}\n",
        a.message,
        a.hint,
        a.severity,
        a.kind,
        a.category,
        a.tenant.as_deref().unwrap_or("-"),
        a.id,
        a.first_ts,
        a.host,
        a.alert_url
    )
}

/// The ID in a create answer: HaloPSA returns the ticket (or a list of them),
/// ConnectWise `{id}`, Autotask `{itemId}`.
fn created_id(v: &Value) -> Option<String> {
    let t = match v {
        Value::Array(a) => a.first()?,
        v => v,
    };
    match t.get("id").or_else(|| t.get("itemId"))? {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn num(field: &str, v: Option<&str>) -> Result<Option<i64>> {
    v.map(|s| s.trim().parse::<i64>().with_context(|| format!("{field}: a number")))
        .transpose()
}

/// One PSA endpoint with its opened secret.
pub struct Api<'a> {
    http: &'a Client,
    p: &'a Psa,
    /// HaloPSA: cached (token, valid until)
    token: Option<(String, i64)>,
}

impl<'a> Api<'a> {
    pub fn new(http: &'a Client, p: &'a Psa) -> Self {
        Api { http, p, token: None }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.p.url.trim_end_matches('/'))
    }

    /// HaloPSA: an OAuth2 client-credentials token (`scope=all`).
    fn halo_token(&mut self, now: i64) -> Result<String> {
        if let Some((t, until)) = &self.token {
            if *until > now {
                return Ok(t.clone());
            }
        }
        let token_url = self.p.token_url.as_deref().context("token_url missing")?;
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", self.p.client_id.as_deref().unwrap_or_default()),
            ("client_secret", self.p.secret.as_str()),
            ("scope", "all"),
        ];
        let mut url = reqwest::Url::parse(token_url).context("token_url")?;
        if let Some(t) = self.p.company.as_deref().filter(|t| !t.is_empty()) {
            url.query_pairs_mut().append_pair("tenant", t);
        }
        let r = self.http.post(url).form(&form).send()?;
        let status = r.status();
        let v: Value = r.json().unwrap_or(Value::Null);
        if !status.is_success() {
            bail!(
                "token endpoint answered {status}{}",
                v["error"].as_str().map(|e| format!(" ({e})")).unwrap_or_default()
            );
        }
        let t = v["access_token"]
            .as_str()
            .context("token endpoint: no access_token")?
            .to_owned();
        let life = v["expires_in"].as_i64().unwrap_or(300);
        self.token = Some((t.clone(), now + (life - 60).max(30)));
        Ok(t)
    }

    fn auth(&mut self, req: RequestBuilder, now: i64) -> Result<RequestBuilder> {
        let p = self.p;
        Ok(match p.vendor.as_str() {
            "halopsa" => req.bearer_auth(self.halo_token(now)?),
            "connectwise" => {
                let user = format!(
                    "{}+{}:{}",
                    p.company.as_deref().unwrap_or_default(),
                    p.username.as_deref().unwrap_or_default(),
                    p.secret
                );
                req.header(
                    "Authorization",
                    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(user)),
                )
                .header("clientId", p.client_id.as_deref().unwrap_or_default())
            }
            "autotask" => req
                .header("UserName", p.username.as_deref().unwrap_or_default())
                .header("Secret", &p.secret)
                .header("ApiIntegrationCode", p.integration_code.as_deref().unwrap_or_default()),
            v => bail!("unknown PSA vendor {v:?}"),
        })
    }

    fn send(&mut self, req: RequestBuilder, body: &Value, now: i64, what: &str) -> Result<Value> {
        let r = self.auth(req, now)?.json(body).send()?;
        let status = r.status();
        let text = r.text().unwrap_or_default();
        if !status.is_success() {
            bail!("{what}: {status} {}", cut(text.trim(), 300));
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Opens a ticket for `a`; returns its ID.
    pub fn create(&mut self, a: &Alert, now: i64) -> Result<String> {
        let p = self.p;
        let (req, body) = match p.vendor.as_str() {
            "halopsa" => {
                let mut t = json!({"summary": summary(a), "details": details(a)});
                if let Some(x) = num("board", p.board.as_deref())? {
                    t["tickettype_id"] = json!(x);
                }
                if let Some(x) = num("account", p.account.as_deref())? {
                    t["client_id"] = json!(x);
                }
                (self.http.post(self.url("/Tickets")), json!([t]))
            }
            "connectwise" => {
                let mut t = json!({"summary": summary(a), "initialDescription": details(a)});
                if let Some(b) = p.board.as_deref() {
                    t["board"] = match b.trim().parse::<i64>() {
                        Ok(id) => json!({"id": id}),
                        Err(_) => json!({"name": b}),
                    };
                }
                if let Some(c) = p.account.as_deref() {
                    t["company"] = json!({"identifier": c});
                }
                (self.http.post(self.url("/service/tickets")), t)
            }
            "autotask" => {
                let mut t = json!({
                    "companyID": num("account", p.account.as_deref())?.context("account (companyID) missing")?,
                    "title": cut(&summary(a), 255), "description": cut(&details(a), 8000),
                    "status": 1, "priority": if a.severity == "critical" { 1 } else { 2 },
                });
                if let Some(x) = num("board", p.board.as_deref())? {
                    t["queueID"] = json!(x);
                }
                (self.http.post(self.url("/Tickets")), t)
            }
            v => bail!("unknown PSA vendor {v:?}"),
        };
        let v = self.send(req, &body, now, "create ticket")?;
        created_id(&v)
            .with_context(|| format!("create ticket: no ticket ID in the answer {}", cut(&v.to_string(), 200)))
    }

    /// Adds an internal note to ticket `id`.
    pub fn note(&mut self, id: &str, text: &str, now: i64) -> Result<()> {
        let (req, body) = match self.p.vendor.as_str() {
            "halopsa" => (
                self.http.post(self.url("/Actions")),
                json!([{"ticket_id": id.parse::<i64>().unwrap_or_default(), "note": text, "outcome": "Note",
                        "hiddenfromuser": true}]),
            ),
            "connectwise" => (
                self.http.post(self.url(&format!("/service/tickets/{id}/notes"))),
                json!({"text": text, "internalAnalysisFlag": true}),
            ),
            "autotask" => (
                self.http.post(self.url(&format!("/Tickets/{id}/Notes"))),
                json!({"title": "NexusBackup", "description": cut(text, 3200), "noteType": 1, "publish": 1}),
            ),
            v => bail!("unknown PSA vendor {v:?}"),
        };
        self.send(req, &body, now, "add note").map(drop)
    }

    /// Closes ticket `id` (a note with `why` first).
    pub fn close(&mut self, id: &str, why: &str, now: i64) -> Result<()> {
        self.note(id, why, now)?;
        let closed = self.p.closed_status.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let (req, body) = match self.p.vendor.as_str() {
            "halopsa" => (
                self.http.post(self.url("/Tickets")),
                json!([{"id": id.parse::<i64>().unwrap_or_default(),
                        "status_id": num("closed_status", closed)?.unwrap_or(9)}]),
            ),
            "connectwise" => {
                let status = match closed.map(|c| c.parse::<i64>()) {
                    Some(Ok(n)) => json!({"id": n}),
                    _ => json!({"name": closed.unwrap_or("Closed")}),
                };
                (
                    self.http.patch(self.url(&format!("/service/tickets/{id}"))),
                    json!([{"op": "replace", "path": "status", "value": status}]),
                )
            }
            "autotask" => (
                self.http.patch(self.url("/Tickets")),
                json!({"id": id.parse::<i64>().unwrap_or_default(),
                       "status": num("closed_status", closed)?.unwrap_or(5)}),
            ),
            v => bail!("unknown PSA vendor {v:?}"),
        };
        self.send(req, &body, now, "close ticket").map(drop)
    }
}

/// Settings → Alert delivery → Test: opens a ticket for the test alert and closes it again.
pub fn test(p: &Psa, a: &Alert) -> Result<String> {
    let http = http()?;
    let mut api = Api::new(&http, p);
    let now = catalog::now();
    let id = api.create(a, now)?;
    api.close(&id, "Test ticket from the NexusBackup appliance: closed at once.", now)
        .with_context(|| format!("ticket {id} was opened but could not be closed"))?;
    Ok(id)
}

/// An open alert as the rounds need it.
struct Open {
    alert: Alert,
    key: String,
}

/// An open ticket.
struct Ticket {
    id: i64,
    key: String,
    ticket: String,
    alert_id: i64,
    noted_count: i64,
    noted_at: i64,
    noted_severity: String,
}

/// The ticketing worker (one per scheduler; [`spawn`]).
pub struct Ticketing {
    db: Arc<Catalog>,
    key: SchedulerKey,
    host: String,
    file: PathBuf,
    http: Client,
    /// HaloPSA tokens per rule: (secret location, token, valid until)
    tokens: HashMap<String, (String, String, i64)>,
}

impl Ticketing {
    pub fn new(db: Arc<Catalog>, key: SchedulerKey, host: String, file: PathBuf) -> Result<Self> {
        Ok(Ticketing {
            db,
            key,
            host,
            file,
            http: http()?,
            tokens: HashMap::new(),
        })
    }

    /// One round over every rule with a PSA channel.
    pub fn step(&mut self, now: i64) {
        let cfg = match AlertsConfig::current(&self.db, &self.key, &self.file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("<3>psa: alert delivery configuration: {e:#}");
                return;
            }
        };
        let rules: Vec<&Rule> = cfg.rules.iter().filter(|r| r.channels.psa.is_some()).collect();
        if let Err(e) = self.forget_removed(&rules) {
            eprintln!("<3>psa: {e:#}");
        }
        if rules.is_empty() {
            return;
        }
        let open = match self.open_alerts() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("<3>psa: open alerts: {e:#}");
                return;
            }
        };
        for r in rules {
            let res = self.round(r, &open, now);
            let c = self.db.conn();
            let w = match &res {
                Ok(()) => c.execute(
                    "INSERT INTO psa_state (rule, last_ok) VALUES (?1, ?2) ON CONFLICT(rule) DO UPDATE SET
                       last_ok = ?2, failing_since = NULL, last_error = NULL",
                    params![r.name, now],
                ),
                Err(e) => {
                    let msg = format!("{e:#}");
                    eprintln!("<4>psa: rule {}: {msg}", r.name);
                    c.execute(
                        "INSERT INTO psa_state (rule, failing_since, last_error) VALUES (?1, ?2, ?3)
                         ON CONFLICT(rule) DO UPDATE SET failing_since = COALESCE(failing_since, ?2), last_error = ?3",
                        params![r.name, now, msg],
                    )
                }
            };
            if let Err(e) = w {
                eprintln!("<3>psa: state: {e:#}");
            }
        }
    }

    /// Tickets and state of rules that no longer have a PSA channel are dropped
    /// (nothing can update those tickets any more).
    fn forget_removed(&self, rules: &[&Rule]) -> Result<()> {
        let names: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();
        let list = serde_json::to_string(&names)?;
        let c = self.db.conn();
        c.execute(
            "DELETE FROM psa_tickets WHERE rule NOT IN (SELECT value FROM json_each(?1))",
            [&list],
        )?;
        c.execute(
            "DELETE FROM psa_state WHERE rule NOT IN (SELECT value FROM json_each(?1))",
            [&list],
        )?;
        Ok(())
    }

    fn open_alerts(&self) -> Result<Vec<Open>> {
        let c = self.db.conn();
        let mut q = c.prepare(
            "SELECT id, ts, COALESCE(last_ts, ts), count, severity, kind, message, tenant, key FROM alerts
             WHERE resolved_at IS NULL ORDER BY id",
        )?;
        let rows = q.query_map([], |r| {
            let id = r.get(0)?;
            let kind: String = r.get(5)?;
            Ok(Open {
                alert: Alert {
                    id,
                    ts: r.get(1)?,
                    first_ts: r.get(1)?,
                    last_ts: r.get(2)?,
                    count: r.get(3)?,
                    severity: r.get(4)?,
                    hint: alerting::hint(&kind).into(),
                    category: alerting::category(&kind).into(),
                    kind,
                    message: r.get(6)?,
                    tenant: r.get(7)?,
                    host: self.host.clone(),
                    alert_url: Alert::url(&self.host, id),
                },
                key: r.get::<_, Option<String>>(8)?.unwrap_or_else(|| format!("alert:{id}")),
            })
        })?;
        Ok(rows
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|o| !alerting::PSA_SKIP_KINDS.contains(&o.alert.kind.as_str()))
            .collect())
    }

    fn tickets(&self, rule: &str) -> Result<Vec<Ticket>> {
        let c = self.db.conn();
        let mut q = c.prepare(
            "SELECT id, key, ticket, alert_id, noted_count, noted_at, noted_severity FROM psa_tickets
             WHERE rule = ?1 AND closed IS NULL ORDER BY id",
        )?;
        let rows = q.query_map([rule], |r| {
            Ok(Ticket {
                id: r.get(0)?,
                key: r.get(1)?,
                ticket: r.get(2)?,
                alert_id: r.get(3)?,
                noted_count: r.get(4)?,
                noted_at: r.get(5)?,
                noted_severity: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Opens, notes and closes the tickets of one rule. Stops at the first PSA
    /// error (the rest waits for the next round).
    fn round(&mut self, r: &Rule, open: &[Open], now: i64) -> Result<()> {
        let p = r.channels.psa.as_ref().expect("rules with a psa channel");
        let loc = alerting::psa_location(&r.name, p);
        let mut api = Api::new(&self.http, p);
        // a token survives rounds while the rule's endpoint and secret stay the same
        if let Some((l, t, until)) = self.tokens.get(&r.name) {
            if *l == loc {
                api.token = Some((t.clone(), *until));
            }
        }
        let res = self.round_with(&mut api, r, open, now);
        if let Some((t, until)) = api.token.take() {
            self.tokens.insert(r.name.clone(), (loc, t, until));
        }
        res
    }

    fn round_with(&self, api: &mut Api, r: &Rule, open: &[Open], now: i64) -> Result<()> {
        let tickets = self.tickets(&r.name)?;
        let matching: Vec<&Open> = open
            .iter()
            .filter(|o| r.matches(&o.alert.severity, &o.alert.kind, o.alert.tenant.as_deref()))
            .collect();
        let mut ops = 0;
        // resolved: close
        for t in &tickets {
            if ops >= OPS_PER_ROUND {
                return Ok(());
            }
            if matching.iter().any(|o| o.key == t.key) {
                continue;
            }
            let how: Option<String> = self
                .db
                .conn()
                .query_row("SELECT resolved_by FROM alerts WHERE id = ?1", [t.alert_id], |row| {
                    row.get(0)
                })
                .optional()?
                .flatten();
            let why = match how.as_deref() {
                Some("scheduler") | None => "Resolved on the NexusBackup appliance: the problem went away.".to_owned(),
                Some(who) => format!("Resolved on the NexusBackup appliance by {who}."),
            };
            api.close(&t.ticket, &why, now)
                .with_context(|| format!("ticket {}", t.ticket))?;
            ops += 1;
            self.db
                .conn()
                .execute("UPDATE psa_tickets SET closed = ?2 WHERE id = ?1", params![t.id, now])?;
        }
        for o in &matching {
            if ops >= OPS_PER_ROUND {
                return Ok(());
            }
            let a = &o.alert;
            match tickets.iter().find(|t| t.key == o.key) {
                None => {
                    let id = api.create(a, now)?;
                    ops += 1;
                    self.db.conn().execute(
                        "INSERT INTO psa_tickets (rule, key, vendor, ticket, alert_id, opened, noted_count, noted_at,
                           noted_severity) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6, ?8)",
                        params![r.name, o.key, api.p.vendor, id, a.id, now, a.count, a.severity],
                    )?;
                    eprintln!("psa: rule {}: ticket {id} opened for alert {}", r.name, a.id);
                }
                Some(t) => {
                    let again = t.alert_id != a.id;
                    let up = alerting::rank(&a.severity) > alerting::rank(&t.noted_severity);
                    let repeat = a.count > t.noted_count && now - t.noted_at >= NOTE_EVERY_SECS;
                    if !(again || up || repeat) {
                        continue;
                    }
                    let text = if again {
                        format!(
                            "Raised again on the NexusBackup appliance (alert {}, {}): {}\n{}",
                            a.id, a.severity, a.message, a.alert_url
                        )
                    } else if up {
                        format!("Escalated to {}: {}\n{}", a.severity, a.message, a.alert_url)
                    } else {
                        format!(
                            "Seen again: {} times in total, last at {} (unix): {}",
                            a.count, a.last_ts, a.message
                        )
                    };
                    api.note(&t.ticket, &text, now)
                        .with_context(|| format!("ticket {}", t.ticket))?;
                    ops += 1;
                    self.db.conn().execute(
                        "UPDATE psa_tickets SET alert_id = ?2, noted_count = ?3, noted_at = ?4, noted_severity = ?5
                         WHERE id = ?1",
                        params![t.id, a.id, a.count, now, a.severity],
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// The ticketing thread (one round every `poll`).
pub fn spawn(db: Arc<Catalog>, key: SchedulerKey, host: String, file: PathBuf, poll: Duration) -> Result<()> {
    let mut t = Ticketing::new(db, key, host, file)?;
    std::thread::spawn(move || loop {
        t.step(catalog::now());
        std::thread::sleep(poll);
    });
    Ok(())
}

impl Scheduler {
    /// Each tick: the `psa:<rule>` alert of a rule failing for
    /// [`ALERT_AFTER_SECS`] (resolved when it works again or the rule is gone).
    pub(crate) fn check_psa(&mut self, now: i64) -> Result<()> {
        let states: Vec<(String, Option<i64>, Option<String>)> = {
            let c = self.db.conn();
            let mut q = c.prepare("SELECT rule, failing_since, last_error FROM psa_state")?;
            let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let open: Vec<String> = {
            let c = self.db.conn();
            let mut q = c.prepare("SELECT key FROM alerts WHERE kind = 'psa' AND resolved_at IS NULL")?;
            let rows = q.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (rule, since, err) in &states {
            let key = format!("psa:{rule}");
            match since {
                Some(t) if now - t >= ALERT_AFTER_SECS => self.raise(
                    "warning",
                    "psa",
                    &key,
                    &format!(
                        "PSA ticketing of alert rule {rule} has failed for {} minutes: {}",
                        (now - t) / 60,
                        err.as_deref().unwrap_or_default()
                    ),
                    None,
                )?,
                Some(_) => {}
                None => self.resolve(&key)?,
            }
        }
        for key in open {
            let rule = key.strip_prefix("psa:").unwrap_or_default();
            if !states.iter().any(|(r, ..)| r == rule) {
                self.resolve(&key)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert() -> Alert {
        Alert {
            id: 7,
            ts: 1,
            first_ts: 1,
            last_ts: 2,
            count: 1,
            severity: "critical".into(),
            kind: "job_failed".into(),
            category: "backup".into(),
            message: "backup of group nightly failed: no route to host\nsecond line".into(),
            hint: "fix it".into(),
            tenant: Some("acme".into()),
            host: "nexus".into(),
            alert_url: "https://nexus/#/alerts?id=7".into(),
        }
    }

    #[test]
    fn ticket_texts() {
        let a = alert();
        let s = summary(&a);
        assert_eq!(
            s,
            "[NexusBackup nexus] critical job_failed: backup of group nightly failed: no route to host"
        );
        let mut long = a.clone();
        long.message = "x".repeat(500);
        assert_eq!(summary(&long).chars().count(), SUMMARY_MAX);
        let d = details(&a);
        assert!(d.contains("What to do: fix it") && d.contains("tenant: acme") && d.ends_with("id=7\n"));
    }

    #[test]
    fn created_ids() {
        assert_eq!(created_id(&json!({"id": 12})).as_deref(), Some("12"));
        assert_eq!(created_id(&json!([{"id": 13, "summary": "x"}])).as_deref(), Some("13"));
        assert_eq!(created_id(&json!({"itemId": 14})).as_deref(), Some("14"));
        assert_eq!(created_id(&json!({"id": "T-15"})).as_deref(), Some("T-15"));
        assert_eq!(created_id(&json!({"id": ""})), None);
        assert_eq!(created_id(&json!({})), None);
        assert_eq!(created_id(&Value::Null), None);
    }
}
