//! Appliance settings pages (docs/phase12-contract.md §3–§5): alert delivery,
//! the appliance's SSH keys and OS updates. The web-api writes intent only:
//! the scheduler delivers alerts and generates / retires keys, `nexus-update`
//! (root, started by `nexus-update.path`) stages and applies images.

use crate::auth::Ctx;
use crate::quorum::{accepted, request};
use crate::{ApiError, ApiResult, St, J};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::alerting::{self, Rule};
use catalog::rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

const ADMIN: &[&str] = &["admin"];
const SETTINGS_READ: &[&str] = &["admin", "security_officer"];
const OPS_READ: &[&str] = &["admin", "operator", "security_officer"];

/// Jobs that belong to no tenant (alert test, SSH keys) carry this tenant name.
pub const APPLIANCE: &str = "-";

/// Queues an appliance job (scheduler-executed, audited like every job).
pub(crate) fn queue(st: &St, ctx: &Ctx, kind: &str, p: Value) -> ApiResult<i64> {
    let id = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
            params![kind, APPLIANCE, p.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "job.create",
        &format!("job/{id}"),
        json!({"kind": kind, "params": p}),
    )?;
    Ok(id)
}

// ---------------------------------------------------------------- alert delivery

pub const ALERTS_SETTING: &str = "alerts";
/// Location owner of the sealed SMTP password (bound to host, port, user).
pub const ALERTS_OWNER: &str = "settings/alerts";
const SEVERITIES: &[&str] = alerting::SEVERITIES;
const MAX_RULES: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpReq {
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default = "yes")]
    starttls: bool,
    from: String,
    /// pre-13f form only (without `rules`): the recipients, now per rule
    #[serde(default)]
    to: Option<Vec<String>>,
    #[serde(default)]
    user: Option<String>,
    /// write-only: omitted / null = keep (refused when host, port or user change)
    #[serde(default)]
    password: Option<String>,
    #[serde(default, rename = "password_set")]
    _password_set: Option<bool>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookReq {
    url: String,
    /// write-only values: null = keep the stored one (refused when the URL changes)
    #[serde(default)]
    headers: BTreeMap<String, Option<String>>,
    #[serde(default)]
    template: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ChannelsReq {
    #[serde(default)]
    email: Vec<String>,
    #[serde(default)]
    webhook: Option<WebhookReq>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleReq {
    name: String,
    #[serde(default)]
    min_severity: Option<String>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    tenants: Vec<String>,
    #[serde(default)]
    channels: ChannelsReq,
}

/// `{smtp, rules, reminder_hours, retention_days}`; the pre-13f form
/// `{webhook_url, smtp: {…, to}, min_severity}` (no `rules`) is still accepted
/// and stored as one rule `default`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsReq {
    #[serde(default)]
    smtp: Option<SmtpReq>,
    #[serde(default)]
    rules: Option<Vec<RuleReq>>,
    #[serde(default)]
    reminder_hours: Option<i64>,
    #[serde(default)]
    retention_days: Option<BTreeMap<String, i64>>,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    min_severity: Option<String>,
}

pub(crate) fn mailbox(s: &str) -> bool {
    let Some((l, d)) = s.split_once('@') else { return false };
    (3..=254).contains(&s.len())
        && !l.is_empty()
        && crate::validate::host(d).is_ok()
        && s.bytes().all(|b| b.is_ascii_graphic() && !b"<>,;\"()[]\\".contains(&b))
}

fn check_webhook(u: &str, what: &str) -> ApiResult<()> {
    let ok = u.len() <= 2048
        && reqwest::Url::parse(u)
            .is_ok_and(|x| matches!(x.scheme(), "https" | "http") && x.host_str().is_some() && x.username().is_empty());
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "{what}: http(s)://host[:port]/path, without user info"
        )))
    }
}

/// The stored setting `alerts` (SMTP server; before 13f also webhook and recipients).
pub fn load_alerts(c: &catalog::rusqlite::Connection) -> ApiResult<Value> {
    Ok(catalog::setting(c, ALERTS_SETTING)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_else(|| json!({"smtp": null})))
}

/// Header values are write-only: shown as null.
fn public_rule(r: &Rule) -> Value {
    let mut v = json!(r);
    if let Some(h) = v["channels"]["webhook"]["headers"].as_object_mut() {
        h.values_mut().for_each(|x| *x = Value::Null);
    }
    v
}

fn alerts_view(c: &catalog::rusqlite::Connection) -> ApiResult<Value> {
    let mut smtp = load_alerts(c)?["smtp"].clone();
    if let Some(s) = smtp.as_object_mut() {
        let set = s.remove("password").is_some_and(|p| !p.is_null());
        s.remove("to");
        s.insert("password_set".into(), json!(set));
    }
    let rules: Vec<Value> = alerting::load_rules(c)?.iter().map(public_rule).collect();
    Ok(
        json!({"smtp": smtp, "rules": rules, "reminder_hours": alerting::reminder_hours(c)?,
              "retention_days": alerting::retention_days(c)?}),
    )
}

pub async fn get_alerts(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(SETTINGS_READ)?;
    Ok(Json(alerts_view(&st.cat.conn())?))
}

fn check_smtp(s: SmtpReq, old: &Value) -> ApiResult<Value> {
    crate::validate::host(&s.host).map_err(|_| ApiError::bad("smtp.host: host name or IP address"))?;
    if s.port == Some(0) {
        return Err(ApiError::bad("smtp.port: 1..=65535"));
    }
    if !mailbox(&s.from) {
        return Err(ApiError::bad("smtp.from: a mail address"));
    }
    if s.user
        .as_ref()
        .is_some_and(|u| !(1..=128).contains(&u.len()) || u.chars().any(char::is_control))
    {
        return Err(ApiError::bad("smtp.user: 1..=128 printable characters"));
    }
    let mut v = json!({"host": s.host, "port": s.port, "starttls": s.starttls, "from": s.from, "user": s.user});
    match s.password {
        Some(p) => {
            if p.is_empty() || p.len() > 1024 || p.chars().any(char::is_control) {
                return Err(ApiError::bad("smtp.password: 1..=1024 printable characters"));
            }
            v["password"] = json!(p);
        }
        None => {
            if let Some(p) = old["password"].as_str() {
                if ["host", "port", "user"].iter().any(|k| old[*k] != v[*k]) {
                    return Err(ApiError::bad(
                        "smtp.password: required again when host, port or user change",
                    ));
                }
                v["password"] = json!(p);
            }
        }
    }
    Ok(v)
}

/// Validates a rule; header values are sealed to the scheduler (null keeps the
/// stored value of the same rule, header and URL).
fn check_rule(st: &St, r: RuleReq, old: &[Rule], smtp: bool) -> ApiResult<Rule> {
    crate::validate::name(&r.name, "rules.name")?;
    let what = |f: &str| format!("rule {}: {f}", r.name);
    let min = r.min_severity.unwrap_or_else(|| "warning".into());
    if !SEVERITIES.contains(&min.as_str()) {
        return Err(ApiError::bad(what("min_severity: info, warning or critical")));
    }
    if r.kinds.len() > 32 || r.kinds.iter().any(|k| crate::validate::name(k, "kind").is_err()) {
        return Err(ApiError::bad(what("kinds: up to 32 alert kinds")));
    }
    if r.tenants.len() > 64 || r.tenants.iter().any(|t| crate::validate::name(t, "tenant").is_err()) {
        return Err(ApiError::bad(what("tenants: up to 64 tenant names")));
    }
    let email = r.channels.email;
    if email.len() > 16 || !email.iter().all(|t| mailbox(t)) {
        return Err(ApiError::bad(what("email: up to 16 mail addresses")));
    }
    if !email.is_empty() && !smtp {
        return Err(ApiError::bad(what("email needs the SMTP server (smtp)")));
    }
    let webhook = match r.channels.webhook {
        None => None,
        Some(w) => {
            check_webhook(&w.url, &what("webhook.url"))?;
            if let Some(t) = &w.template {
                alerting::check_template(t).map_err(|e| ApiError::bad(what(&format!("webhook.template: {e}"))))?;
            }
            if w.headers.len() > 16 {
                return Err(ApiError::bad(what("webhook.headers: at most 16")));
            }
            let prev = old
                .iter()
                .find(|o| o.name == r.name)
                .and_then(|o| o.channels.webhook.as_ref());
            let mut headers = BTreeMap::new();
            for (h, val) in w.headers {
                let token = (1..=64).contains(&h.len())
                    && h.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
                let reserved = ["host", "content-type", "content-length"].contains(&h.to_ascii_lowercase().as_str());
                if !token || reserved {
                    return Err(ApiError::bad(what(&format!(
                        "webhook.headers: invalid header name {h:?}"
                    ))));
                }
                let sealed = match val {
                    Some(v) => {
                        if v.is_empty() || v.len() > 4096 || v.chars().any(char::is_control) {
                            return Err(ApiError::bad(what(
                                "webhook.headers: values of 1..=4096 printable characters",
                            )));
                        }
                        st.seal_key()?
                            .seal(&alerting::header_location(&r.name, &h, &w.url), &v)?
                    }
                    None => match prev.filter(|p| p.url == w.url).and_then(|p| p.headers.get(&h)) {
                        Some(v) => v.clone(),
                        None => {
                            return Err(ApiError::bad(what(&format!(
                                "webhook.headers: a value for {h} is required (new header or URL changed)"
                            ))))
                        }
                    },
                };
                headers.insert(h, sealed);
            }
            Some(alerting::Webhook {
                url: w.url,
                headers,
                template: w.template.filter(|t| !t.trim().is_empty()),
            })
        }
    };
    Ok(Rule {
        name: r.name,
        min_severity: min,
        kinds: r.kinds,
        tenants: r.tenants,
        channels: alerting::Channels { email, webhook },
    })
}

pub async fn put_alerts(State(st): State<St>, ctx: Ctx, J(mut r): J<AlertsReq>) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    let (old, old_rules) = {
        let c = st.cat.conn();
        (load_alerts(&c)?, alerting::load_rules(&c)?)
    };
    let legacy = r.rules.is_none();
    let legacy_to = r.smtp.as_mut().and_then(|s| s.to.take());
    let smtp = match r.smtp {
        None => Value::Null,
        Some(s) => check_smtp(s, &old["smtp"])?,
    };
    let rules_req = match r.rules {
        Some(rules) => {
            if r.webhook_url.is_some() || r.min_severity.is_some() || legacy_to.is_some() {
                return Err(ApiError::bad("rules replace webhook_url, min_severity and smtp.to"));
            }
            rules
        }
        None => {
            // pre-13f form: one rule `default` for every alert kind and tenant
            let to = legacy_to.unwrap_or_default();
            if !smtp.is_null() && to.is_empty() {
                return Err(ApiError::bad("smtp.to: 1..=16 mail addresses"));
            }
            let webhook = r.webhook_url.filter(|u| !u.trim().is_empty());
            if let Some(u) = &webhook {
                check_webhook(u, "webhook_url")?;
            }
            vec![RuleReq {
                name: "default".into(),
                min_severity: Some(r.min_severity.unwrap_or_else(|| "warning".into())),
                kinds: Vec::new(),
                tenants: Vec::new(),
                channels: ChannelsReq {
                    email: to,
                    webhook: webhook.map(|url| WebhookReq {
                        url,
                        headers: BTreeMap::new(),
                        template: None,
                    }),
                },
            }]
        }
    };
    if rules_req.len() > MAX_RULES {
        return Err(ApiError::bad(format!("rules: at most {MAX_RULES}")));
    }
    let mut rules = Vec::new();
    for rr in rules_req {
        if rules.iter().any(|x: &Rule| x.name == rr.name) {
            return Err(ApiError::bad(format!("rules: duplicate name {}", rr.name)));
        }
        rules.push(check_rule(&st, rr, &old_rules, !smtp.is_null())?);
    }
    if legacy && rules[0].channels == alerting::Channels::default() {
        rules.clear();
    }
    let reminder = r.reminder_hours.unwrap_or(alerting::DEFAULT_REMINDER_HOURS);
    if !(0..=24 * 30).contains(&reminder) {
        return Err(ApiError::bad("reminder_hours: 0 (never) ..= 720"));
    }
    let retention = match r.retention_days {
        None => alerting::retention_days(&st.cat.conn())?,
        Some(m) => {
            if m.iter()
                .any(|(k, d)| !SEVERITIES.contains(&k.as_str()) || !(1..=3650).contains(d))
            {
                return Err(ApiError::bad(
                    "retention_days: {info, warning, critical}: 1..=3650 days",
                ));
            }
            m
        }
    };
    let mut new = json!({"smtp": smtp});
    if new["smtp"]["password"]
        .as_str()
        .is_some_and(|p| !catalog::secret::is_sealed(p))
    {
        st.seal_key()?.seal_all(ALERTS_OWNER, &mut new)?;
    }
    let shown = {
        let c = st.cat.conn();
        catalog::set_setting(&c, ALERTS_SETTING, &new.to_string())?;
        catalog::set_setting(&c, alerting::RULES_SETTING, &json!(rules).to_string())?;
        catalog::set_setting(&c, alerting::REMINDER_SETTING, &reminder.to_string())?;
        catalog::set_setting(&c, alerting::RETENTION_SETTING, &json!(retention).to_string())?;
        alerts_view(&c)?
    };
    st.audit(ctx.name(), "settings.alerts", "settings/alerts", shown.clone())?;
    Ok(Json(shown))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TestReq {
    #[serde(default)]
    rule: Option<String>,
}

/// A JSON body that may be absent (older clients post without one).
pub fn opt_body<T: serde::de::DeserializeOwned + Default>(b: &[u8]) -> ApiResult<T> {
    if b.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(b).map_err(|e| ApiError::bad(e.to_string()))
}

/// One `test` alert through the channels of rule `rule` (every rule if absent),
/// sent by the scheduler (it holds the secrets). Waits up to 45 s for the
/// result (`"ok"` / `"error: …"` per channel: `{webhook?, email?}` for one rule,
/// `{"<rule>/<channel>": …}` for all); slower → 202 `{job_id}` (the result
/// lands in the job).
pub async fn test_alerts(State(st): State<St>, ctx: Ctx, body: Bytes) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let r: TestReq = opt_body(&body)?;
    if let Some(n) = &r.rule {
        crate::validate::name(n, "rule")?;
    }
    let p = match r.rule {
        Some(n) => json!({"rule": n}),
        None => json!({}),
    };
    let id = queue(&st, &ctx, "alert_test", p)?;
    wait_test_job(&st, id, "alert test").await
}

/// Queues the appliance job `kind` and waits up to 45 s for its JSON result
/// (slower → 202 `{job_id}`).
pub async fn run_test_job(st: &St, ctx: &Ctx, kind: &str, p: Value, what: &str) -> ApiResult<Response> {
    let id = queue(st, ctx, kind, p)?;
    wait_test_job(st, id, what).await
}

async fn wait_test_job(st: &St, id: i64, what: &str) -> ApiResult<Response> {
    for _ in 0..180 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let row: Option<(String, Option<String>, String)> = st
            .cat
            .conn()
            .query_row("SELECT state, result, log FROM jobs WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        match row {
            Some((s, Some(res), _)) if s == "ok" => {
                let v: Value = serde_json::from_str(&res).unwrap_or(Value::Null);
                return Ok(Json(v).into_response());
            }
            Some((s, _, log)) if s == "failed" || s == "cancelled" => {
                return Err(ApiError::conflict(format!(
                    "{what} failed: {}",
                    log.lines().last().unwrap_or("see the job log")
                )))
            }
            _ => {}
        }
    }
    Ok((StatusCode::ACCEPTED, Json(json!({"job_id": id}))).into_response())
}

// ---------------------------------------------------------------- SSH keys

/// Published by the scheduler (public halves only, `/etc/nexus/ssh`).
pub const SSH_KEYS_SETTING: &str = "ssh_keys";

fn ssh_keys(st: &St) -> ApiResult<Vec<Value>> {
    Ok(catalog::setting(&st.cat.conn(), SSH_KEYS_SETTING)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

pub async fn list_ssh_keys(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(OPS_READ)?;
    Ok(Json(json!(ssh_keys(&st)?)))
}

fn known_key(st: &St, name: &str) -> ApiResult<Value> {
    ssh_keys(st)?
        .into_iter()
        .find(|k| k["name"] == name)
        .ok_or_else(ApiError::not_found)
}

/// Quorum `ssh_key.rotate` (approvals on); the scheduler generates the new
/// key, the old one stays in use until `retire`.
pub async fn rotate_ssh_key(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let k = known_key(&st, &name)?;
    if !k["previous"].is_null() {
        return Err(ApiError::conflict(
            "a new key is waiting already: add it to the sources, then retire the old one",
        ));
    }
    let o = request(
        &st,
        &ctx,
        "ssh_key.rotate",
        &format!("ssh_key/{name}"),
        json!({"name": name, "fingerprint": k["fingerprint"]}),
    )?;
    Ok(accepted(o, json!({})))
}

/// Makes the rotated key the one in use and deletes the old one (job `ssh_key_retire`).
pub async fn retire_ssh_key(State(st): State<St>, ctx: Ctx, Path(name): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let k = known_key(&st, &name)?;
    if k["previous"].is_null() {
        return Err(ApiError::conflict("nothing to retire: rotate the key first"));
    }
    let id = queue(&st, &ctx, "ssh_key_retire", json!({"name": name}))?;
    st.audit(
        ctx.name(),
        "ssh_key.retire",
        &format!("ssh_key/{name}"),
        json!({"old": k["previous"]["fingerprint"], "new": k["fingerprint"], "job": id}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"job_id": id}))).into_response())
}

// ---------------------------------------------------------------- updates

fn update_dir(st: &St) -> std::path::PathBuf {
    st.update_dir
        .get_or_init(|| {
            std::env::var_os("NEXUS_UPDATE_DIR")
                .map(Into::into)
                .unwrap_or_else(|| "/var/lib/nexus/update".into())
        })
        .clone()
}

/// The contract view: `api` as `nexus-update` writes it into status.json
/// (`nexus-update status --json` prints the same), plus a request still waiting.
pub fn update_status(dir: &std::path::Path) -> Value {
    let raw: Option<Value> = std::fs::read(dir.join("status.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let mut v = raw
        .as_ref()
        .map(|r| r["api"].clone())
        .filter(Value::is_object)
        .unwrap_or_else(|| {
            json!({"booted": null, "staged": null, "available": null, "channel": null, "window": null,
                   "last_check": null, "status": "error", "rollback": null,
                   "error": "no update status yet (nexus-update has not run on this appliance)"})
        });
    if let Ok(req) = std::fs::read_to_string(dir.join("request")) {
        v["status"] = json!("checking");
        v["pending_request"] = json!(req.trim());
    }
    v
}

pub async fn get_updates(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(OPS_READ)?;
    Ok(Json(update_status(&update_dir(&st))))
}

/// Writes the one-word request for `nexus-update.path` (tmp + rename).
fn update_request(st: &St, word: &str) -> ApiResult<()> {
    let dir = update_dir(st);
    let tmp = dir.join(".request.tmp");
    std::fs::write(&tmp, format!("{word}\n")).map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, dir.join("request")).map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?;
    Ok(())
}

pub async fn check_updates(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    update_request(&st, "stage")?;
    st.audit(ctx.name(), "update.check", "appliance/update", json!({}))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"status": "checking"}))).into_response())
}

/// Stages now / reboots into the staged image: quorum `update.apply` while
/// approvals are enabled (the request file is written once it is approved).
pub async fn apply_update(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let s = update_status(&update_dir(&st));
    let o = request(
        &st,
        &ctx,
        "update.apply",
        "appliance/update",
        json!({"staged": s["staged"], "booted": s["booted"]}),
    )?;
    Ok(accepted(o, json!({})))
}

/// After an executed quorum action (approved, or direct with approvals off).
pub fn after_approve(st: &St, action: &str, actor: &str, p: &Value) {
    let r = match action {
        "update.apply" => update_request(st, "apply"),
        "oidc.update" => serde_json::from_value(p["settings"].clone())
            .map_err(|e| ApiError::bad(e.to_string()))
            .and_then(|s| crate::oidc::audit_applied(st, actor, &s)),
        _ => Ok(()),
    };
    if let Err(e) = r {
        eprintln!("<3>web-api: after {action}: {}", e.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_addresses() {
        assert!(mailbox("ops@example.com"));
        for bad in [
            "ops",
            "@example.com",
            "a@b c",
            "a<b>@example.com",
            "a@-x.example",
            "a@b@c.example",
        ] {
            assert!(!mailbox(bad), "{bad}");
        }
    }

    #[test]
    fn update_status_view() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(update_status(d.path())["status"], "error");
        std::fs::write(
            d.path().join("status.json"),
            r#"{"api": {"status": "idle", "booted": {"version": "1"}}, "booted": {}}"#,
        )
        .unwrap();
        assert_eq!(update_status(d.path())["status"], "idle");
        std::fs::write(d.path().join("request"), "stage\n").unwrap();
        let v = update_status(d.path());
        assert_eq!(
            (v["status"].as_str(), v["pending_request"].as_str()),
            (Some("checking"), Some("stage"))
        );
    }
}
