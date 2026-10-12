//! Expiry alerts (Phase 14d), kind `cert_expiry`, key `cert_expiry:<what>`:
//! 90 days before → info, 30 → warning, 7 (and once expired) → critical;
//! resolved when renewed or gone. Checked with every full refresh.
//! - `web`, `identity`: the served web certificate and the self-signed identity
//!   (replication secondaries pin it); dates from the setting `tls_status`, which
//!   the web-api publishes (the scheduler cannot read /etc/nexus/tls);
//! - `agent:<id>`: agent certificates: `agents.cert_expires` as reported by the
//!   last session (renewal.rs), else 10 years from enrollment (agent-conn `ca.rs`);
//!   renewed automatically 30 days (or 10 % of the lifetime) before expiry;
//! - `agent_ca`: the appliance's client certificate for agents (10 years) and the
//!   agent CA (20 years), created with the first enrollment;
//! - `replication_peer:<id>`: secondaries' client certificates (10 years from
//!   enrollment, replication `ca.rs`);
//! - `oidc_secret`: the IdP client secret, if its expiry was entered;
//! - `token:<id>`: API tokens, info only, during their last 7 days.

use super::*;
use catalog::alerting;

pub const DAY: i64 = 86400;
/// agent-conn / replication `validity(.., 10)`: 10 × 365 days
const TEN_YEARS: i64 = 3650 * DAY;
/// earliest agent enrollment seen (the agent CA is created by the first one)
pub const AGENT_CA_SETTING: &str = "agent_ca_created";
const PREFIX: &str = "cert_expiry:";

/// `None` while more than 90 days are left.
pub fn severity(not_after: i64, now: i64) -> Option<&'static str> {
    match not_after - now {
        l if l <= 7 * DAY => Some("critical"),
        l if l <= 30 * DAY => Some("warning"),
        l if l <= 90 * DAY => Some("info"),
        _ => None,
    }
}

fn when(not_after: i64, now: i64) -> String {
    match (not_after - now) / DAY {
        d if not_after <= now => format!("expired {} day(s) ago", -d),
        0 => "expires today".into(),
        d => format!("expires in {d} day(s)"),
    }
}

struct Item {
    key: String,
    what: String,
    not_after: i64,
    tenant: Option<String>,
    /// API tokens: an info alert, only in the last 7 days
    token: bool,
}

impl Scheduler {
    fn expiry_items(&self, now: i64) -> Result<Vec<Item>> {
        let mut v = vec![];
        let item = |key: String, what: String, not_after: i64, tenant: Option<String>| Item {
            key,
            what,
            not_after,
            tenant,
            token: false,
        };
        let c = self.db.conn();
        let tls = catalog::setting(&c, "tls_status")?
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .unwrap_or_default();
        let imported = tls["web"]["imported"] == json!(true);
        for (k, what) in [
            ("web", "The web certificate"),
            (
                "identity",
                "The self-signed appliance certificate (pinned by replication secondaries)",
            ),
        ] {
            // without an import the web certificate is the identity one: one alert
            if k == "web" && !imported {
                continue;
            }
            if let Some(t) = tls[k]["not_after"].as_i64() {
                let subject = tls[k]["subject"].as_str().unwrap_or_default();
                v.push(item(k.into(), format!("{what} {subject}"), t, None));
            }
        }
        let mut q =
            c.prepare("SELECT id, tenant, name, enrolled_at, cert_expires FROM agents WHERE enrolled_at IS NOT NULL")?;
        let agents = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut first = catalog::setting(&c, AGENT_CA_SETTING)?.and_then(|s| s.parse::<i64>().ok());
        for (id, tenant, name, at, expires) in agents {
            first = Some(first.map_or(at, |f| f.min(at)));
            v.push(item(
                format!("agent:{id}"),
                format!(
                    "The certificate of agent {tenant}/{name} (renewed automatically; Agents → Renew certificate, \
                     or re-enroll the agent)"
                ),
                expires.unwrap_or(at + TEN_YEARS),
                Some(tenant),
            ));
        }

        if let Some(f) = first {
            catalog::set_setting(&c, AGENT_CA_SETTING, &f.to_string())?;
            v.push(item(
                "agent_ca".into(),
                "The appliance's client certificate for agents (agent CA)".into(),
                f + TEN_YEARS,
                None,
            ));
        }
        let mut q = c.prepare(
            "SELECT id, name, enrolled_at FROM replication_peers WHERE state = 'enrolled' AND enrolled_at IS NOT NULL",
        )?;
        let peers = q
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (id, name, at) in peers {
            v.push(item(
                format!("replication_peer:{id}"),
                format!("The client certificate of replication secondary {name} (enroll it again to renew)"),
                at + TEN_YEARS,
                None,
            ));
        }
        let oidc = catalog::setting(&c, "oidc")?
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .unwrap_or_default();
        if let Some(t) = oidc["client_secret_expires"].as_i64() {
            v.push(item(
                "oidc_secret".into(),
                "The OIDC client secret (create a new one at the IdP, enter it in Settings → Single sign-on)".into(),
                t,
                None,
            ));
        }
        let mut q = c.prepare(
            "SELECT t.id, t.name, u.name, u.tenant, t.expires FROM api_tokens t JOIN users u ON u.id = t.user_id
             WHERE t.expires > ?1 AND t.expires <= ?2",
        )?;
        let tokens = q
            .query_map(params![now, now + 7 * DAY], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (id, name, user, tenant, exp) in tokens {
            v.push(Item {
                key: format!("token:{id}"),
                what: format!("API token {name} of {user}"),
                not_after: exp,
                tenant,
                token: true,
            });
        }
        Ok(v)
    }

    /// Raises, escalates and resolves the `cert_expiry:*` alerts.
    pub fn check_expiry(&self, now: i64) -> Result<()> {
        let items = self.expiry_items(now)?;
        let open: HashMap<String, String> = {
            let c = self.db.conn();
            let mut q =
                c.prepare("SELECT key, severity FROM alerts WHERE resolved_at IS NULL AND key LIKE 'cert_expiry:%'")?;
            let r = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            r.collect::<Result<_, _>>()?
        };
        let mut due = HashSet::new();
        for it in &items {
            let sev = if it.token {
                Some("info")
            } else {
                severity(it.not_after, now)
            };
            let Some(sev) = sev else { continue };
            let key = format!("{PREFIX}{}", it.key);
            // once per level: a repeat would only count up every refresh
            if open.get(&key).is_none_or(|o| alerting::rank(sev) > alerting::rank(o)) {
                let msg = format!("{} {}", it.what, when(it.not_after, now));
                self.raise(sev, "cert_expiry", &key, &msg, it.tenant.as_deref())?;
            }
            due.insert(key);
        }
        for key in open.keys().filter(|k| !due.contains(*k)) {
            self.resolve(key)?;
        }
        Ok(())
    }
}
