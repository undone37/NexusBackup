//! Agent updates pushed from the appliance (Phase 27, catalog v41,
//! docs/agent-update-plan.md "Implementation"): rollouts and their items, shared by the
//! web-api (rollouts created by people) and the scheduler (automatic rollouts, the
//! rollout poller).

use crate::schedule::Window;
use anyhow::{bail, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Quorum action of a rollback rollout (an approved downgrade).
pub const ROLLBACK_ACTION: &str = "agent.rollback";
/// Alert kinds.
pub const ALERT_FAILED: &str = "agent_update_failed";
pub const ALERT_PAUSED: &str = "rollout_paused";

pub const ITEM_ACTIVE: &[&str] = &["queued", "running"];
pub const ITEM_DONE: &[&str] = &["ok", "failed", "skipped", "cancelled"];

/// Which agents a rollout covers (all fields optional and combined with AND; empty =
/// every enrolled agent).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<i64>,
    /// `linux` / `windows`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
}

fn d_canary() -> u32 {
    1
}
fn d_soak() -> u32 {
    60
}
fn d_conc() -> u32 {
    5
}
fn d_maxf() -> u32 {
    3
}
fn d_maxp() -> u32 {
    20
}

/// A rollout as requested (`POST /agent-rollouts`, automatic mode).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub version: String,
    #[serde(default)]
    pub scope: Scope,
    /// canary agents (wave 0); `canary_pct` instead: that share of the agents
    #[serde(default = "d_canary")]
    pub canary: u32,
    #[serde(default)]
    pub canary_pct: Option<u32>,
    #[serde(default = "d_soak")]
    pub soak_minutes: u32,
    #[serde(default = "d_conc")]
    pub concurrency: u32,
    /// pause after this many failures (0 = no count limit)
    #[serde(default = "d_maxf")]
    pub max_failures: u32,
    /// pause when this share of the finished agents failed (0 = no share limit)
    #[serde(default = "d_maxp")]
    pub max_failure_pct: u32,
    /// maintenance windows (UTC); empty = any time
    #[serde(default)]
    pub windows: Vec<Window>,
    #[serde(default)]
    pub rollback: bool,
}

impl Spec {
    pub fn check(&self) -> Result<()> {
        if agent_version(&self.version).is_none() {
            bail!("version: X.Y.Z expected");
        }
        if self.canary > 1000 || self.canary_pct.is_some_and(|p| p > 100) {
            bail!("canary: at most 1000 agents or 100 %");
        }
        if self.soak_minutes > 7 * 24 * 60 {
            bail!("soak_minutes: at most one week");
        }
        if !(1..=100).contains(&self.concurrency) {
            bail!("concurrency: 1..=100");
        }
        if self.max_failure_pct > 100 || self.max_failures > 10_000 {
            bail!("max_failure_pct: 0..=100, max_failures: 0..=10000");
        }
        if self.windows.len() > 16 {
            bail!("windows: at most 16");
        }
        for w in &self.windows {
            w.check()?;
        }
        let s = &self.scope;
        if s.os.as_deref().is_some_and(|o| o != "linux" && o != "windows") {
            bail!("scope.os: linux or windows");
        }
        if s.tag.as_deref().is_some_and(|t| !valid_tag(t)) {
            bail!("scope.tag: [a-z0-9_.-]{{1,32}}");
        }
        if s.agents.as_ref().is_some_and(|a| a.is_empty() || a.len() > 10_000) {
            bail!("scope.agents: 1..=10000 agent ids");
        }
        Ok(())
    }
}

pub fn agent_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().split('.').map(|p| p.parse::<u64>().ok());
    let r = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(r)
}

/// Agent tags (rollout scope): `[a-z0-9_.-]{1,32}`.
pub fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 32
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'))
}

/// An enrolled agent a rollout may cover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub tenant: String,
    pub version: Option<String>,
}

/// Enrolled agents matching `scope` (and `within`: the caller's tenant, if limited),
/// ordered by tenant and name.
pub fn scope_agents(c: &Connection, scope: &Scope, within: Option<&str>) -> Result<Vec<Candidate>> {
    let mut st = c.prepare(
        "SELECT id, tenant, version, os, tags FROM agents WHERE cert_sha256 IS NOT NULL ORDER BY tenant, name",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let group: Option<Vec<String>> = match scope.group_id {
        Some(g) => {
            let guests: Option<(String, String)> = c
                .query_row("SELECT tenant, guests FROM groups WHERE id = ?1", [g], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let Some((gt, guests)) = guests else {
                bail!("scope.group_id: no such group");
            };
            if scope.tenant.as_deref().is_some_and(|t| t != gt) || within.is_some_and(|t| t != gt) {
                bail!("scope.group_id: the group belongs to another tenant");
            }
            Some(
                serde_json::from_str::<Vec<Value>>(&guests)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
            )
        }
        None => None,
    };
    let mut out = Vec::new();
    for r in rows {
        let (id, tenant, version, os, tags) = r?;
        if within.is_some_and(|t| t != tenant) || scope.tenant.as_deref().is_some_and(|t| t != tenant) {
            continue;
        }
        if group.as_ref().is_some_and(|g| !g.contains(&id)) {
            continue;
        }
        if scope.agents.as_ref().is_some_and(|a| !a.contains(&id)) {
            continue;
        }
        if let Some(o) = &scope.os {
            let windows = os.as_deref().unwrap_or_default().to_ascii_lowercase().contains("windows");
            if (o == "windows") != windows {
                continue;
            }
        }
        if let Some(t) = &scope.tag {
            let tags: Vec<String> = serde_json::from_str(&tags).unwrap_or_default();
            if !tags.contains(t) {
                continue;
            }
        }
        out.push(Candidate { id, tenant, version });
    }
    Ok(out)
}

/// Why an agent is skipped by a rollout to `target` (`None` = it needs the update).
pub fn skip_reason(current: Option<&str>, target: &str, rollback: bool) -> Option<String> {
    let (Some(c), Some(t)) = (current.and_then(agent_version), agent_version(target)) else {
        return None; // unknown version: try (the agent refuses what does not fit)
    };
    if c == t {
        return Some(format!("already runs {target}"));
    }
    match (rollback, c > t) {
        (false, true) => Some(format!("runs {}, newer than {target}", current.unwrap_or_default())),
        (true, false) => Some(format!("runs {}, older than {target}", current.unwrap_or_default())),
        _ => None,
    }
}

/// Canary agents of `n` eligible ones.
pub fn canary_count(spec: &Spec, n: usize) -> usize {
    let c = match spec.canary_pct {
        Some(p) => (n * p as usize).div_ceil(100),
        None => spec.canary as usize,
    };
    c.min(n)
}

/// Creates a rollout with one item per agent of the scope (inside the caller's
/// transaction). Agents that already run the target (or, without rollback, a newer
/// version) are `skipped`; the first [`canary_count`] eligible agents form wave 0.
pub fn create(
    c: &Connection,
    spec: &Spec,
    by: &str,
    within: Option<&str>,
    automatic: bool,
    state: &str,
    now: i64,
) -> Result<i64> {
    spec.check()?;
    let agents = scope_agents(c, &spec.scope, within)?;
    if agents.is_empty() {
        bail!("the scope contains no enrolled agent");
    }
    if agents
        .iter()
        .all(|a| skip_reason(a.version.as_deref(), &spec.version, spec.rollback).is_some())
    {
        bail!(
            "no agent in the scope needs {} ({})",
            spec.version,
            if spec.rollback { "none runs a newer version" } else { "all run it or a newer one" }
        );
    }
    c.execute(
        "INSERT INTO agent_rollouts (version, scope, canary, canary_pct, soak_minutes, concurrency, max_failures, \
         max_failure_pct, windows, rollback, automatic, state, created, created_by) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            spec.version,
            serde_json::to_string(&spec.scope)?,
            spec.canary,
            spec.canary_pct,
            spec.soak_minutes,
            spec.concurrency,
            spec.max_failures,
            spec.max_failure_pct,
            serde_json::to_string(&spec.windows)?,
            spec.rollback,
            automatic,
            state,
            now,
            by
        ],
    )?;
    let id = c.last_insert_rowid();
    let eligible = agents
        .iter()
        .filter(|a| skip_reason(a.version.as_deref(), &spec.version, spec.rollback).is_none())
        .count();
    let mut canaries = canary_count(spec, eligible);
    for a in &agents {
        let skip = skip_reason(a.version.as_deref(), &spec.version, spec.rollback);
        let wave = if skip.is_none() && canaries > 0 {
            canaries -= 1;
            0
        } else {
            1
        };
        c.execute(
            "INSERT INTO agent_rollout_items (rollout_id, agent_id, tenant, wave, state, error, from_version, updated) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                id,
                a.id,
                a.tenant,
                wave,
                if skip.is_some() { "skipped" } else { "waiting" },
                skip,
                a.version,
                now
            ],
        )?;
    }
    // no canary: start with the rest
    let has_canary: bool = c.query_row(
        "SELECT COUNT(*) > 0 FROM agent_rollout_items WHERE rollout_id = ?1 AND wave = 0",
        [id],
        |r| r.get(0),
    )?;
    if !has_canary {
        c.execute("UPDATE agent_rollouts SET wave = 1 WHERE id = ?1", [id])?;
    }
    Ok(id)
}

/// Item counts per state.
pub fn counts(c: &Connection, id: i64) -> Result<Value> {
    let mut v = json!({"total": 0, "waiting": 0, "queued": 0, "running": 0, "ok": 0, "failed": 0, "skipped": 0, "cancelled": 0});
    let mut st = c.prepare("SELECT state, COUNT(*) FROM agent_rollout_items WHERE rollout_id = ?1 GROUP BY state")?;
    let mut total = 0;
    for r in st.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
        let (s, n) = r?;
        v[s.as_str()] = json!(n);
        total += n;
    }
    v["total"] = json!(total);
    Ok(v)
}

const COLS: &str = "id, version, scope, canary, canary_pct, soak_minutes, concurrency, max_failures, max_failure_pct, \
                    windows, rollback, automatic, state, reason, wave, quorum_id, created, created_by, finished, wave_done_at";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    let j = |i: usize| -> rusqlite::Result<Value> {
        Ok(serde_json::from_str(&r.get::<_, String>(i)?).unwrap_or(Value::Null))
    };
    Ok(json!({
        "id": r.get::<_, i64>(0)?, "version": r.get::<_, String>(1)?, "scope": j(2)?,
        "canary": r.get::<_, i64>(3)?, "canary_pct": r.get::<_, Option<i64>>(4)?,
        "soak_minutes": r.get::<_, i64>(5)?, "concurrency": r.get::<_, i64>(6)?,
        "max_failures": r.get::<_, i64>(7)?, "max_failure_pct": r.get::<_, i64>(8)?,
        "windows": j(9)?, "rollback": r.get::<_, bool>(10)?, "automatic": r.get::<_, bool>(11)?,
        "state": r.get::<_, String>(12)?, "reason": r.get::<_, Option<String>>(13)?,
        "wave": r.get::<_, i64>(14)?, "quorum_id": r.get::<_, Option<i64>>(15)?,
        "created": r.get::<_, i64>(16)?, "created_by": r.get::<_, String>(17)?,
        "finished": r.get::<_, Option<i64>>(18)?, "wave_done_at": r.get::<_, Option<i64>>(19)?,
    }))
}

/// One rollout with its counts (and items).
pub fn get(c: &Connection, id: i64, items: bool) -> Result<Option<Value>> {
    let Some(mut v) = c
        .query_row(&format!("SELECT {COLS} FROM agent_rollouts WHERE id = ?1"), [id], row)
        .optional()?
    else {
        return Ok(None);
    };
    v["counts"] = counts(c, id)?;
    if items {
        let mut st = c.prepare(
            "SELECT i.agent_id, a.name, i.tenant, i.wave, i.state, i.job_id, i.attempts, i.error, i.from_version, \
             a.version, i.updated FROM agent_rollout_items i LEFT JOIN agents a ON a.id = i.agent_id \
             WHERE i.rollout_id = ?1 ORDER BY i.wave, i.tenant, a.name",
        )?;
        let rows = st
            .query_map([id], |r| {
                Ok(json!({
                    "agent_id": r.get::<_, String>(0)?, "name": r.get::<_, Option<String>>(1)?,
                    "tenant": r.get::<_, String>(2)?, "wave": r.get::<_, i64>(3)?, "state": r.get::<_, String>(4)?,
                    "job_id": r.get::<_, Option<i64>>(5)?, "attempts": r.get::<_, i64>(6)?,
                    "error": r.get::<_, Option<String>>(7)?, "from_version": r.get::<_, Option<String>>(8)?,
                    "version": r.get::<_, Option<String>>(9)?, "updated": r.get::<_, i64>(10)?,
                }))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        v["items"] = Value::Array(rows);
    }
    Ok(Some(v))
}

/// All rollouts, newest first (at most 200).
pub fn list(c: &Connection) -> Result<Vec<Value>> {
    let ids: Vec<i64> = c
        .prepare("SELECT id FROM agent_rollouts ORDER BY id DESC LIMIT 200")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for id in ids {
        if let Some(v) = get(c, id, false)? {
            out.push(v);
        }
    }
    Ok(out)
}

/// `agent_update_settings` rows (automatic mode per tenant / group).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Setting {
    pub tenant: String,
    #[serde(default)]
    pub group_id: Option<i64>,
    pub mode: String,
    #[serde(default)]
    pub windows: Vec<Window>,
    #[serde(default = "d_canary")]
    pub canary: u32,
    #[serde(default = "d_soak")]
    pub soak_minutes: u32,
}

impl Setting {
    pub fn check(&self) -> Result<()> {
        if self.mode != "manual" && self.mode != "automatic" {
            bail!("mode: manual or automatic");
        }
        if self.canary > 1000 || self.soak_minutes > 7 * 24 * 60 || self.windows.len() > 16 {
            bail!("canary at most 1000, soak_minutes at most one week, at most 16 windows");
        }
        for w in &self.windows {
            w.check()?;
        }
        Ok(())
    }
}

pub fn settings(c: &Connection) -> Result<Vec<Value>> {
    let mut st = c.prepare(
        "SELECT tenant, group_id, mode, windows, canary, soak_minutes, updated, updated_by FROM agent_update_settings \
         ORDER BY tenant, group_id",
    )?;
    let rows = st
        .query_map([], |r| {
            let g: i64 = r.get(1)?;
            Ok(json!({
                "tenant": r.get::<_, String>(0)?, "group_id": (g != 0).then_some(g), "mode": r.get::<_, String>(2)?,
                "windows": serde_json::from_str::<Value>(&r.get::<_, String>(3)?).unwrap_or(json!([])),
                "canary": r.get::<_, i64>(4)?, "soak_minutes": r.get::<_, i64>(5)?,
                "updated": r.get::<_, i64>(6)?, "updated_by": r.get::<_, String>(7)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn put_setting(c: &Connection, s: &Setting, by: &str, now: i64) -> Result<()> {
    s.check()?;
    c.execute(
        "INSERT INTO agent_update_settings (tenant, group_id, mode, windows, canary, soak_minutes, updated, updated_by) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(tenant, group_id) DO UPDATE SET mode = excluded.mode, \
         windows = excluded.windows, canary = excluded.canary, soak_minutes = excluded.soak_minutes, \
         updated = excluded.updated, updated_by = excluded.updated_by",
        params![
            s.tenant,
            s.group_id.unwrap_or(0),
            s.mode,
            serde_json::to_string(&s.windows)?,
            s.canary,
            s.soak_minutes,
            now,
            by
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> crate::Catalog {
        let c = crate::Catalog::open_memory().unwrap();
        c.conn()
            .execute_batch(
                "INSERT INTO tenants (name) VALUES ('acme'), ('globex');
                 INSERT INTO agents (id, tenant, name, host, port, cert_sha256, version, os, tags) VALUES
                   ('a000000000000001','acme','web1','h',7444,'x','0.1.0','Debian GNU/Linux 13','[\"web\"]'),
                   ('a000000000000002','acme','web2','h',7444,'x','0.1.0','Debian GNU/Linux 13','[\"web\"]'),
                   ('a000000000000003','acme','db1','h',7444,'x','0.2.0','AlmaLinux 10','[]'),
                   ('a000000000000004','acme','win1','h',7444,'x','0.1.0','Windows Server 2022','[]'),
                   ('a000000000000005','acme','new','h',7444,NULL,NULL,NULL,'[]'),
                   ('b000000000000001','globex','g1','h',7444,'x','0.3.0','Debian GNU/Linux 13','[]');",
            )
            .unwrap();
        c
    }

    fn spec(v: &str) -> Spec {
        serde_json::from_value(json!({"version": v})).unwrap()
    }

    #[test]
    fn scope_selects_enrolled_agents() {
        let c = db();
        let c = c.conn();
        let ids = |s: Scope, w: Option<&str>| -> Vec<String> {
            scope_agents(&c, &s, w).unwrap().into_iter().map(|a| a.id).collect()
        };
        assert_eq!(ids(Scope::default(), None).len(), 5, "not the unenrolled one");
        assert_eq!(ids(Scope::default(), Some("globex")), ["b000000000000001"]);
        let os = Scope {
            os: Some("windows".into()),
            ..Default::default()
        };
        assert_eq!(ids(os, None), ["a000000000000004"]);
        let tag = Scope {
            tag: Some("web".into()),
            ..Default::default()
        };
        assert_eq!(ids(tag, None).len(), 2);
        let sel = Scope {
            agents: Some(vec!["a000000000000003".into(), "b000000000000001".into()]),
            tenant: Some("acme".into()),
            ..Default::default()
        };
        assert_eq!(ids(sel, None), ["a000000000000003"]);
    }

    #[test]
    fn waves_canary_and_skips() {
        let c = db();
        let c = c.conn();
        let mut s = spec("0.2.0");
        s.scope.tenant = Some("acme".into());
        s.canary = 2;
        let id = create(&c, &s, "alice", None, false, "running", 100).unwrap();
        let v = get(&c, id, true).unwrap().unwrap();
        let items: Vec<(String, i64, String)> = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    i["name"].as_str().unwrap().to_owned(),
                    i["wave"].as_i64().unwrap(),
                    i["state"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        // db1 already runs 0.2.0; two canaries among the three eligible
        assert_eq!(v["counts"]["total"], 4);
        assert_eq!(v["counts"]["skipped"], 1);
        assert_eq!(items.iter().filter(|i| i.1 == 0).count(), 2);
        assert!(items.contains(&("db1".into(), 1, "skipped".into())));
        assert_eq!(v["wave"], 0);
        // percentage canary, rounded up
        let mut p = spec("0.2.0");
        p.canary_pct = Some(10);
        assert_eq!(canary_count(&p, 25), 3);
        assert_eq!(canary_count(&p, 0), 0);
        // no canary: wave 1 right away
        let mut s = spec("0.2.0");
        s.canary = 0;
        s.scope.tenant = Some("acme".into());
        let id = create(&c, &s, "alice", None, false, "running", 100).unwrap();
        assert_eq!(get(&c, id, false).unwrap().unwrap()["wave"], 1);
        // rollback: only agents newer than the target
        let mut r = spec("0.2.0");
        r.rollback = true;
        let id = create(&c, &r, "alice", None, false, "pending_approval", 100).unwrap();
        let v = get(&c, id, true).unwrap().unwrap();
        assert_eq!(v["counts"]["waiting"], 1, "globex g1 (0.3.0) only");
        assert_eq!(v["state"], "pending_approval");
        // nothing in scope
        let mut e = spec("0.2.0");
        e.scope.tag = Some("none".into());
        assert!(create(&c, &e, "alice", None, false, "running", 1).is_err());
        assert_eq!(list(&c).unwrap().len(), 3);
    }

    #[test]
    fn spec_and_setting_checks() {
        assert!(spec("0.2").check().is_err());
        let mut s = spec("0.2.0");
        s.concurrency = 0;
        assert!(s.check().is_err());
        let mut s = spec("0.2.0");
        s.scope.os = Some("mac".into());
        assert!(s.check().is_err());
        assert!(serde_json::from_value::<Spec>(json!({"version": "1.0.0", "bogus": 1})).is_err());
        assert_eq!(skip_reason(Some("0.2.0"), "0.2.0", false).unwrap(), "already runs 0.2.0");
        assert!(skip_reason(Some("0.3.0"), "0.2.0", false).is_some());
        assert!(skip_reason(Some("0.1.0"), "0.2.0", true).is_some());
        assert!(skip_reason(None, "0.2.0", false).is_none());
        assert!(valid_tag("web-01.eu_x") && !valid_tag("Web") && !valid_tag(""));
        let c = db();
        let c = c.conn();
        let st: Setting = serde_json::from_value(json!({"tenant": "acme", "mode": "automatic",
            "windows": [{"days": ["Sat"], "from": "02:00", "to": "05:00"}]}))
        .unwrap();
        put_setting(&c, &st, "alice", 5).unwrap();
        put_setting(&c, &Setting { canary: 3, ..st.clone() }, "bob", 6).unwrap();
        let v = settings(&c).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!((v[0]["canary"].as_i64(), v[0]["updated_by"].as_str()), (Some(3), Some("bob")));
        assert_eq!(v[0]["group_id"], Value::Null);
        assert!(put_setting(&c, &Setting { mode: "often".into(), ..st }, "x", 1).is_err());
    }
}
