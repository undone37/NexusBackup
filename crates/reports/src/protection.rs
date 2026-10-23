//! Protected objects (the dashboard's protection tile, the `protection` and `sla`
//! reports): every guest / host / share / dataset / plugin guest a group backs up,
//! with its RPO (the shortest schedule period of its groups) and SLA state.

use crate::rusqlite::{self, params, Connection, OptionalExtension};
use crate::{iso, Cell, Kind, Table, DAY};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// An object breaches its SLA when its last good backup is older than RPO × 1.5.
pub const SLA_FACTOR: f64 = 1.5;

/// RPO of a policy schedule: the (longest) schedule period.
pub fn rpo(schedule: &str) -> i64 {
    catalog::schedule::Schedule::parse(schedule).map_or(DAY, catalog::schedule::Schedule::period)
}

/// A protected object: one guest / host / dataset / share / plugin guest, merged over all groups that back it up.
pub struct Object {
    /// Tenant that owns the object.
    pub tenant: String,
    /// snapshot sources that count for this object (PVE: `vm-` and `ct-`)
    pub sources: Vec<String>,
    /// Display name (`<source> guest <vmid>`, `<source> (<agent>)`, `<source> <dataset>`, ...).
    pub name: String,
    /// Source kind (`pve`, `linux`, `truenas`, `nfs`, `smb`, `plugin:<kind>`).
    pub kind: String,
    /// Recovery point objective in seconds: the shortest schedule period of its groups.
    pub rpo: i64,
    /// every group of the object is paused (or its source in maintenance, Phase 13b)
    pub paused: bool,
    /// its tenant is deactivated (Phase 17f): never a breach, shown as `deactivated`
    pub deactivated: bool,
    /// names of the groups that back it up
    pub groups: Vec<String>,
    /// policy tiers of those groups (bronze / silver / gold, Phase 19b)
    pub tiers: Vec<String>,
}

/// Object key (tenant, first source) → object; one object in several groups
/// counts once (shortest RPO).
pub fn objects(c: &Connection, scope: Option<&str>, now: i64) -> rusqlite::Result<BTreeMap<(String, String), Object>> {
    /// (tenant, source id, guests, schedule, kind, source name, config, auto, paused, (group, tier))
    type Row = (
        String,
        i64,
        Vec<Value>,
        String,
        String,
        String,
        String,
        bool,
        bool,
        (String, Option<String>),
    );
    let rows: Vec<Row> = c
        .prepare(
            "SELECT g.tenant, g.source_id, g.guests, p.schedule, s.kind, s.name, s.config, g.mode, g.selector, g.exclude,
                    g.paused_until = -1 OR g.paused_until > ?2 OR s.maintenance_until = -1 OR s.maintenance_until > ?2,
                    g.name, p.tier
             FROM groups g JOIN policies p ON p.id = g.policy_id JOIN sources s ON s.id = g.source_id
             WHERE ?1 IS NULL OR g.tenant = ?1 ORDER BY g.id",
        )?
        .query_map(params![scope, now], |r| {
            let (sid, kind, mode): (i64, String, String) = (r.get(1)?, r.get(4)?, r.get(7)?);
            // the scheduler's resolution (explicit list or inventory, catalog::inventory)
            let guests = catalog::inventory::resolve(
                c,
                sid,
                &kind,
                &mode,
                &r.get::<_, String>(2)?,
                &r.get::<_, String>(8)?,
                &r.get::<_, String>(9)?,
            )?;
            let auto = catalog::inventory::auto(&mode);
            let paused = r.get::<_, Option<bool>>(10)?.unwrap_or(false);
            let group = (r.get(11)?, r.get(12)?);
            Ok((r.get(0)?, sid, guests, r.get(3)?, kind, r.get(5)?, r.get(6)?, auto, paused, group))
        })?
        .collect::<Result<_, _>>()?;
    let mut objs: BTreeMap<(String, String), Object> = BTreeMap::new();
    for (tenant, sid, guests, schedule, kind, sname, cfg, auto, paused, (group, tier)) in rows {
        let strs = || guests.iter().filter_map(Value::as_str).map(str::to_owned);
        let mut add: Vec<(Vec<String>, String)> = Vec::new();
        match kind.as_str() {
            "pve" => {
                for v in guests.iter().filter_map(Value::as_u64) {
                    add.push((vec![format!("vm-{v}"), format!("ct-{v}")], format!("{sname} guest {v}")));
                }
            }
            "linux" => {
                for a in strs() {
                    add.push((vec![format!("host-{a}")], format!("{sname} ({a})")));
                }
            }
            "truenas" => {
                let mut ds: Vec<String> = strs().collect();
                if ds.is_empty() && !auto {
                    let cfg: Value = serde_json::from_str(&cfg).unwrap_or(Value::Null);
                    ds = cfg["datasets"]
                        .as_array()
                        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                        .unwrap_or_default();
                }
                for d in ds {
                    add.push((vec![truenas::source_name(sid as u64, &d)], format!("{sname} {d}")));
                }
            }
            "nfs" | "smb" => add.push((vec![nas::source_name(sid as u64)], sname.clone())),
            "vmware" => {
                for u in strs() {
                    // the VM by its vSphere name from the inventory, the UUID when not listed yet
                    let name: Option<String> = c
                        .query_row(
                            "SELECT name FROM inventory WHERE source_id = ?1 AND guest = ?2 AND name != ''",
                            params![sid, u],
                            |r| r.get(0),
                        )
                        .optional()?;
                    add.push((
                        vec![vmware::names::source_name(&u)],
                        format!("{sname} {}", name.unwrap_or_else(|| u.clone())),
                    ));
                }
            }
            k => {
                let Some(pk) = k.strip_prefix("plugin:") else { continue };
                let Some(cur) = plugin_manager::current_for_kind(c, pk).ok().flatten() else {
                    continue;
                };
                let g: Vec<String> = strs().collect();
                if g.is_empty() && !auto {
                    add.push((
                        vec![plugin_proto::source_name(&cur.id, sid as u64, None)],
                        sname.clone(),
                    ));
                }
                for x in g {
                    add.push((
                        vec![plugin_proto::source_name(&cur.id, sid as u64, Some(&x))],
                        format!("{sname} {x}"),
                    ));
                }
            }
        }
        let r = rpo(&schedule);
        for (sources, name) in add {
            let o = objs
                .entry((tenant.clone(), sources[0].clone()))
                .or_insert_with(|| Object {
                    tenant: tenant.clone(),
                    sources,
                    name,
                    kind: kind.clone(),
                    rpo: r,
                    paused,
                    deactivated: false,
                    groups: Vec::new(),
                    tiers: Vec::new(),
                });
            o.rpo = o.rpo.min(r);
            o.paused &= paused;
            if !o.groups.contains(&group) {
                o.groups.push(group.clone());
            }
            if let Some(t) = tier.as_ref().filter(|t| !o.tiers.contains(t)) {
                o.tiers.push(t.clone());
            }
        }
    }
    let off = catalog::tenants::all_disabled(c)?;
    for o in objs.values_mut().filter(|o| off.contains(&o.tenant)) {
        o.paused = true;
        o.deactivated = true;
    }
    Ok(objs)
}

/// An object with its SLA state now.
pub struct Status {
    /// The object assessed.
    pub obj: Object,
    /// the source that has snapshots (else the first one)
    pub source: String,
    /// Unix time of the newest snapshot of any of its sources (`None` = never backed up).
    pub last_ok: Option<i64>,
    /// Seconds since `last_ok` (never negative).
    pub age: Option<i64>,
    /// `ok`, `breach`, `never` (no backup yet), `paused` (overdue, but paused on purpose)
    /// or `deactivated` (the tenant is deactivated)
    pub sla: &'static str,
}

/// Every protected object with its last good backup and SLA state.
pub fn assess(c: &Connection, scope: Option<&str>, now: i64) -> rusqlite::Result<Vec<Status>> {
    let objs = objects(c, scope, now)?;
    let last: HashMap<(String, String), i64> = c
        .prepare(
            "SELECT tenant, source, MAX(time) FROM snapshots WHERE ?1 IS NULL OR tenant = ?1 GROUP BY tenant, source",
        )?
        .query_map([scope], |r| Ok(((r.get(0)?, r.get(1)?), r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for o in objs.into_values() {
        let key = |s: &String| (o.tenant.clone(), s.clone());
        let last_ok = o.sources.iter().filter_map(|s| last.get(&key(s))).max().copied();
        let source = o
            .sources
            .iter()
            .find(|s| last.contains_key(&key(s)))
            .unwrap_or(&o.sources[0])
            .clone();
        let age = last_ok.map(|t| (now - t).max(0));
        let over = |a: i64| a as f64 > o.rpo as f64 * SLA_FACTOR;
        let sla = match age {
            _ if o.deactivated => "deactivated",
            None => "never",
            Some(a) if over(a) && o.paused => "paused",
            Some(a) if over(a) => "breach",
            Some(_) => "ok",
        };
        out.push(Status {
            obj: o,
            source,
            last_ok,
            age,
            sla,
        });
    }
    Ok(out)
}

/// (tenant, source, time) → `consistent` flag of the backup job that wrote it
/// (agent, share and plugin backups before 15d; the fallback when
/// `snapshots.consistency` is not set).
fn consistency(
    c: &Connection,
    scope: Option<&str>,
    since: i64,
) -> rusqlite::Result<HashMap<(String, String, i64), bool>> {
    c.prepare(
        "SELECT j.tenant, json_extract(e.value, '$.source'), json_extract(e.value, '$.time'),
                json_extract(e.value, '$.consistent')
         FROM jobs j, json_each(j.result, '$.snapshots') e
         WHERE j.kind IN ('backup', 'plugin_backup') AND j.state = 'ok' AND j.finished >= ?1
           AND (?2 IS NULL OR j.tenant = ?2) AND json_valid(j.result)
           AND json_extract(e.value, '$.consistent') IS NOT NULL",
    )?
    .query_map(params![since, scope], |r| {
        Ok(((r.get(0)?, r.get(1)?, r.get(2)?), r.get::<_, bool>(3)?))
    })?
    .collect()
}

/// Columns of the `protection` report.
pub const PROTECTION_COLUMNS: &[&str] = &[
    "tenant",
    "groups",
    "object",
    "kind",
    "source",
    "rpo_hours",
    "last_good",
    "age_hours",
    "status",
    "local",
    "offsite",
    "verified",
    "consistency",
];

/// The `protection` report: one row per protected object, state as of `now`.
pub fn table(c: &Connection, scope: Option<&str>, now: i64) -> rusqlite::Result<Table> {
    let st = assess(c, scope, now)?;
    let since = st.iter().filter_map(|s| s.last_ok).min().unwrap_or(now) - DAY;
    let cons = consistency(c, scope, since)?;
    let mut rows = Vec::new();
    for s in st {
        let snap: Option<(bool, bool, Option<i64>, Option<String>)> = match s.last_ok {
            Some(t) => {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT local, offsite, verified, consistency FROM snapshots
                     WHERE tenant = ?1 AND source = ?2 AND time = ?3",
                    params![s.obj.tenant, s.source, t],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?
            }
            None => None,
        };
        let yes = |b: bool| Cell::text(if b { "yes" } else { "no" });
        // levels of Phase 15d (application / crash / inconsistent / unknown); before
        // it only the `consistent` flag: a consistent view was at least a snapshot
        let legacy = s
            .last_ok
            .and_then(|t| cons.get(&(s.obj.tenant.clone(), s.source.clone(), t)));
        let consistent = match (snap.as_ref().and_then(|x| x.3.as_deref()), legacy) {
            (Some(l), _) => l.to_owned(),
            (None, Some(true)) => "crash".into(),
            (None, Some(false)) => "inconsistent".into(),
            (None, None) => "unknown".into(),
        };
        rows.push(vec![
            Cell::text(&s.obj.tenant),
            Cell::text(s.obj.groups.join(" ")),
            Cell::text(&s.obj.name),
            Cell::text(&s.obj.kind),
            Cell::text(&s.source),
            Cell::hours(s.obj.rpo),
            Cell::opt_time(s.last_ok),
            s.age.map_or(Cell::Empty, Cell::hours),
            Cell::text(s.sla),
            snap.as_ref().map_or(Cell::Empty, |x| yes(x.0)),
            snap.as_ref().map_or(Cell::Empty, |x| yes(x.1)),
            Cell::opt_time(snap.as_ref().and_then(|x| x.2)),
            Cell::text(consistent),
        ]);
    }
    Ok(Table {
        kind: Kind::Protection,
        columns: PROTECTION_COLUMNS,
        rows,
    })
}

/// Columns of the `sla` report.
pub const SLA_COLUMNS: &[&str] = &[
    "type",
    "tenant",
    "groups",
    "tier",
    "object",
    "start",
    "end",
    "hours",
    "target_hours",
    "detail",
];

/// The breach intervals of one object: after each good backup, from
/// `backup + limit` until the next one (or `now`, unless paused), clipped to
/// `[from, to)`. Returns (start, end, ongoing).
pub fn breaches(times: &[i64], limit: i64, paused: bool, from: i64, to: i64, now: i64) -> Vec<(i64, i64, bool)> {
    let mut out = Vec::new();
    let mut push = |s: i64, e: i64, ongoing: bool| {
        let (s, e) = (s.max(from), e.min(to));
        if s < e {
            out.push((s, e, ongoing));
        }
    };
    for w in times.windows(2) {
        if w[1] - w[0] > limit {
            push(w[0] + limit, w[1], false);
        }
    }
    if let (Some(last), false) = (times.last(), paused) {
        if now - last > limit {
            push(last + limit, now, true);
        }
    }
    out
}

/// RPO breaches (from the snapshot catalog plus the snapshots recorded by
/// successful backup jobs, so retention does not open false gaps) and
/// `sla_missed` alerts raised in `[from, to)`.
#[allow(clippy::type_complexity)]
pub fn sla(c: &Connection, scope: Option<&str>, from: i64, to: i64, now: i64) -> rusqlite::Result<Table> {
    let mut times: HashMap<(String, String), Vec<i64>> = HashMap::new();
    let mut add = |rows: Vec<(String, String, i64)>| {
        for (t, s, ts) in rows {
            times.entry((t, s)).or_default().push(ts);
        }
    };
    add(c
        .prepare("SELECT tenant, source, time FROM snapshots WHERE (?1 IS NULL OR tenant = ?1) AND time < ?2")?
        .query_map(params![scope, to], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?);
    add(c
        .prepare(
            "SELECT j.tenant, json_extract(e.value, '$.source'), json_extract(e.value, '$.time')
             FROM jobs j, json_each(j.result, '$.snapshots') e
             WHERE j.kind IN ('backup', 'plugin_backup') AND j.state = 'ok' AND (?1 IS NULL OR j.tenant = ?1)
               AND json_valid(j.result) AND json_type(e.value, '$.time') = 'integer'
               AND json_extract(e.value, '$.time') < ?2",
        )?
        .query_map(params![scope, to], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?);
    let mut rows: Vec<(i64, Vec<Cell>)> = Vec::new();
    for o in objects(c, scope, now)?.into_values() {
        let mut ts: Vec<i64> = o
            .sources
            .iter()
            .filter_map(|s| times.get(&(o.tenant.clone(), s.clone())))
            .flatten()
            .copied()
            .collect();
        ts.sort_unstable();
        ts.dedup();
        let limit = (o.rpo as f64 * SLA_FACTOR) as i64;
        for (s, e, ongoing) in breaches(&ts, limit, o.paused, from, to, now) {
            let last = ts.iter().rev().find(|t| **t <= s).copied();
            let detail = match (ongoing, last) {
                (true, Some(l)) => format!("ongoing: no good backup since {}", iso(l)),
                (_, Some(l)) => format!("no good backup between {} and {}", iso(l), iso(e)),
                (_, None) => String::new(),
            };
            rows.push((
                s,
                vec![
                    Cell::text("rpo_breach"),
                    Cell::text(&o.tenant),
                    Cell::text(o.groups.join(" ")),
                    Cell::text(o.tiers.join(" ")),
                    Cell::text(&o.name),
                    Cell::Time(s),
                    if ongoing { Cell::Empty } else { Cell::Time(e) },
                    Cell::hours(e - s),
                    Cell::hours(limit),
                    Cell::text(detail),
                ],
            ));
        }
    }
    let alerts: Vec<(
        i64,
        Option<String>,
        String,
        Option<String>,
        Option<i64>,
        Option<i64>,
        (Option<i64>, Option<String>),
    )> = c
        .prepare(
            "SELECT a.ts, a.tenant, a.message, g.name, j.started, j.finished, p.sla_minutes, p.tier FROM alerts a
             LEFT JOIN jobs j ON a.key = 'sla_missed:' || j.id
             LEFT JOIN groups g ON g.id = json_extract(j.params, '$.group_id')
             LEFT JOIN policies p ON p.id = g.policy_id
             WHERE a.kind = 'sla_missed' AND a.ts >= ?1 AND a.ts < ?2 AND (?3 IS NULL OR a.tenant = ?3)",
        )?
        .query_map(params![from, to, scope], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                (r.get(6)?, r.get(7)?),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (ts, tenant, msg, group, started, finished, (sla_min, tier)) in alerts {
        let start = started.unwrap_or(ts);
        rows.push((
            start,
            vec![
                Cell::text("sla_missed"),
                Cell::text(tenant.unwrap_or_default()),
                Cell::text(group.unwrap_or_default()),
                Cell::text(tier.unwrap_or_default()),
                Cell::Empty,
                Cell::Time(start),
                Cell::opt_time(finished),
                finished.map_or(Cell::Empty, |f| Cell::hours(f - start)),
                sla_min.map_or(Cell::Empty, |m| Cell::hours(m * 60)),
                Cell::text(msg),
            ],
        ));
    }
    rows.sort_by_key(|(s, _)| *s);
    Ok(Table {
        kind: Kind::Sla,
        columns: SLA_COLUMNS,
        rows: rows.into_iter().map(|(_, r)| r).collect(),
    })
}
