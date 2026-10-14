//! Phase 28 (docs/commvault-comparison.md Tier 1): scheduled threat scans,
//! the IOC hash hunt and the scheduler's half of the tenant lockdown.
//!
//! - **Scheduled scans** (docs/malware-scan.md "Scheduled scans"): a group with
//!   `scan_schedule` (policy schedule grammar, in the group's time zone) gets,
//!   when a slot is due, one `snapshot_scan {source, time, group_id,
//!   scheduled: true}` for the newest local snapshot of each of its sources
//!   that has no verdict yet (`snapshots.scan_state`). The scans queue behind
//!   the one-at-a-time plan key `snapshot_scan` like on-demand scans; a hit
//!   raises `scan_hit` (scan.rs). Nothing is queued without YARA rules, during
//!   restore priority or for a deactivated tenant.
//! - **Hash hunt** (docs/file-index.md "IOC hash hunt"): `hash_hunt {lists?,
//!   source?, from?, to?}` searches the SHA-256 recorded in the sealed name
//!   indexes of a tenant (v2, `groups.file_hashes`) for the uploaded IOC lists
//!   (`hash_lists`). Read-only, in-process like the file search; hits flag the
//!   snapshots and raise `hash_hunt_hit`.
//! - **Tenant lockdown** (docs/control-plane.md "Tenant lockdown"): the web-api
//!   holds, pauses and ends sessions; the scheduler refuses the jobs that would
//!   change the tenant's data while it is active (backups, deletes, restores
//!   that overwrite).

use super::*;
use chunkstore::names::Sha256;
use chunkstore::{Manifest, Store};
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

/// A hash hunt stops picking up snapshots after this (`truncated`).
pub const HUNT_BUDGET: Duration = Duration::from_secs(30 * 60);
/// Distinct (source, path, hash) hits kept in a result.
pub const MAX_HITS: usize = 2000;
/// Snapshots flagged per hunt at most (the newest first).
const MAX_FLAGS: usize = 500;

/// Kinds refused for a locked-down tenant (overwriting restores: see [`overwrites`]).
const LOCKDOWN_REFUSED: &[&str] = &["backup", "snapshot_delete", "agent_update", "agent_renew"];

/// A restore job that writes over existing data of the tenant.
fn overwrites(job: &Job) -> bool {
    let p = &job.params;
    match job.kind.as_str() {
        "restore" | "restore_ct" => p["replace"] == true,
        "restore_files" => p["overwrite"].as_str().is_some_and(|o| o != "never"),
        // Phase 33: a synthetic restore onto a host behaves like restore_files
        "synthetic_restore" => p["mode"] == "host" && p["overwrite"].as_str().is_some_and(|o| o != "never"),
        "plugin_restore" => true,
        _ => false,
    }
}

/// The uploaded IOC lists: hash → list names (all lists, or the named ones).
pub(crate) fn hash_set(
    c: &catalog::rusqlite::Connection,
    only: Option<&[String]>,
) -> Result<HashMap<Sha256, Vec<String>>> {
    let mut out: HashMap<Sha256, Vec<String>> = HashMap::new();
    let mut q = c.prepare("SELECT name, hashes FROM hash_lists ORDER BY name")?;
    let rows = q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (name, text) in rows {
        if only.is_some_and(|o| !o.contains(&name)) {
            continue;
        }
        for line in text.lines() {
            if let Some(h) = parse_sha256(line) {
                let names = out.entry(h).or_default();
                if !names.contains(&name) {
                    names.push(name.clone());
                }
            }
        }
    }
    Ok(out)
}

pub fn parse_sha256(s: &str) -> Option<Sha256> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(h)
}

fn hex(h: &[u8]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Which snapshots a hunt looks at.
pub struct HuntFilter {
    pub source: Option<String>,
    pub from: Option<u64>,
    pub to: Option<u64>,
}

impl HuntFilter {
    fn wants(&self, m: &Manifest) -> bool {
        self.source.as_ref().is_none_or(|s| *s == m.source)
            && self.from.is_none_or(|f| m.time >= f)
            && self.to.is_none_or(|t| m.time <= t)
    }
}

/// (path, size, hash) of the files of one snapshot on a list; `None` = no hashes recorded
type SnapHits = Option<Vec<(String, u64, Sha256)>>;

/// Runs a hunt; the JSON result of a `hash_hunt` job: `{matches: [{source,
/// path, size, sha256, lists, times}], scanned, unhashed, truncated, hashes,
/// elapsed_ms}` (newest snapshots first; one row per file version).
pub fn hunt(
    store: &Store,
    set: &HashMap<Sha256, Vec<String>>,
    f: &HuntFilter,
    budget: Duration,
) -> std::io::Result<Value> {
    let t0 = Instant::now();
    let mut snaps: Vec<Manifest> = store.list_snapshots()?.into_iter().filter(|m| f.wants(m)).collect();
    snaps.sort_by(|a, b| b.time.cmp(&a.time).then_with(|| a.source.cmp(&b.source)));
    let next = AtomicUsize::new(0);
    let failed = Mutex::new(None);
    let results: Mutex<Vec<(usize, SnapHits)>> = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
    std::thread::scope(|s| {
        for _ in 0..workers {
            let (snaps, next, failed, results) = (&snaps, &next, &failed, &results);
            s.spawn(move || loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= snaps.len() || t0.elapsed() > budget {
                    break;
                }
                match store.load_names(&snaps[i]) {
                    Ok(n) => {
                        let hits = n.filter(|n| n.has_hashes()).map(|n| {
                            n.hashed()
                                .filter(|(_, _, h)| set.contains_key(*h))
                                .map(|(p, s, h)| (p.to_owned(), s, *h))
                                .collect::<Vec<_>>()
                        });
                        results.lock().unwrap().push((i, hits));
                    }
                    Err(e) => {
                        failed.lock().unwrap().get_or_insert(e);
                        next.store(snaps.len(), Ordering::SeqCst);
                    }
                }
            });
        }
    });
    if let Some(e) = failed.into_inner().unwrap() {
        return Err(e);
    }
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);
    let scanned = results.len();
    let mut unhashed = 0usize;
    let mut truncated = scanned < snaps.len();
    let mut rows: Vec<(String, String, u64, Sha256, Vec<u64>)> = Vec::new();
    let mut by_key: HashMap<(String, String, Sha256), usize> = HashMap::new();
    for (i, hits) in results {
        let Some(hits) = hits else {
            unhashed += 1;
            continue;
        };
        let m = &snaps[i];
        for (path, size, h) in hits {
            let key = (m.source.clone(), path, h);
            match by_key.get(&key) {
                Some(&r) => rows[r].4.push(m.time),
                None if rows.len() < MAX_HITS => {
                    by_key.insert(key.clone(), rows.len());
                    rows.push((key.0, key.1, size, h, vec![m.time]));
                }
                None => truncated = true,
            }
        }
    }
    rows.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    let matches: Vec<Value> = rows
        .into_iter()
        .map(|(source, path, size, h, times)| {
            json!({"source": source, "path": path, "size": size, "sha256": hex(&h),
                   "lists": set.get(&h).cloned().unwrap_or_default(), "times": times})
        })
        .collect();
    Ok(json!({
        "matches": matches,
        "scanned": scanned,
        "unhashed": unhashed,
        "truncated": truncated,
        "hashes": set.len(),
        "elapsed_ms": t0.elapsed().as_millis() as u64,
    }))
}

impl Scheduler {
    /// Scheduled threat scans (module doc). `first_seen["scancheck/<group>"]`
    /// remembers a due slot that found nothing to scan.
    pub(crate) fn queue_threat_scans(&mut self, now: i64) -> Result<()> {
        if self.restore_priority()?.is_some() {
            return Ok(());
        }
        let groups: Vec<(i64, String, String, Option<i64>)> = {
            let c = self.db.conn();
            if !c.query_row("SELECT EXISTS (SELECT 1 FROM yara_rules)", [], |r| r.get::<_, bool>(0))? {
                return Ok(());
            }
            let mut q = c.prepare(
                "SELECT id, tenant, scan_schedule, scan_budget_min FROM groups WHERE scan_schedule IS NOT NULL ORDER BY id",
            )?;
            let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        if groups.is_empty() {
            return Ok(());
        }
        let off = self.disabled_tenants()?;
        let rows = self.groups()?;
        for (id, tenant, schedule, budget) in groups {
            if off.contains(&tenant) {
                continue;
            }
            let Some(g) = rows.iter().find(|g| g.id == id) else {
                continue;
            };
            let ctl = self.control(id)?;
            let sched = match Schedule::parse(&schedule).and_then(|s| s.in_tz(&ctl.tz)) {
                Ok(s) => s,
                Err(e) => {
                    self.alert(
                        "warning",
                        "config",
                        &format!("group {id}: threat scan schedule: {e}"),
                        None,
                    )?;
                    continue;
                }
            };
            let check = format!("scancheck/{id}");
            let last = self.last_run(
                &format!("scan/{id}"),
                "SELECT MAX(created) FROM jobs WHERE kind='snapshot_scan' AND requested_by='scheduler' \
                 AND json_extract(params,'$.group_id')=?1",
                &[&id],
                now,
            )?;
            let last = last.max(self.first_seen.get(&check).copied().unwrap_or(0));
            if !sched.due(last, now) {
                continue;
            }
            self.first_seen.insert(check, now);
            let (sources, prefixes) = (group_sources(g), group_prefixes(g));
            // newest local snapshot of each source, its verdict and whether a scan is pending
            let newest: Vec<(String, i64, Option<String>, bool)> = {
                let c = self.db.conn();
                let mut q = c.prepare(
                    "SELECT s.source, s.time, s.scan_state,
                       EXISTS (SELECT 1 FROM jobs j WHERE j.kind = 'snapshot_scan' AND j.tenant = s.tenant
                         AND j.state IN ('queued','running') AND json_extract(j.params,'$.source') = s.source
                         AND json_extract(j.params,'$.time') = s.time)
                     FROM snapshots s WHERE s.tenant = ?1 AND s.local = 1
                       AND s.time = (SELECT MAX(time) FROM snapshots x WHERE x.tenant = s.tenant
                                     AND x.source = s.source AND x.local = 1)
                     ORDER BY s.source",
                )?;
                let rows = q.query_map([&tenant], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            for (source, time, state, pending) in newest {
                let ours = sources.contains(&source) || prefixes.iter().any(|p| source.starts_with(p.as_str()));
                if !ours || state.is_some() || pending {
                    continue;
                }
                let mut p = json!({"source": source, "time": time, "group_id": id, "scheduled": true});
                if let Some(b) = budget {
                    p["budget"] = json!(b * 60);
                }
                self.insert_job("snapshot_scan", &tenant, &p)?;
            }
        }
        Ok(())
    }

    /// `hash_hunt`: in-process over the tenant's store (read-only, own plan key).
    pub(crate) fn plan_hunt(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let p = &job.params;
        let only: Option<Vec<String>> = p["lists"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect());
        let set = hash_set(&self.db.conn(), only.as_deref())?;
        if set.is_empty() {
            bail!("no IOC hashes uploaded (Settings → IOC hash lists)");
        }
        let f = HuntFilter {
            source: match p["source"].as_str() {
                Some(_) => Some(ident(p, "source")?.to_owned()),
                None => None,
            },
            from: p["from"].as_u64(),
            to: p["to"].as_u64(),
        };
        plan.key = format!("hunt:{}", job.id);
        plan.steps.push(Step::Store(run::StoreOp(Box::new(move |s| {
            hunt(s, &set, &f, HUNT_BUDGET)
                .map(|v| v.to_string())
                .map_err(|e| format!("hash hunt: {e}"))
        }))));
        Ok(plan)
    }

    /// A finished `hash_hunt` with matches: flag the snapshots, raise `hash_hunt_hit`.
    pub(crate) fn hunt_bookkeeping(&mut self, job: &Job, r: Option<&Value>) -> Result<()> {
        let Some(matches) = r.and_then(|r| r["matches"].as_array()).filter(|m| !m.is_empty()) else {
            return Ok(());
        };
        let mut per_snap: BTreeMap<(String, i64), Vec<&str>> = BTreeMap::new();
        for m in matches {
            let (Some(source), Some(path)) = (m["source"].as_str(), m["path"].as_str()) else {
                continue;
            };
            for t in m["times"].as_array().into_iter().flatten().filter_map(Value::as_i64) {
                per_snap.entry((source.to_owned(), t)).or_default().push(path);
            }
        }
        let mut snaps: Vec<_> = per_snap.into_iter().collect();
        snaps.sort_by_key(|a| std::cmp::Reverse(a.0 .1));
        for ((source, time), paths) in snaps.iter().take(MAX_FLAGS) {
            let why = format!(
                "IOC hash: {} file(s) on a hash list (hunt job {}), e.g. {}",
                paths.len(),
                job.id,
                paths[0]
            );
            self.flag_snapshot(&job.tenant, source, *time, &why)?;
        }
        let first = &matches[0];
        self.raise(
            "critical",
            "hash_hunt_hit",
            &format!("hash_hunt_hit:{}", job.tenant),
            &format!(
                "IOC hash hunt (job {}) in tenant {}: {} file versions on a hash list in {} snapshots, e.g. {} in {} ({})",
                job.id,
                job.tenant,
                matches.len(),
                snaps.len(),
                first["path"].as_str().unwrap_or("?"),
                first["source"].as_str().unwrap_or("?"),
                first["lists"][0].as_str().unwrap_or("?")
            ),
            Some(&job.tenant),
        )?;
        self.db.audit(
            ACTOR,
            "hash_hunt.hits",
            &format!("job/{}", job.id),
            &json!({"tenant": job.tenant, "matches": matches.len(), "snapshots": snaps.len()}),
        )?;
        Ok(())
    }

    /// Jobs that would change a locked-down tenant's data are refused.
    pub(crate) fn refuse_locked(&self, job: &Job) -> Result<()> {
        if !(LOCKDOWN_REFUSED.contains(&job.kind.as_str()) || overwrites(job)) {
            return Ok(());
        }
        if catalog::tenants::locked_down(&self.db.conn(), &job.tenant)? {
            bail!(
                "tenant {} is locked down: no {} jobs until the lockdown is lifted (approval)",
                job.tenant,
                job.kind
            );
        }
        Ok(())
    }
}
