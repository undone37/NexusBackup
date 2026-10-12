//! Disk alerts (Phase 16a), kind `disk`, from the status the root helper nexus-disks
//! writes every 5 minutes (`<disks_dir>/status.json`, rules in `catalog::hardware`):
//! - `disk:<serial>`: SMART failing (critical), bad sectors, NVMe wear or critical warning,
//!   media errors, temperature, a failed self-test (warning); bad sectors that grew since
//!   the last scan escalate to critical;
//! - `disk:md:<uuid>`: an array failed or degraded (critical);
//! - `disk:md:<uuid>:sync`: rebuild / resync / reshape running (info, progress in the message);
//! - `disk:monitor`: the status is older than 30 minutes (warning).
//!
//! Checked every tick (a small file). A raised alert keeps its severity until resolved;
//! newer messages (progress) replace the text without counting a repeat. Resolved when the
//! status no longer asks for it. Operations nexus-disks finished (`ops.json`: array created,
//! spare added, disk replaced, grow, self-test) are audited once as `hardware.op`.

use super::*;
use catalog::alerting;
use catalog::hardware;

/// last seen bad-sector count per disk (growth escalates)
const SECTORS_SETTING: &str = "disk_sector_counts";
/// ids of helper operations already audited (the newest 100)
const AUDITED_SETTING: &str = "disk_ops_audited";
const ACTOR_DISKS: &str = "nexus-disks";

fn read(p: &Path) -> Option<Value> {
    let b = fs::read(p).ok()?;
    (b.len() <= 4 << 20).then(|| serde_json::from_slice(&b).ok())?
}

impl Scheduler {
    /// Raises, escalates, updates and resolves the `disk:*` alerts; audits finished operations.
    pub fn check_disks(&self, now: i64) -> Result<()> {
        let dir = &self.cfg.disks_dir;
        if let Some(ops) = read(&dir.join("ops.json")) {
            self.audit_disk_ops(&ops)?;
        }
        // no status at all: no monitoring here (a VM without the helper, tests); nothing to say
        let Some(status) = read(&dir.join("status.json")) else {
            return Ok(());
        };
        let mut want = hardware::alerts(&status);
        let scanned = status["scanned"].as_i64().unwrap_or(0);
        if now - scanned > hardware::STALE_SECS {
            want.insert(
                "disk:monitor".into(),
                (
                    "warning",
                    format!(
                        "No disk status for {} minutes: nexus-disks.timer is not running (systemctl status nexus-disks.timer)",
                        (now - scanned) / 60
                    ),
                ),
            );
        }
        self.sector_growth(&status, &mut want)?;
        let open: HashMap<String, (String, String)> = {
            let c = self.db.conn();
            let mut q = c.prepare(
                "SELECT key, severity, message FROM alerts WHERE resolved_at IS NULL AND kind = 'disk' AND key LIKE 'disk:%'",
            )?;
            let r = q.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?;
            r.collect::<Result<_, _>>()?
        };
        for (key, (sev, msg)) in &want {
            match open.get(key) {
                Some((old, _)) if alerting::rank(sev) > alerting::rank(old) => {
                    self.raise(sev, "disk", key, msg, None)?
                }
                Some((_, m)) if m != msg => {
                    self.db.conn().execute(
                        "UPDATE alerts SET message = ?2, last_ts = ?3 WHERE key = ?1 AND resolved_at IS NULL",
                        params![key, msg, now],
                    )?;
                }
                Some(_) => {}
                None => self.raise(sev, "disk", key, msg, None)?,
            }
        }
        for key in open.keys().filter(|k| !want.contains_key(*k)) {
            self.resolve(key)?;
        }
        Ok(())
    }

    /// Bad sectors that grew since the last scan: that disk's alert becomes critical.
    fn sector_growth(&self, status: &Value, want: &mut BTreeMap<String, (&'static str, String)>) -> Result<()> {
        let c = self.db.conn();
        let last: HashMap<String, i64> = catalog::setting(&c, SECTORS_SETTING)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let mut now_counts = HashMap::new();
        for d in status["disks"].as_array().into_iter().flatten() {
            if d["smart"]["available"] != Value::Bool(true) {
                continue;
            }
            let key = hardware::disk_key(d);
            let n = hardware::sector_count(d);
            if let (Some(prev), Some(a)) = (last.get(&key), want.get_mut(&key)) {
                if n > *prev {
                    *a = ("critical", format!("{} (growing: was {prev})", a.1));
                }
            }
            now_counts.insert(key, n);
        }
        if now_counts != last {
            catalog::set_setting(&c, SECTORS_SETTING, &serde_json::to_string(&now_counts)?)?;
        }
        Ok(())
    }

    fn audit_disk_ops(&self, ops: &Value) -> Result<()> {
        let mut seen: Vec<String> = catalog::setting(&self.db.conn(), AUDITED_SETTING)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let before = seen.len();
        for o in ops.as_array().into_iter().flatten() {
            let (Some(id), Some(state)) = (o["id"].as_str(), o["state"].as_str()) else {
                continue;
            };
            if !matches!(state, "done" | "refused" | "error") || seen.iter().any(|s| s == id) {
                continue;
            }
            let op = o["op"].as_str().unwrap_or("?");
            self.db.audit(
                ACTOR_DISKS,
                "hardware.op",
                &format!("hardware/{op}"),
                &json!({"id": id, "op": op, "state": state, "requested_by": o["by"], "quorum_id": o["quorum_id"],
                        "params": o["params"], "detail": o["detail"], "error": o["error"]}),
            )?;
            seen.push(id.to_owned());
        }
        if seen.len() != before {
            let keep = seen.len().saturating_sub(100);
            catalog::set_setting(&self.db.conn(), AUDITED_SETTING, &serde_json::to_string(&seen[keep..])?)?;
        }
        Ok(())
    }
}
