//! Plugin snapshot metadata (protocol v1.8 `SnapshotMeta`, Phase 18b): the plugin
//! host prints it per snapshot in its `result {json}` line; the backup result
//! carries it as `snapshots[].meta` and it is kept in `snapshots.meta` (catalog v23),
//! e.g. PostgreSQL's recoverable range for the point-in-time restore dialog. A source system's own
//! change-rate finding in it (`anomaly`, e.g. NexusStor's, #137) flags the snapshot and raises `anomaly`
//! ([`Scheduler::external_anomaly`]).

use crate::{Job, Scheduler};
use anyhow::Result;
use catalog::rusqlite::params;
use serde_json::Value;

/// Copies `meta` from the plugin host's `result` line onto the matching snapshots.
pub(crate) fn attach(log: &str, snaps: &mut [Value]) {
    let Some(res) = log
        .lines()
        .find_map(|l| serde_json::from_str::<Value>(l.strip_prefix("result ")?).ok())
    else {
        return;
    };
    for m in res["snapshots"].as_array().into_iter().flatten() {
        if !m["meta"].is_object() {
            continue;
        }
        if let Some(s) = snaps
            .iter_mut()
            .find(|s| s["source"] == m["source"] && s["time"] == m["time"])
        {
            s["meta"] = m["meta"].clone();
        }
    }
}

impl Scheduler {
    /// `snapshots.meta` of a finished backup's snapshots, merged with what the row has (the
    /// row may not exist yet: the refresh fills in the rest).
    pub(crate) fn meta_bookkeeping(&self, job: &Job, result: Option<&Value>) -> Result<()> {
        for s in result.and_then(|r| r["snapshots"].as_array()).into_iter().flatten() {
            let (Some(src), Some(t), Some(m)) = (s["source"].as_str(), s["time"].as_i64(), s.get("meta")) else {
                continue;
            };
            if !m.is_object() {
                continue;
            }
            self.db.conn().execute(
                // the snapshot was just committed to the local store: local = 1 now, not after the
                // next store scan (a restore test right after the backup found "no such local snapshot")
                "INSERT INTO snapshots (tenant, source, time, local, offsite, meta) VALUES (?1,?2,?3,1,0,?4)
                 ON CONFLICT (tenant, source, time) DO UPDATE SET meta = json_patch(COALESCE(meta,'{}'), ?4)",
                params![job.tenant, src, t, m.to_string()],
            )?;
            if let Some(a) = m.get("anomaly").filter(|a| a.is_object()) {
                self.external_anomaly(&job.tenant, src, t, a)?;
            }
        }
        Ok(())
    }

    /// The source system reported a change-rate anomaly of its own (NexusStor's ransomware signal in the
    /// plugin's snapshot meta: `{system, nexusstor?, snapshot, at, last_good, last_good_created}`, values from
    /// the source system, so untrusted): the snapshot that carries the data after it is flagged, and the
    /// `anomaly` alert names the newest clean snapshot from no later than the system's last good state (a
    /// snapshot between that and the system's finding may already hold the changed data).
    pub(crate) fn external_anomaly(&self, tenant: &str, source: &str, time: i64, a: &Value) -> Result<()> {
        let text = |k: &str| -> String {
            a[k].as_str()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_control())
                .take(120)
                .collect()
        };
        let system = match text("system") {
            s if s.is_empty() => "the source system".to_owned(),
            s => s,
        };
        let why = format!(
            "{system} reported a change-rate anomaly (its snapshot {})",
            text("snapshot")
        );
        self.flag_snapshot(tenant, source, time, &why)?;
        let bound = a["last_good_created"]
            .as_i64()
            .or(a["at"].as_i64())
            .unwrap_or(time)
            .min(time);
        let last = self.last_clean(tenant, source, bound + 1)?;
        self.raise(
            "critical",
            "anomaly",
            &format!("anomaly:{tenant}/{source}"),
            &format!("{why} on {tenant}/{source}: snapshot {time} holds the data after it; {last}"),
            Some(tenant),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn meta_from_the_result_line() {
        let log = "committed plugin-postgresql-3/100 1 entries\n\
                   result {\"snapshots\":[{\"source\":\"plugin-postgresql-3\",\"time\":100,\"meta\":{\"recoverable\":{\"to_time\":99}}},\
                   {\"source\":\"plugin-postgresql-3\",\"time\":101,\"meta\":null}],\"failed\":[]}\n";
        let mut snaps = vec![
            json!({"source": "plugin-postgresql-3", "time": 100}),
            json!({"source": "plugin-postgresql-3", "time": 101}),
        ];
        attach(log, &mut snaps);
        assert_eq!(snaps[0]["meta"]["recoverable"]["to_time"], 99);
        assert!(snaps[1].get("meta").is_none());
        // a forged line in plugin output is escaped/prefixed by the host, never `result `
        let mut s = vec![json!({"source": "x", "time": 1})];
        attach("plugin[info]: result {}", &mut s);
        assert!(s[0].get("meta").is_none());
    }
}
