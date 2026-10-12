//! Plugin snapshot metadata (protocol v1.6 `SnapshotMeta`, Phase 18b): the plugin
//! host prints it per snapshot in its `result {json}` line; the backup result
//! carries it as `snapshots[].meta` and it is kept in `snapshots.meta` (catalog v23),
//! e.g. PostgreSQL's recoverable range for the point-in-time restore dialog.

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
    /// `snapshots.meta` of a finished backup's snapshots (the row may not exist yet:
    /// the refresh fills in the rest).
    pub(crate) fn meta_bookkeeping(&self, job: &Job, result: Option<&Value>) -> Result<()> {
        for s in result.and_then(|r| r["snapshots"].as_array()).into_iter().flatten() {
            let (Some(src), Some(t), Some(m)) = (s["source"].as_str(), s["time"].as_i64(), s.get("meta")) else {
                continue;
            };
            if !m.is_object() {
                continue;
            }
            self.db.conn().execute(
                "INSERT INTO snapshots (tenant, source, time, local, offsite, meta) VALUES (?1,?2,?3,0,0,?4)
                 ON CONFLICT (tenant, source, time) DO UPDATE SET meta=?4",
                params![job.tenant, src, t, m.to_string()],
            )?;
        }
        Ok(())
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
