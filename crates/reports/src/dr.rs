//! DR report of one recovery run (test run or execution, Phase 25): a
//! self-contained HTML page (inline styles, no scripts) with the plan as it
//! ran, who requested and approved it, and per guest the snapshot used, the
//! target, the times and every check. Printable to PDF from the browser.

use crate::{escape, iso};
use catalog::rusqlite::{self, Connection, OptionalExtension};
use serde_json::Value;
use std::fmt::Write as _;

fn dur(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min {} s", s / 60, s % 60),
        s => format!("{} h {} min", s / 3600, s / 60 % 60),
    }
}

/// The report of run `id` (None: no such run). `scope`: only runs of that tenant.
pub fn dr_report(c: &Connection, id: i64, scope: Option<&str>, host: &str) -> rusqlite::Result<Option<String>> {
    type Row = (
        String,
        String,
        String,
        String,
        Option<i64>,
        String,
        String,
        i64,
        Option<i64>,
    );
    let row: Option<Row> = c
        .query_row(
            "SELECT tenant, mode, state, requested_by, quorum_id, plan, results, started, finished FROM recovery_runs
             WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
            rusqlite::params![id, scope],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            },
        )
        .optional()?;
    let Some((tenant, mode, state, by, quorum, plan, results, started, finished)) = row else {
        return Ok(None);
    };
    let approved: Option<String> = match quorum {
        Some(q) => c
            .query_row("SELECT decided_by FROM quorum WHERE id = ?1", [q], |r| r.get(0))
            .optional()?
            .flatten(),
        None => None,
    };
    let plan: Value = serde_json::from_str(&plan).unwrap_or(Value::Null);
    let results: Value = serde_json::from_str(&results).unwrap_or(Value::Null);
    let s = |v: &Value| escape(v.as_str().unwrap_or(""));
    let what = if mode == "execute" {
        "Disaster recovery execution"
    } else {
        "Recovery plan test run"
    };
    let color = match state.as_str() {
        "passed" => "#1f7a3a",
        "running" => "#52606d",
        _ => "#b42318",
    };
    let mut h = String::new();
    let _ = write!(
        h,
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>DR report {} run {id}</title></head>\
         <body style=\"font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1f2933;max-width:1100px;margin:24px auto\">\
         <h1 style=\"font-size:22px;margin:0 0 4px\">{what}: {}</h1>\
         <p style=\"margin:0 0 16px;color:#52606d\">tenant {} · run {id} · appliance {}</p>\
         <p style=\"font-size:18px;font-weight:bold;color:{color}\">{}</p><table style=\"border-collapse:collapse\">",
        s(&plan["name"]),
        s(&plan["name"]),
        escape(&tenant),
        escape(host),
        escape(&state.to_uppercase()),
    );
    let mut kv = |k: &str, v: String| {
        let _ = write!(
            h,
            "<tr><th style=\"text-align:left;padding:2px 16px 2px 0;color:#52606d\">{}</th><td>{v}</td></tr>",
            escape(k)
        );
    };
    kv("Requested by", escape(&by));
    if mode == "execute" {
        kv(
            "Approved by",
            escape(approved.as_deref().unwrap_or("(approvals disabled)")),
        );
    }
    kv("Started", iso(started));
    kv(
        "Finished",
        finished.map_or("still running".into(), |f| {
            format!("{} (after {})", iso(f), dur(f - started))
        }),
    );
    kv(
        "Target node / storage",
        format!("{} / {}", s(&plan["node"]), s(&plan["storage"])),
    );
    let network = if mode == "execute" {
        let map: Vec<String> = plan["network_map"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, v)| format!("{} → {}", escape(k), s(v)))
            .collect();
        if map.is_empty() {
            "bridges as backed up".into()
        } else {
            map.join(", ")
        }
    } else {
        match plan["test_bridge"].as_str() {
            Some(b) => format!("isolated bridge {}", escape(b)),
            None => "isolated: all network links down".into(),
        }
    };
    kv("Network", network);
    kv("RPO", format!("{} h", plan["rpo_hours"].as_i64().unwrap_or(24)));
    h.push_str("</table><h2 style=\"font-size:16px;margin:24px 0 8px\">Steps</h2>");
    let th =
        |t: &str| format!("<th style=\"text-align:left;border-bottom:2px solid #9aa5b1;padding:4px 8px\">{t}</th>");
    let _ = write!(
        h,
        "<table style=\"border-collapse:collapse;font-size:13px;width:100%\"><tr>{}{}{}{}{}{}{}{}</tr>",
        th("Wave"),
        th("Guest"),
        th("Snapshot"),
        th("Restored as"),
        th("Result"),
        th("Boot"),
        th("Times"),
        th("Checks")
    );
    let td = "border-bottom:1px solid #e4e7eb;padding:4px 8px;vertical-align:top";
    for r in results.as_array().into_iter().flatten() {
        let checks: Vec<String> = r["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| {
                format!(
                    "<span style=\"color:{}\">{} {}</span>: {}",
                    if c["ok"] == true { "#1f7a3a" } else { "#b42318" },
                    if c["ok"] == true { "✓" } else { "✗" },
                    s(&c["name"]),
                    s(&c["detail"])
                )
            })
            .chain(
                r["error"]
                    .as_str()
                    .map(|e| format!("<span style=\"color:#b42318\">error: {}</span>", escape(e))),
            )
            .chain((r["destroyed"] == false).then(|| "<b>test guest not destroyed: remove it by hand</b>".to_owned()))
            .collect();
        let target = match (r["target"].as_u64(), r["name"].as_str()) {
            (Some(t), Some(n)) => format!("{t} {}", escape(n)),
            _ => "–".into(),
        };
        let times = match (r["started"].as_i64(), r["finished"].as_i64()) {
            (Some(a), Some(b)) => format!("{} – {}", iso(a), &iso(b)[11..]),
            _ => String::new(),
        };
        let _ = write!(
            h,
            "<tr><td style=\"{td}\">{}</td><td style=\"{td}\">{}</td><td style=\"{td}\">{}</td><td style=\"{td}\">{target}</td>\
             <td style=\"{td}\">{}</td><td style=\"{td}\">{}</td><td style=\"{td}\">{times}</td><td style=\"{td}\">{}</td></tr>",
            r["wave"].as_u64().map_or(String::new(), |w| w.to_string()),
            s(&r["source"]),
            r["time"].as_i64().map_or(String::new(), iso),
            s(&r["state"]),
            r["boot_secs"].as_i64().map_or("–".into(), dur),
            checks.join("<br>")
        );
    }
    h.push_str(
        "</table><p style=\"margin-top:24px;color:#7b8794;font-size:12px\">Times are UTC. Generated by the NexusBackup \
         appliance (Recovery plans page). Test runs boot isolated copies that are destroyed afterwards; an execution \
         restores the guests for real.</p></body></html>",
    );
    Ok(Some(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_lists_steps_and_escapes() {
        let cat = catalog::Catalog::open_memory().unwrap();
        let c = cat.conn();
        c.execute_batch(
            r#"INSERT INTO quorum (id, action, params, requested_by, created, decided_by, state)
                 VALUES (4, 'recovery_plan.execute', '{}', 'alice', 1, 'bob', 'executed');
               INSERT INTO recovery_runs (id, plan_id, tenant, mode, state, requested_by, quorum_id, plan, results, started, finished)
               VALUES (7, 1, 'acme', 'execute', 'failed', 'alice', 4,
                 '{"name": "erp <prod>", "node": "pve1", "storage": "local-lvm", "network_map": {"vmbr0": "vmbr9"}, "rpo_hours": 24}',
                 '[{"source": "vm-101", "time": 1791700000, "wave": 1, "target": 101, "name": "db1", "state": "passed",
                    "started": 1791800000, "finished": 1791800090, "boot_secs": 45,
                    "checks": [{"name": "tcp/5432", "ok": true, "detail": "listening"}]},
                   {"source": "vm-102", "time": 1791700000, "wave": 2, "state": "skipped", "error": "an earlier wave failed"}]',
                 1791800000, 1791800400);"#,
        )
        .unwrap();
        let h = dr_report(&c, 7, None, "nexus1").unwrap().unwrap();
        assert!(h.contains("Disaster recovery execution: erp &lt;prod&gt;"));
        assert!(h.contains("Approved by</th><td>bob"));
        assert!(h.contains("vmbr0 → vmbr9"));
        assert!(h.contains("101 db1"));
        assert!(h.contains("✓ tcp/5432</span>: listening"));
        assert!(h.contains("error: an earlier wave failed"));
        assert!(h.contains("after 6 min 40 s"));
        assert!(!h.contains("<prod>"));
        assert!(dr_report(&c, 7, Some("globex"), "x").unwrap().is_none());
        assert!(dr_report(&c, 8, None, "x").unwrap().is_none());
    }
}
