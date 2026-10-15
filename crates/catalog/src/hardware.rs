//! Disk and RAID health rules (Phase 16a, docs/hardware.md), shared by the scheduler
//! (`disk` alerts) and the web-api (issues and the summary on the Hardware page). The
//! input is the status JSON the root helper `nexus-disks` writes
//! (`/var/lib/nexus/disks/status.json`): stateless here; the scheduler adds the
//! "sector counts growing" escalation.

use serde_json::Value;
use std::collections::BTreeMap;

/// Directory of nexus-disks: status.json, ops.json (0644), `req-<id>.json` (web-api).
pub const DIR: &str = "/var/lib/nexus/disks";
/// Hotter than this (°C) is a warning: spinning disks / SSDs and NVMe.
pub const HDD_TEMP_MAX: i64 = 55;
pub const SSD_TEMP_MAX: i64 = 70;
/// NVMe "percentage used" (rated endurance consumed) from which it is a warning.
pub const NVME_WEAR_WARN: i64 = 90;
/// A status older than this means the helper stopped running.
pub const STALE_SECS: i64 = 1800;

/// (severity, message), worst first.
pub type Issues = Vec<(&'static str, String)>;

fn n(v: &Value) -> i64 {
    v.as_i64().unwrap_or(0)
}

fn sort(mut v: Issues) -> Issues {
    v.sort_by_key(|(s, _)| std::cmp::Reverse(crate::alerting::rank(s)));
    v
}

/// Bad sectors of a disk (pending + reallocated + offline uncorrectable): the scheduler
/// escalates when this grows.
pub fn sector_count(d: &Value) -> i64 {
    let s = &d["smart"];
    n(&s["pending"]) + n(&s["reallocated"]) + n(&s["offline_uncorrectable"])
}

/// What is wrong with one disk according to its SMART data.
pub fn disk_issues(d: &Value) -> Issues {
    let s = &d["smart"];
    let mut v = Issues::new();
    if s["available"] != Value::Bool(true) {
        return v;
    }
    if s["health"] == "failed" {
        v.push(("critical", "SMART health check failed: replace the disk".into()));
    }
    let (p, r, o) = (n(&s["pending"]), n(&s["reallocated"]), n(&s["offline_uncorrectable"]));
    if p + r + o > 0 {
        v.push((
            "warning",
            format!("{p} pending, {r} reallocated, {o} offline-uncorrectable sectors"),
        ));
    }
    if n(&s["critical_warning"]) != 0 {
        v.push((
            "warning",
            format!("NVMe critical warning 0x{:02x}", n(&s["critical_warning"])),
        ));
    }
    if n(&s["percentage_used"]) >= NVME_WEAR_WARN {
        v.push((
            "warning",
            format!("NVMe wear {} % of the rated endurance", n(&s["percentage_used"])),
        ));
    }
    if n(&s["media_errors"]) > 0 {
        v.push(("warning", format!("{} media errors", n(&s["media_errors"]))));
    }
    let max = if d["type"] == "hdd" { HDD_TEMP_MAX } else { SSD_TEMP_MAX };
    if let Some(t) = s["temperature"].as_i64().filter(|t| *t > max) {
        v.push(("warning", format!("temperature {t} °C (above {max} °C)")));
    }
    let last = &s["self_test"]["last"];
    if last["passed"] == Value::Bool(false) {
        v.push((
            "warning",
            format!(
                "last self-test ({}) failed: {}",
                last["type"].as_str().unwrap_or("?"),
                last["status"].as_str().unwrap_or("?")
            ),
        ));
    }
    sort(v)
}

/// What is wrong with one md array: failed or degraded (critical), a rebuild, resync or
/// reshape running (info, with the progress).
pub fn array_issues(a: &Value) -> Issues {
    let mut v = Issues::new();
    let state = a["state"].as_str().unwrap_or_default();
    let faulty: Vec<&str> = a["members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["state"] == "faulty")
        .map(|m| m["serial"].as_str().or(m["dev"].as_str()).unwrap_or("?"))
        .collect();
    if matches!(state, "failed" | "inactive") {
        v.push(("critical", format!("array {state}: the data on it is not available")));
    } else if a["degraded"] == Value::Bool(true) {
        let mut m = format!(
            "degraded: {} of {} devices active",
            n(&a["active_devices"]),
            n(&a["raid_devices"])
        );
        if !faulty.is_empty() {
            m += &format!(", failed: {}", faulty.join(", "));
        }
        v.push(("critical", m));
    } else if !faulty.is_empty() {
        v.push((
            "warning",
            format!("failed member(s) still listed: {}", faulty.join(", ")),
        ));
    }
    if let Some(action) = a["action"]
        .as_str()
        .filter(|x| matches!(*x, "recover" | "resync" | "reshape"))
    {
        let what = match action {
            "recover" => "rebuilding",
            "resync" => "resynchronising",
            _ => "reshaping",
        };
        let mut m = format!("{what} {:.1} %", a["progress"].as_f64().unwrap_or(0.0));
        if let Some(f) = a["finish_minutes"].as_f64() {
            m += &format!(" (about {} min left)", f.round() as i64);
        }
        v.push(("info", m));
    }
    sort(v)
}

fn disk_label(d: &Value) -> String {
    format!(
        "Disk {} {} ({})",
        d["model"].as_str().unwrap_or("?"),
        d["serial"].as_str().unwrap_or("?"),
        d["name"].as_str().unwrap_or("?")
    )
}

/// Alert key of a disk (`disk:<serial>`, the device name if it has none) and of an array
/// (`disk:md:<uuid>`; the rebuild info is `disk:md:<uuid>:sync`).
pub fn disk_key(d: &Value) -> String {
    format!("disk:{}", d["serial"].as_str().or(d["name"].as_str()).unwrap_or("?"))
}

pub fn array_key(a: &Value) -> String {
    format!("disk:md:{}", a["uuid"].as_str().or(a["name"].as_str()).unwrap_or("?"))
}

/// The open `disk` alerts this status asks for: key -> (severity, message). One per disk
/// (its worst issue decides), one per array problem, one for a running rebuild.
pub fn alerts(status: &Value) -> BTreeMap<String, (&'static str, String)> {
    let mut out = BTreeMap::new();
    for d in status["disks"].as_array().into_iter().flatten() {
        let is = disk_issues(d);
        if let Some((sev, _)) = is.first() {
            let msg = is.iter().map(|(_, m)| m.as_str()).collect::<Vec<_>>().join("; ");
            out.insert(disk_key(d), (*sev, format!("{}: {msg}", disk_label(d))));
        }
    }
    for a in status["arrays"].as_array().into_iter().flatten() {
        let label = format!(
            "Array {} ({}, {})",
            a["name"].as_str().unwrap_or("?"),
            a["level"].as_str().unwrap_or("?"),
            a["md_name"].as_str().or(a["role"].as_str()).unwrap_or("-")
        );
        for (sev, m) in array_issues(a) {
            let key = if sev == "info" {
                format!("{}:sync", array_key(a))
            } else {
                array_key(a)
            };
            out.entry(key).or_insert((sev, format!("{label}: {m}")));
        }
    }
    out
}

/// ok / warning / critical (worst issue over disks and arrays; a rebuild alone is a warning:
/// the redundancy is reduced until it finishes), unknown without a status.
pub fn summary(status: Option<&Value>) -> Value {
    let Some(s) = status else {
        return serde_json::json!({"state": "unknown", "disks": 0, "arrays": 0, "warnings": 0, "critical": 0});
    };
    let (mut warn, mut crit) = (0, 0);
    let worst = |is: Issues| is.first().map(|(s, _)| *s);
    let disks = s["disks"].as_array().map_or(&[][..], |v| v);
    let arrays = s["arrays"].as_array().map_or(&[][..], |v| v);
    for w in disks
        .iter()
        .map(|d| worst(disk_issues(d)))
        .chain(arrays.iter().map(|a| worst(array_issues(a))))
    {
        match w {
            Some("critical") => crit += 1,
            Some(_) => warn += 1,
            None => {}
        }
    }
    let state = if crit > 0 {
        "critical"
    } else if warn > 0 {
        "warning"
    } else {
        "ok"
    };
    serde_json::json!({"state": state, "disks": disks.len(), "arrays": arrays.len(), "warnings": warn, "critical": crit})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn disk(smart: Value) -> Value {
        json!({"name": "sdc", "serial": "WD-1", "model": "WDC", "type": "hdd", "smart": smart})
    }

    #[test]
    fn disk_rules() {
        let ok = json!({"available": true, "health": "passed", "temperature": 38, "pending": 0, "reallocated": 0});
        assert!(disk_issues(&disk(ok.clone())).is_empty());
        assert!(disk_issues(&disk(json!({"available": false, "error": "virtio"}))).is_empty());
        let mut bad = ok.clone();
        bad["pending"] = json!(8);
        bad["reallocated"] = json!(24);
        bad["temperature"] = json!(58);
        let is = disk_issues(&disk(bad.clone()));
        assert_eq!(is.len(), 2);
        assert_eq!(
            is[0],
            (
                "warning",
                "8 pending, 24 reallocated, 0 offline-uncorrectable sectors".into()
            )
        );
        assert!(is[1].1.contains("58 °C"));
        bad["health"] = json!("failed");
        assert_eq!(disk_issues(&disk(bad.clone()))[0].0, "critical");
        assert_eq!(sector_count(&disk(bad)), 32);
        // NVMe: wear, critical warning, media errors; 58 °C is fine for an SSD
        let nv = json!({"name": "nvme0n1", "serial": "S7", "type": "nvme", "smart": {"available": true, "health": "passed",
            "temperature": 58, "percentage_used": 91, "critical_warning": 4, "media_errors": 2}});
        let is = disk_issues(&nv);
        assert_eq!(is.len(), 3, "{is:?}");
        assert!(is.iter().all(|(s, _)| *s == "warning"));
        let st = json!({"available": true, "health": "passed",
            "self_test": {"running": false, "last": {"type": "Short offline", "status": "Completed: read failure", "passed": false}}});
        assert!(disk_issues(&disk(st))[0].1.contains("read failure"));
    }

    #[test]
    fn array_rules_and_alerts() {
        let a = json!({"name": "md126", "uuid": "3f0c1a2b:4d5e6f70:81920a1b:2c3d4e5f", "level": "raid6", "md_name": "nexus-data",
            "state": "recovering", "degraded": true, "raid_devices": 4, "active_devices": 3, "action": "recover",
            "progress": 24.8, "finish_minutes": 301.2,
            "members": [{"serial": "WD-4", "dev": "sdf", "state": "faulty"}, {"serial": "WD-5", "dev": "sdg", "state": "rebuilding"}]});
        let is = array_issues(&a);
        assert_eq!(
            is[0],
            ("critical", "degraded: 3 of 4 devices active, failed: WD-4".into())
        );
        assert_eq!(is[1], ("info", "rebuilding 24.8 % (about 301 min left)".into()));
        let st = json!({"disks": [disk(json!({"available": true, "health": "failed"}))], "arrays": [a]});
        let al = alerts(&st);
        assert_eq!(al.len(), 3);
        assert_eq!(al["disk:WD-1"].0, "critical");
        assert_eq!(
            al["disk:WD-1"].1,
            "Disk WDC WD-1 (sdc): SMART health check failed: replace the disk"
        );
        let k = "disk:md:3f0c1a2b:4d5e6f70:81920a1b:2c3d4e5f";
        assert_eq!(
            al[k].1,
            "Array md126 (raid6, nexus-data): degraded: 3 of 4 devices active, failed: WD-4"
        );
        assert_eq!(al[&format!("{k}:sync")].0, "info");
        assert_eq!(summary(Some(&st))["state"], "critical");
        assert_eq!(summary(None)["state"], "unknown");
        let clean = json!({"name": "md127", "state": "clean", "degraded": false, "members": []});
        assert!(array_issues(&clean).is_empty());
        assert_eq!(summary(Some(&json!({"disks": [], "arrays": [clean]})))["state"], "ok");
        let failed = json!({"name": "md0", "state": "inactive", "degraded": false, "members": []});
        assert_eq!(array_issues(&failed)[0].0, "critical");
    }
}
