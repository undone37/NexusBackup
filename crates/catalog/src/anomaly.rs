//! Per-source sensitivity of the anomaly checks (Phase 30, catalog v45,
//! docs/ransomware-signals.md "Duration and dedup rate"): `low` | `medium` |
//! `high` per (tenant, source) in `anomaly_sensitivity`; no row = `medium`.
//! The scheduler (`anomaly.rs`) maps a level to its thresholds; the web-api
//! sets it (`PUT /stats/sensitivity`, lowering it is an approval).

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Approval action of a lowered sensitivity (weakens a ransomware signal).
pub const LOWER_ACTION: &str = "anomaly.sensitivity";

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Low,
    #[default]
    Medium,
    High,
}

impl Sensitivity {
    pub fn as_str(self) -> &'static str {
        match self {
            Sensitivity::Low => "low",
            Sensitivity::Medium => "medium",
            Sensitivity::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Sensitivity> {
        match s {
            "low" => Some(Sensitivity::Low),
            "medium" => Some(Sensitivity::Medium),
            "high" => Some(Sensitivity::High),
            _ => None,
        }
    }
}

/// The source's level (`medium` without a row or with an unreadable one).
pub fn get(c: &Connection, tenant: &str, source: &str) -> rusqlite::Result<Sensitivity> {
    let v: Option<String> = c
        .query_row(
            "SELECT level FROM anomaly_sensitivity WHERE tenant = ?1 AND source = ?2",
            params![tenant, source],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v.as_deref().and_then(Sensitivity::parse).unwrap_or_default())
}

/// Stores a level; `medium` removes the row (the default).
pub fn set(c: &Connection, tenant: &str, source: &str, level: Sensitivity, by: &str) -> rusqlite::Result<()> {
    if level == Sensitivity::Medium {
        c.execute(
            "DELETE FROM anomaly_sensitivity WHERE tenant = ?1 AND source = ?2",
            params![tenant, source],
        )?;
        return Ok(());
    }
    c.execute(
        "INSERT INTO anomaly_sensitivity (tenant, source, level, set_by, set_at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (tenant, source) DO UPDATE SET level = excluded.level, set_by = excluded.set_by,
           set_at = excluded.set_at",
        params![tenant, source, level.as_str(), by, crate::now()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_set_and_order() {
        let cat = crate::Catalog::open_memory().unwrap();
        let c = cat.conn();
        assert_eq!(get(&c, "t", "vm-1").unwrap(), Sensitivity::Medium);
        set(&c, "t", "vm-1", Sensitivity::High, "ann").unwrap();
        assert_eq!(get(&c, "t", "vm-1").unwrap(), Sensitivity::High);
        set(&c, "t", "vm-1", Sensitivity::Medium, "ann").unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM anomaly_sensitivity", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "medium is the default: no row");
        assert!(Sensitivity::Low < Sensitivity::Medium && Sensitivity::Medium < Sensitivity::High);
        assert_eq!(Sensitivity::parse("max"), None);
    }
}
