//! Input validation shared by all handlers.

use crate::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};

/// `[A-Za-z0-9._-]{1,64}`, no leading dot (names end up in paths, threat model T11).
pub fn name(s: &str, what: &str) -> ApiResult<()> {
    let ok = (1..=64).contains(&s.len())
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "{what}: must match [A-Za-z0-9._-]{{1,64}} without a leading dot"
        )))
    }
}

/// A policy schedule (`catalog::schedule`: `daily HH:MM`, `hourly MM`,
/// `every Nh [at MM]`, `Mon,Wed HH:MM`, `monthly D HH:MM`).
pub fn schedule(s: &str) -> ApiResult<()> {
    catalog::schedule::Schedule::parse(s)
        .map(drop)
        .map_err(|e| ApiError::bad(format!("schedule: {e}")))
}

/// IANA time zone of a group (`Europe/Berlin`, `UTC`).
pub fn timezone(s: &str) -> ApiResult<()> {
    catalog::schedule::tz(s)
        .map(drop)
        .map_err(|e| ApiError::bad(format!("timezone: {e}")))
}

/// Bandwidth windows (offsite, replication source; Phase 17a).
pub fn windows(w: &[catalog::schedule::RateWindow]) -> ApiResult<()> {
    catalog::schedule::check_windows(w).map_err(|e| ApiError::bad(format!("windows: {e}")))
}

/// Sync window of a replication source (Phase 17a).
pub fn sync_window(s: &[catalog::schedule::Span]) -> ApiResult<()> {
    catalog::schedule::check_spans(s).map_err(|e| ApiError::bad(format!("sync_window: {e}")))
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Gfs {
    /// keep every snapshot of the last N hours (Phase 18b; policies only)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub recent: u32,
    pub daily: u32,
    pub weekly: u32,
    pub monthly: u32,
    pub yearly: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl Gfs {
    pub fn check(&self) -> ApiResult<()> {
        if self.recent > 8760 {
            return Err(ApiError::bad("gfs.recent: hours within 0..=8760"));
        }
        if [self.daily, self.weekly, self.monthly, self.yearly]
            .iter()
            .all(|v| *v <= 1000)
        {
            Ok(())
        } else {
            Err(ApiError::bad("gfs: values must be within 0..=1000"))
        }
    }
    /// True if any retention count of `new` is lower than in `self`.
    pub fn lowered_by(&self, new: &Gfs) -> bool {
        new.recent < self.recent
            || new.daily < self.daily
            || new.weekly < self.weekly
            || new.monthly < self.monthly
            || new.yearly < self.yearly
    }
}

pub fn vmid(v: u32) -> ApiResult<()> {
    if (100..=999_999_999).contains(&v) {
        Ok(())
    } else {
        Err(ApiError::bad("vmid: must be within 100..=999999999"))
    }
}

/// Agent ids (chosen by `POST /agents`): 16 lowercase hex characters.
pub fn agent_id(s: &str) -> ApiResult<()> {
    if s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(ApiError::bad("agent_id: expected 16 lowercase hex characters"))
    }
}

/// `C:\Users\a` / `C:/Users/a` -> `/C/Users/a`, the Windows agent's path form in snapshots
/// (docs/agent-windows.md "Paths"); `None` for anything else.
pub fn windows_canonical(s: &str) -> Option<String> {
    let b = s.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        .then(|| format!("/{}{}", &s[..1], s[2..].replace('\\', "/")))
}

/// Absolute path on a host without `.`/`..` components (restore targets); Windows agents
/// also take `C:\...` (checked in its canonical form).
pub fn host_path(s: &str, what: &str) -> ApiResult<()> {
    let canonical = windows_canonical(s);
    let s = canonical.as_deref().unwrap_or(s);
    guest_path(s).map_err(|_| {
        ApiError::bad(format!(
            "{what}: must be absolute, at most 4096 bytes, without control characters"
        ))
    })?;
    if s.split('/').any(|c| c == "." || c == "..") {
        return Err(ApiError::bad(format!("{what}: `.` and `..` are not allowed")));
    }
    Ok(())
}

/// `vm-<vmid>`, `ct-<vmid>`, `host-<agent_id>`, `nas-<source-id>-<dataset>` (TrueNAS), `share-<source-id>` (NFS/SMB)
/// `vmw-<uuid>` (VMware) or `xcp-<uuid>` (XCP-ng).
pub fn source_ref(s: &str) -> ApiResult<()> {
    if s.starts_with(vmware::names::SOURCE_PREFIX) {
        return vmware::names::parse_source_name(s)
            .map(|_| ())
            .ok_or_else(|| ApiError::bad("source: expected vmw-<VM UUID>"));
    }
    if s.starts_with(xcpng::names::SOURCE_PREFIX) {
        return xcpng::names::parse_source_name(s)
            .map(|_| ())
            .ok_or_else(|| ApiError::bad("source: expected xcp-<VM UUID>"));
    }
    if s.starts_with("plugin-") {
        return plugin_proto::parse_source_name(s)
            .map(|_| ())
            .ok_or_else(|| ApiError::bad("source: expected plugin-<plugin>-<source-id>[-<guest>]"));
    }
    if s.starts_with("share-") {
        return nas::parse_source_name(s)
            .map(|_| ())
            .ok_or_else(|| ApiError::bad("source: expected share-<source-id>"));
    }
    if s.starts_with("nas-") {
        return truenas::parse_source_name(s)
            .map(|_| ())
            .ok_or_else(|| ApiError::bad("source: expected nas-<source-id>-<pool.dataset>"));
    }
    if let Some(a) = s.strip_prefix("host-") {
        return agent_id(a).map_err(|_| ApiError::bad("source: expected vm-<vmid>, ct-<vmid> or host-<agent_id>"));
    }
    let ok = s
        .strip_prefix("vm-")
        .or_else(|| s.strip_prefix("ct-"))
        .and_then(|n| {
            if n.starts_with('0') {
                None
            } else {
                n.parse::<u32>().ok()
            }
        })
        .is_some_and(|v| vmid(v).is_ok());
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad(
            "source: expected vm-<vmid>, ct-<vmid> or host-<agent_id>",
        ))
    }
}

/// Free text with a length bound and no control characters.
pub fn text(s: &str, what: &str, max: usize) -> ApiResult<()> {
    if s.len() <= max && !s.chars().any(|c| c.is_control() && c != '\n' && c != '\r') {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "{what}: too long or contains control characters"
        )))
    }
}

/// Absolute path inside a guest file system.
pub fn guest_path(s: &str) -> ApiResult<()> {
    if s.starts_with('/') && s.len() <= 4096 && !s.contains('\0') && !s.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(ApiError::bad(
            "path: must be absolute, at most 4096 bytes, without control characters",
        ))
    }
}

pub fn host(s: &str) -> ApiResult<()> {
    let ok = (1..=253).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        && !s.starts_with('-');
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad("host: invalid host name or address"))
    }
}

/// `viewer` (v15): read-only, appliance-wide or one tenant. `tenant_admin`
/// (Phase 19b): manages one tenant (crate::tenancy, docs/control-plane.md).
pub const ROLES: [&str; 6] = [
    "admin",
    "security_officer",
    "operator",
    "tenant_admin",
    "tenant_user",
    "viewer",
];

pub fn role(s: &str) -> ApiResult<()> {
    if ROLES.contains(&s) {
        Ok(())
    } else {
        Err(ApiError::bad(
            "role: must be admin, security_officer, operator, tenant_admin, tenant_user or viewer",
        ))
    }
}

pub fn privileged(role: &str) -> bool {
    role == "admin" || role == "security_officer"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert!(name("acme-1.prod_x", "n").is_ok());
        for bad in ["", ".hidden", "a/b", "a b", &"x".repeat(65), "ä"] {
            assert!(name(bad, "n").is_err(), "{bad}");
        }
        for ok in [
            "daily 00:00",
            "daily 23:59",
            "hourly 05",
            "every 6h at 15",
            "every 15m",
            "Mon-Fri 22:00",
            "monthly 1 03:00",
        ] {
            assert!(schedule(ok).is_ok(), "{ok}");
        }
        for bad in [
            "daily 24:00",
            "daily 1:00",
            "hourly 60",
            "weekly 01",
            "daily 12:00 ",
            "hourly +5",
            "every 7h",
            "every 7m",
            "every 1m",
        ] {
            assert!(schedule(bad).is_err(), "{bad}");
        }
        assert!(timezone("Europe/Berlin").is_ok() && timezone("UTC").is_ok() && timezone("CEST").is_err());
        assert!(source_ref("vm-100").is_ok() && source_ref("ct-999").is_ok());
        assert!(source_ref("vm-99").is_err() && source_ref("vm-0100").is_err() && source_ref("xx-100").is_err());
        assert!(source_ref("host-0123456789abcdef").is_ok() && source_ref("host-0123456789ABCDEF").is_err());
        assert!(source_ref("vmw-5003c9a6-1b2e-4f7a-9d3c-0123456789ab").is_ok());
        assert!(source_ref("vmw-5003c9a6").is_err() && source_ref("vmw-../x").is_err());
        assert!(source_ref("xcp-4b885545-0f69-4a05-9f95-f1f0a75cf2cb").is_ok());
        assert!(source_ref("xcp-4b885545").is_err() && source_ref("xcp-../x").is_err());
        assert!(
            host_path("/srv/x", "t").is_ok()
                && host_path("C:\\Users\\a", "t").is_ok()
                && host_path("C:/Users/a", "t").is_ok()
                && host_path("C:\\Users\\..\\Windows", "t").is_err()
                && windows_canonical("C:\\Users\\a b").as_deref() == Some("/C/Users/a b")
                && windows_canonical("/srv").is_none()
                && host_path("/srv/../etc", "t").is_err()
                && host_path("srv", "t").is_err()
        );
        let g = Gfs {
            recent: 0,
            daily: 7,
            weekly: 4,
            monthly: 12,
            yearly: 1,
        };
        assert!(g.lowered_by(&Gfs { yearly: 0, ..g }) && !g.lowered_by(&Gfs { daily: 30, ..g }));
        assert!(Gfs { daily: 1001, ..g }.check().is_err());
        assert!(Gfs { recent: 24, ..g }.check().is_ok() && Gfs { recent: 8761, ..g }.check().is_err());
        assert!(Gfs { recent: 24, ..g }.lowered_by(&g) && !g.lowered_by(&Gfs { recent: 24, ..g }));
    }
}
