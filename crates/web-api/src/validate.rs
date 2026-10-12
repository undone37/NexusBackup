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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Gfs {
    pub daily: u32,
    pub weekly: u32,
    pub monthly: u32,
    pub yearly: u32,
}

impl Gfs {
    pub fn check(&self) -> ApiResult<()> {
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
        new.daily < self.daily || new.weekly < self.weekly || new.monthly < self.monthly || new.yearly < self.yearly
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

/// Absolute path on a host without `.`/`..` components (restore targets).
pub fn host_path(s: &str, what: &str) -> ApiResult<()> {
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

/// `vm-<vmid>`, `ct-<vmid>`, `host-<agent_id>`, `nas-<source-id>-<dataset>` (TrueNAS) or `share-<source-id>` (NFS/SMB).
pub fn source_ref(s: &str) -> ApiResult<()> {
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

pub const ROLES: [&str; 4] = ["admin", "security_officer", "operator", "tenant_user"];

pub fn role(s: &str) -> ApiResult<()> {
    if ROLES.contains(&s) {
        Ok(())
    } else {
        Err(ApiError::bad(
            "role: must be admin, security_officer, operator or tenant_user",
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
        ] {
            assert!(schedule(bad).is_err(), "{bad}");
        }
        assert!(timezone("Europe/Berlin").is_ok() && timezone("UTC").is_ok() && timezone("CEST").is_err());
        assert!(source_ref("vm-100").is_ok() && source_ref("ct-999").is_ok());
        assert!(source_ref("vm-99").is_err() && source_ref("vm-0100").is_err() && source_ref("xx-100").is_err());
        assert!(source_ref("host-0123456789abcdef").is_ok() && source_ref("host-0123456789ABCDEF").is_err());
        assert!(
            host_path("/srv/x", "t").is_ok()
                && host_path("/srv/../etc", "t").is_err()
                && host_path("srv", "t").is_err()
        );
        let g = Gfs {
            daily: 7,
            weekly: 4,
            monthly: 12,
            yearly: 1,
        };
        assert!(g.lowered_by(&Gfs { yearly: 0, ..g }) && !g.lowered_by(&Gfs { daily: 30, ..g }));
        assert!(Gfs { daily: 1001, ..g }.check().is_err());
    }
}
