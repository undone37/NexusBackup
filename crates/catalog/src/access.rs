//! Access settings shared by the web-api (writes them, enforces the session
//! limits), the scheduler (dormant accounts, management allow-list for the
//! firewall) and nexus-setup (console reset of the allow-list); catalog v15,
//! docs/control-plane.md "Access".

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// `{idle_min, absolute_h}`
pub const SESSION: &str = "session";
/// days without login after which an account is disabled; 0 / absent = off
pub const DORMANT_DAYS: &str = "dormant_days";
/// text shown on the login page (≤ [`BANNER_MAX`] characters)
pub const LOGIN_BANNER: &str = "login_banner";
/// JSON array of CIDRs allowed to reach the management port; empty = any.
/// Since Phase 16c a mirror of the inbound policy's `web` list (crate::firewall).
pub const MGMT_ALLOW: &str = "mgmt_allow";

pub const BANNER_MAX: usize = 2000;
pub const MGMT_MAX: usize = 64;
pub const DORMANT_MAX: i64 = 3650;

/// Session timeouts (defaults: 30 min idle, 12 h absolute).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct SessionLimits {
    pub idle_min: i64,
    pub absolute_h: i64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        SessionLimits {
            idle_min: 30,
            absolute_h: 12,
        }
    }
}

impl SessionLimits {
    pub fn check(&self) -> Result<(), &'static str> {
        if !(5..=120).contains(&self.idle_min) {
            return Err("idle_min: 5..=120 minutes");
        }
        if !(1..=24).contains(&self.absolute_h) {
            return Err("absolute_h: 1..=24 hours");
        }
        Ok(())
    }
    pub fn idle_secs(&self) -> i64 {
        self.idle_min * 60
    }
    pub fn absolute_secs(&self) -> i64 {
        self.absolute_h * 3600
    }
    /// Either timeout gets longer (a weakening: approval).
    pub fn looser_than(&self, old: &SessionLimits) -> bool {
        self.idle_min > old.idle_min || self.absolute_h > old.absolute_h
    }
}

/// Stored limits; a missing or unreadable value means the defaults.
pub fn session_limits(c: &Connection) -> rusqlite::Result<SessionLimits> {
    Ok(crate::setting(c, SESSION)?
        .and_then(|v| serde_json::from_str::<SessionLimits>(&v).ok())
        .filter(|l| l.check().is_ok())
        .unwrap_or_default())
}

pub fn dormant_days(c: &Connection) -> rusqlite::Result<i64> {
    Ok(crate::setting(c, DORMANT_DAYS)?
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|d| (0..=DORMANT_MAX).contains(d))
        .unwrap_or(0))
}

pub fn login_banner(c: &Connection) -> rusqlite::Result<String> {
    Ok(crate::setting(c, LOGIN_BANNER)?.unwrap_or_default())
}

/// Download privilege of a role when the account has no explicit
/// `can_download`: admins, operators and tenant users restore files to the
/// browser; viewers and security officers (approvals, audit) do not.
pub fn role_can_download(role: &str) -> bool {
    matches!(role, "admin" | "operator" | "tenant_user")
}

/// `a.b.c.d/n`, `v6/n` or a bare address (= /32, /128), normalised to the
/// network address (host bits cleared). `None` if not a valid CIDR.
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = match s.trim().split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s.trim(), None),
    };
    let addr: IpAddr = a.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix: u8 = match p {
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.len() <= 3 => p.parse().ok()?,
        Some(_) => return None,
        None => max,
    };
    if prefix > max {
        return None;
    }
    Some((mask(addr, prefix), prefix))
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v) => {
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            IpAddr::V4((u32::from(v) & m).into())
        }
        IpAddr::V6(v) => {
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

/// Canonical text form (`10.0.0.0/8`).
pub fn cidr_string(s: &str) -> Option<String> {
    parse_cidr(s).map(|(a, p)| format!("{a}/{p}"))
}

/// Whether `ip` (canonical text, as the web-api's `ClientIp`) lies in one of
/// the CIDRs; an empty list allows everything.
pub fn allows(list: &[String], ip: &str) -> bool {
    if list.is_empty() {
        return true;
    }
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    let ip = match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    list.iter()
        .filter_map(|c| parse_cidr(c))
        .any(|(net, p)| net.is_ipv4() == ip.is_ipv4() && mask(ip, p) == net)
}

/// The management allow-list: the inbound policy's `web` sources
/// (crate::firewall, Phase 16c).
pub fn mgmt_allow(c: &Connection) -> rusqlite::Result<Vec<String>> {
    Ok(crate::firewall::load(c)?.rule("web").allow)
}

/// The 14d setting as stored (canonical CIDRs; invalid entries dropped):
/// read by the inbound policy's migration only.
pub fn legacy_mgmt_allow(c: &Connection) -> rusqlite::Result<Vec<String>> {
    Ok(crate::setting(c, MGMT_ALLOW)?
        .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|s| cidr_string(s))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidrs() {
        assert_eq!(cidr_string("10.1.2.3/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(cidr_string("192.0.2.7").as_deref(), Some("192.0.2.7/32"));
        assert_eq!(cidr_string("2001:db8::1/32").as_deref(), Some("2001:db8::/32"));
        assert_eq!(cidr_string("0.0.0.0/0").as_deref(), Some("0.0.0.0/0"));
        for bad in [
            "",
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "x/8",
            "10.0.0.0/8 ; flush",
            "::/129",
        ] {
            assert_eq!(cidr_string(bad), None, "{bad}");
        }
        let l = vec!["10.0.0.0/8".to_owned(), "2001:db8::/32".to_owned()];
        assert!(allows(&l, "10.9.9.9") && allows(&l, "::ffff:10.1.1.1") && allows(&l, "2001:db8::5"));
        assert!(!allows(&l, "192.0.2.1") && !allows(&l, "unknown") && !allows(&l, "2001:db9::1"));
        assert!(allows(&[], "unknown"));
    }

    #[test]
    fn session_limits_and_defaults() {
        let d = SessionLimits::default();
        assert_eq!((d.idle_secs(), d.absolute_secs()), (1800, 43200));
        assert!(SessionLimits { idle_min: 4, ..d }.check().is_err());
        assert!(SessionLimits { absolute_h: 25, ..d }.check().is_err());
        assert!(SessionLimits { idle_min: 60, ..d }.looser_than(&d));
        assert!(!SessionLimits { idle_min: 10, ..d }.looser_than(&d));
        let c = crate::Catalog::open_memory().unwrap();
        let conn = c.conn();
        assert_eq!(session_limits(&conn).unwrap(), d);
        crate::set_setting(&conn, SESSION, r#"{"idle_min":1,"absolute_h":2}"#).unwrap();
        assert_eq!(session_limits(&conn).unwrap(), d, "out of range: defaults");
        assert_eq!(dormant_days(&conn).unwrap(), 0);
        crate::set_setting(&conn, MGMT_ALLOW, r#"["10.1.0.0/16","bad"]"#).unwrap();
        assert_eq!(mgmt_allow(&conn).unwrap(), vec!["10.1.0.0/16"]);
    }
}
