//! Snapshot source names of VMware VMs, without the connector's dependencies (web-api, scheduler): `vmw-<uuid>`,
//! the VM's instance UUID (vCenter) or BIOS UUID (standalone host). The UUID is also the guest id in a group and
//! the inventory, so the scheduler can map a group's guests to their snapshots.

/// Prefix of a VMware VM's snapshot source.
pub const SOURCE_PREFIX: &str = "vmw-";

/// The snapshot source of a VM.
pub fn source_name(uuid: &str) -> String {
    format!("{SOURCE_PREFIX}{uuid}")
}

/// A VM UUID as vSphere reports it: 32 hex digits, optionally with dashes (`5003c9a6-1b2e-...`).
pub fn valid_uuid(s: &str) -> bool {
    let hex = s.chars().filter(char::is_ascii_hexdigit).count();
    s.len() <= 36 && hex == 32 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// The UUID of a `vmw-<uuid>` source name.
pub fn parse_source_name(s: &str) -> Option<&str> {
    s.strip_prefix(SOURCE_PREFIX).filter(|u| valid_uuid(u))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let u = "5003c9a6-1b2e-4f7a-9d3c-0123456789ab";
        assert!(valid_uuid(u));
        assert!(valid_uuid("5003c9a61b2e4f7a9d3c0123456789ab"));
        assert_eq!(parse_source_name(&source_name(u)), Some(u));
        for bad in [
            "",
            "5003c9a6",
            "5003c9a6-1b2e-4f7a-9d3c-0123456789ag",
            "../etc",
            "5003c9a6 1b2e 4f7a 9d3c 0123456789ab",
        ] {
            assert!(!valid_uuid(bad), "{bad}");
        }
        assert_eq!(parse_source_name("vm-101"), None);
        assert_eq!(parse_source_name("vmw-x"), None);
    }
}
