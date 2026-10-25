//! Snapshot source names of XCP-ng VMs, without the connector's dependencies (web-api, scheduler): `xcp-<uuid>`,
//! the VM UUID, which is also the guest id in a group and the inventory.

/// Prefix of an XCP-ng VM's snapshot source.
pub const SOURCE_PREFIX: &str = "xcp-";

/// The snapshot source of a VM.
pub fn source_name(uuid: &str) -> String {
    format!("{SOURCE_PREFIX}{uuid}")
}

/// A VM UUID as XAPI prints them (lowercase, 8-4-4-4-12).
pub fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == '-'
            } else {
                c.is_ascii_digit() || ('a'..='f').contains(&c)
            }
        })
}

/// The UUID of an `xcp-<uuid>` source name.
pub fn parse_source_name(s: &str) -> Option<&str> {
    s.strip_prefix(SOURCE_PREFIX).filter(|u| valid_uuid(u))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let u = "4b885545-0f69-4a05-9f95-f1f0a75cf2cb";
        assert_eq!(parse_source_name(&source_name(u)), Some(u));
        for bad in [
            "",
            "4b885545-0f69-4a05-9f95-f1f0a75cf2c",
            "4B885545-0F69-4A05-9F95-F1F0A75CF2CB",
            "../../etc/passwd/x/x/x/x/x/x/x/x/x/x",
        ] {
            assert!(!valid_uuid(bad), "{bad}");
        }
        assert_eq!(parse_source_name("vmw-4b885545-0f69-4a05-9f95-f1f0a75cf2cb"), None);
    }
}
