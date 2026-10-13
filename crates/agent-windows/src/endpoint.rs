//! Endpoint UI support that builds on every platform (unit-tested on Linux): the
//! named pipe's security descriptor and the mapping of Windows power / network cost
//! values to `agent_proto::PowerState`. The Win32 calls are in `win::pipe` / `win::power`.

/// `\\.\pipe\nexus-agent-ui`: protected DACL, SYSTEM and Administrators full control,
/// interactive users (IU) read + write data only — `0x12008b` = FILE_GENERIC_READ |
/// FILE_WRITE_DATA, deliberately without FILE_APPEND_DATA (= FILE_CREATE_PIPE_INSTANCE:
/// a user could otherwise create a rogue server instance of the pipe). Network logons
/// are not IU, and the pipe rejects remote clients anyway.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;IU)";

const FILE_CREATE_PIPE_INSTANCE: u32 = 0x4;

/// (trustee, access mask) of the allow ACEs of an SDDL DACL with hex masks or `GA`.
pub fn allow_aces(sddl: &str) -> Vec<(String, u32)> {
    sddl.split('(')
        .skip(1)
        .filter_map(|ace| {
            let f: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
            if f.len() != 6 || f[0] != "A" {
                return None;
            }
            let mask = match f[2] {
                "GA" => 0x1000_0000,
                m => u32::from_str_radix(m.trim_start_matches("0x"), 16).ok()?,
            };
            Some((f[5].to_string(), mask))
        })
        .collect()
}

/// No one but SYSTEM / Administrators may create pipe instances or change the DACL
/// (generic all/write, WRITE_DAC, WRITE_OWNER).
pub fn pipe_sddl_ok(sddl: &str) -> bool {
    const FORBIDDEN: u32 = FILE_CREATE_PIPE_INSTANCE | 0x1000_0000 | 0x4000_0000 | 0x0004_0000 | 0x0008_0000;
    sddl.starts_with("D:P")
        && allow_aces(sddl)
            .iter()
            .all(|(who, mask)| matches!(who.as_str(), "SY" | "BA") || mask & FORBIDDEN == 0)
}

/// `SYSTEM_POWER_STATUS` → (on battery, percent). ACLineStatus 0 = offline, 1 =
/// online, 255 = unknown; BatteryFlag 128 = no system battery, 255 = unknown;
/// BatteryLifePercent 255 = unknown.
pub fn power_from(ac_line: u8, battery_flag: u8, percent: u8) -> (Option<bool>, Option<u8>) {
    if battery_flag == 128 {
        return (Some(false), None);
    }
    let pct = (percent <= 100 && battery_flag != 255).then_some(percent);
    let on_battery = match ac_line {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    };
    (on_battery, pct)
}

/// Network List Manager cost (`NLM_CONNECTION_COST_*`) → metered: fixed or variable
/// plans, over the data limit or roaming = metered; unrestricted = not; 0 = unknown.
pub fn metered_from_cost(cost: u32) -> Option<bool> {
    const UNRESTRICTED: u32 = 0x1;
    const METERED: u32 = 0x2 | 0x4 | 0x1_0000 | 0x4_0000;
    if cost & METERED != 0 {
        Some(true)
    } else if cost & UNRESTRICTED != 0 {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_acl_users_cannot_create_instances() {
        assert!(pipe_sddl_ok(PIPE_SDDL));
        let aces = allow_aces(PIPE_SDDL);
        assert_eq!(aces.len(), 3);
        assert_eq!(aces[2], ("IU".to_string(), 0x12008b));
        // FILE_GENERIC_WRITE for users would include FILE_CREATE_PIPE_INSTANCE
        assert!(!pipe_sddl_ok("D:P(A;;GA;;;SY)(A;;0x120116;;;IU)"));
        assert!(!pipe_sddl_ok("D:P(A;;GA;;;SY)(A;;GA;;;WD)"));
        assert!(!pipe_sddl_ok("D:(A;;GA;;;SY)"), "DACL must be protected");
    }

    #[test]
    fn power_and_cost_mapping() {
        assert_eq!(power_from(0, 1, 80), (Some(true), Some(80)));
        assert_eq!(power_from(1, 8, 100), (Some(false), Some(100)));
        assert_eq!(power_from(1, 128, 255), (Some(false), None), "desktop");
        assert_eq!(power_from(255, 255, 255), (None, None));
        assert_eq!(metered_from_cost(0x1), Some(false));
        assert_eq!(metered_from_cost(0x2), Some(true));
        assert_eq!(metered_from_cost(0x1 | 0x4_0000), Some(true), "roaming");
        assert_eq!(metered_from_cost(0), None);
    }
}
