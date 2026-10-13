//! Battery and network state for the appliance's laptop policies (`PollReply`):
//! batteries from `/sys/class/power_supply`, metered network and connection name from
//! NetworkManager over D-Bus (`busctl`, if available; otherwise unknown).

use agent_proto::PowerState;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

const POWER_SUPPLY: &str = "/sys/class/power_supply";

pub fn state() -> PowerState {
    let (on_battery, battery_percent) = battery(Path::new(POWER_SUPPLY));
    let (metered, network_name) = network();
    PowerState {
        on_battery,
        battery_percent,
        metered,
        network_name,
    }
}

/// (on battery, charge %) from the power supply class. No battery (desktops,
/// servers) = (Some(false), None); no power supply information at all = unknown.
pub fn battery(dir: &Path) -> (Option<bool>, Option<u8>) {
    let Ok(rd) = fs::read_dir(dir) else { return (None, None) };
    let read = |p: &Path, f: &str| fs::read_to_string(p.join(f)).map(|s| s.trim().to_string()).ok();
    let (mut mains_online, mut any) = (None::<bool>, false);
    let (mut pct, mut discharging) = (None::<u8>, false);
    for e in rd.flatten() {
        let p = e.path();
        any = true;
        match read(&p, "type").as_deref() {
            Some("Mains") | Some("USB") => {
                let on = read(&p, "online").as_deref() == Some("1");
                mains_online = Some(mains_online.unwrap_or(false) || on);
            }
            // device batteries (mice, keyboards) have scope "Device"
            Some("Battery") if read(&p, "scope").as_deref() != Some("Device") => {
                if let Some(c) = read(&p, "capacity").and_then(|c| c.parse::<u8>().ok()) {
                    pct = Some(pct.map_or(c, |x| x.min(c)).min(100));
                }
                discharging |= read(&p, "status").as_deref() == Some("Discharging");
            }
            _ => {}
        }
    }
    if !any {
        return (None, None);
    }
    let on_battery = match (pct, mains_online) {
        (None, _) => false,
        (Some(_), Some(online)) => !online,
        (Some(_), None) => discharging,
    };
    (Some(on_battery), pct)
}

fn busctl(args: &[&str]) -> Option<String> {
    let mut c = Command::new("busctl")
        .args(["--system", "--timeout=2"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // busctl honours --timeout; this guards against a hung bus connection
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match c.try_wait().ok()? {
            Some(st) if st.success() => break,
            Some(_) => return None,
            None if std::time::Instant::now() > end => {
                let _ = c.kill();
                let _ = c.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(&mut c.stdout.take()?, &mut out).ok()?;
    Some(out)
}

const NM: &str = "org.freedesktop.NetworkManager";

fn network() -> (Option<bool>, Option<String>) {
    let metered =
        busctl(&["get-property", NM, "/org/freedesktop/NetworkManager", NM, "Metered"]).and_then(|o| parse_metered(&o));
    let name = busctl(&[
        "get-property",
        NM,
        "/org/freedesktop/NetworkManager",
        NM,
        "PrimaryConnection",
    ])
    .and_then(|o| parse_object_path(&o))
    .and_then(|p| busctl(&["get-property", NM, &p, &format!("{NM}.Connection.Active"), "Id"]))
    .and_then(|o| parse_string(&o));
    (metered, name)
}

/// `u 4` → NMMetered: 1 yes, 3 guess-yes = metered; 2 no, 4 guess-no = not; 0 unknown.
pub fn parse_metered(out: &str) -> Option<bool> {
    match out.trim().strip_prefix("u ")?.trim() {
        "1" | "3" => Some(true),
        "2" | "4" => Some(false),
        _ => None,
    }
}

/// `o "/org/freedesktop/NetworkManager/ActiveConnection/3"` (`"/"` = none)
pub fn parse_object_path(out: &str) -> Option<String> {
    let p = out.trim().strip_prefix("o ")?.trim().trim_matches('"');
    (p.starts_with("/org/freedesktop/NetworkManager/") && !p.contains(char::is_whitespace)).then(|| p.to_string())
}

/// `s "Office WiFi"` → `Office WiFi` (truncated to 64 characters)
pub fn parse_string(out: &str) -> Option<String> {
    let s = out.trim().strip_prefix("s ")?.trim();
    let s = s.strip_prefix('"')?.strip_suffix('"')?;
    Some(s.chars().filter(|c| !c.is_control()).take(64).collect()).filter(|s: &String| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supply(root: &Path, name: &str, files: &[(&str, &str)]) {
        let d = root.join(name);
        fs::create_dir_all(&d).unwrap();
        for (f, v) in files {
            fs::write(d.join(f), format!("{v}\n")).unwrap();
        }
    }

    #[test]
    fn battery_states() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(battery(&t.path().join("missing")), (None, None));
        supply(t.path(), "AC", &[("type", "Mains"), ("online", "0")]);
        supply(
            t.path(),
            "BAT0",
            &[("type", "Battery"), ("capacity", "37"), ("status", "Discharging")],
        );
        supply(
            t.path(),
            "hidpp_battery_0",
            &[("type", "Battery"), ("scope", "Device"), ("capacity", "5")],
        );
        assert_eq!(battery(t.path()), (Some(true), Some(37)));
        fs::write(t.path().join("AC/online"), "1\n").unwrap();
        assert_eq!(battery(t.path()), (Some(false), Some(37)));
        // a desktop: mains only
        let t = tempfile::tempdir().unwrap();
        supply(t.path(), "AC", &[("type", "Mains"), ("online", "1")]);
        assert_eq!(battery(t.path()), (Some(false), None));
        // battery without a mains entry: the battery status decides
        let t = tempfile::tempdir().unwrap();
        supply(
            t.path(),
            "BAT1",
            &[("type", "Battery"), ("capacity", "80"), ("status", "Charging")],
        );
        assert_eq!(battery(t.path()), (Some(false), Some(80)));
    }

    #[test]
    fn busctl_output() {
        assert_eq!(parse_metered("u 1\n"), Some(true));
        assert_eq!(parse_metered("u 3"), Some(true));
        assert_eq!(parse_metered("u 4"), Some(false));
        assert_eq!(parse_metered("u 0"), None);
        assert_eq!(parse_metered("garbage"), None);
        assert_eq!(
            parse_object_path("o \"/org/freedesktop/NetworkManager/ActiveConnection/3\"\n").as_deref(),
            Some("/org/freedesktop/NetworkManager/ActiveConnection/3")
        );
        assert_eq!(parse_object_path("o \"/\""), None);
        assert_eq!(parse_string("s \"Office WiFi\"\n").as_deref(), Some("Office WiFi"));
        assert_eq!(parse_string("s \"\""), None);
    }
}
