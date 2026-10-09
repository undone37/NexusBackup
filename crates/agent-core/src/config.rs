//! File layout and `agent.conf` settings (shared by all agents).
//!
//! Linux: `/etc/nexus-agent` (0700 root): `agent.conf`, `token` (sha256 of the enrollment
//! token), `agent.key` (private key, 0600), `enroll.crt` (self-signed, enrollment mode),
//! `agent.crt` + `ca.crt` + `agent.id` (after enrollment), `hooks.d/{pre,post}/`,
//! `release-keys/*.pub` (pinned cosign keys for self-update).
//! `/var/lib/nexus-agent` (0700): `enroll.failures`, `cache/`, `spool/`, `snapshots.journal`.
//!
//! Windows: the same names below `%ProgramData%\NexusAgent\config` and `...\state`; the
//! directory `%ProgramData%\NexusAgent` carries a protected ACL (SYSTEM + Administrators
//! only) that every file inherits, so the Unix `mode` arguments are ignored there.

use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = "/etc/nexus-agent";
pub const DEFAULT_STATE: &str = "/var/lib/nexus-agent";
pub const DEFAULT_RUN: &str = "/run/nexus-agent";

#[derive(Clone, Debug)]
pub struct Paths {
    pub config: PathBuf,
    pub state: PathBuf,
    /// mount points for LVM snapshots (inside the agent's private mount namespace)
    pub run: PathBuf,
}

impl Default for Paths {
    #[cfg(not(windows))]
    fn default() -> Self {
        Paths {
            config: DEFAULT_CONFIG.into(),
            state: DEFAULT_STATE.into(),
            run: DEFAULT_RUN.into(),
        }
    }

    #[cfg(windows)]
    fn default() -> Self {
        let base = PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()))
            .join("NexusAgent");
        Paths {
            config: base.join("config"),
            state: base.join("state"),
            run: base.join("run"),
        }
    }
}

impl Paths {
    pub fn conf(&self) -> PathBuf {
        self.config.join("agent.conf")
    }
    pub fn token(&self) -> PathBuf {
        self.config.join("token")
    }
    pub fn key(&self) -> PathBuf {
        self.config.join("agent.key")
    }
    pub fn enroll_cert(&self) -> PathBuf {
        self.config.join("enroll.crt")
    }
    pub fn cert(&self) -> PathBuf {
        self.config.join("agent.crt")
    }
    pub fn ca(&self) -> PathBuf {
        self.config.join("ca.crt")
    }
    pub fn agent_id(&self) -> PathBuf {
        self.config.join("agent.id")
    }
    pub fn hooks(&self) -> PathBuf {
        self.config.join("hooks.d")
    }
    pub fn release_keys(&self) -> PathBuf {
        self.config.join("release-keys")
    }
    pub fn failures(&self) -> PathBuf {
        self.state.join("enroll.failures")
    }
    pub fn cache_dir(&self) -> PathBuf {
        self.state.join("cache")
    }
    pub fn spool_dir(&self) -> PathBuf {
        self.state.join("spool")
    }
    pub fn journal(&self) -> PathBuf {
        self.state.join("snapshots.journal")
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub listen: String,
    pub port: u16,
    /// size of thick LVM snapshots in percent of the origin LV
    pub lvm_snapshot_percent: u32,
    pub hook_timeout_secs: u64,
    /// fallback mode: chunk data read during the scan is kept here (bounded) so `Want`
    /// returns exactly what was hashed even if the live file changes afterwards
    pub spool_max_bytes: u64,
    /// optional pin: accept only this appliance id in the client certificate CN
    pub appliance_id: Option<String>,
    pub max_connections: usize,
    /// uid that must own hook files and directories (0 in production)
    pub hook_owner: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            listen: "::".into(),
            port: agent_proto::DEFAULT_PORT,
            lvm_snapshot_percent: 10,
            hook_timeout_secs: 3600,
            spool_max_bytes: 2 << 30,
            appliance_id: None,
            max_connections: 4,
            hook_owner: 0,
        }
    }
}

impl Settings {
    /// `key = value` lines, `#` comments. Unknown keys are an error (typos must not
    /// silently weaken anything).
    pub fn parse(text: &str) -> Result<Settings, String> {
        let mut s = Settings::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("agent.conf line {}: expected key = value", n + 1))?;
            let (k, v) = (k.trim(), v.trim());
            let num = |v: &str| {
                v.parse::<u64>()
                    .map_err(|_| format!("agent.conf line {}: {k} must be a number", n + 1))
            };
            match k {
                "listen" => s.listen = v.to_string(),
                "port" => s.port = num(v)?.try_into().map_err(|_| format!("port {v} out of range"))?,
                "lvm_snapshot_percent" => s.lvm_snapshot_percent = num(v)?.clamp(1, 100) as u32,
                "hook_timeout_secs" => s.hook_timeout_secs = num(v)?.max(1),
                "spool_max_bytes" => s.spool_max_bytes = num(v)?,
                "appliance_id" => s.appliance_id = Some(v.to_string()).filter(|v| !v.is_empty()),
                "max_connections" => s.max_connections = num(v)?.clamp(1, 64) as usize,
                _ => return Err(format!("agent.conf line {}: unknown key {k}", n + 1)),
            }
        }
        Ok(s)
    }

    pub fn load(paths: &Paths) -> Result<Settings, String> {
        match fs::read_to_string(paths.conf()) {
            Ok(t) => Settings::parse(&t),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(format!("{}: {e}", paths.conf().display())),
        }
    }
}

/// Write a file atomically (temp file + fsync + rename) with the given mode (Unix; on
/// Windows the file inherits the protected ACL of its directory).
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(mode).custom_flags(libc::O_NOFOLLOW);
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = o.open(&tmp)?;
    f.write_all(data)?;
    #[cfg(unix)]
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Create a directory (and parents) and force its mode (Unix only, see above).
pub fn ensure_dir(path: &Path, mode: u32) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    return fs::set_permissions(path, fs::Permissions::from_mode(mode));
    #[cfg(not(unix))]
    {
        let _ = mode;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_settings_and_rejects_unknown_keys() {
        let s = Settings::parse("# c\nport = 7555\nlvm_snapshot_percent=20\nappliance_id = abc\n").unwrap();
        assert_eq!(s.port, 7555);
        assert_eq!(s.lvm_snapshot_percent, 20);
        assert_eq!(s.appliance_id.as_deref(), Some("abc"));
        assert!(Settings::parse("prot = 1").is_err());
        assert!(Settings::parse("port = 70000").is_err());
    }
}
