//! File layout and `agent.conf` settings (shared by all agents).
//!
//! Linux: `/etc/nexus-agent` (0700 root): `agent.conf`, `token` (sha256 of the enrollment
//! token or fleet secret), `fleet` (fleet id), `fleet-secret` (dropped by a package
//! deployment, adopted at the next start), `agent.key` (private key, 0600), `enroll.crt` (self-signed, enrollment mode),
//! `agent.crt` + `ca.crt` + `agent.id` (after enrollment), `hooks.d/{pre,post}/`,
//! `release-keys/*.pub` (pinned cosign keys for self-update).
//! `/var/lib/nexus-agent` (0700): `enroll.failures`, `cache/`, `spool/`, `snapshots.journal`, `ui-state.json`.
//! `/run/nexus-agent` (0711): snapshot mount points, `ui.sock` (root:nexus-agent-ui 0660).
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
    /// fleet id while awaiting fleet enrollment (`init --fleet-secret`; `token` then
    /// holds the fleet secret's digest)
    pub fn fleet(&self) -> PathBuf {
        self.config.join("fleet")
    }
    /// fleet secret dropped by a package deployment (Ansible, MSI `FLEETSECRET`):
    /// adopted and deleted at the next start ([`crate::adopt_fleet_secret`])
    pub fn fleet_secret(&self) -> PathBuf {
        self.config.join("fleet-secret")
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
    /// session summaries, appliance status and queued requests for the endpoint UIs
    pub fn ui_state(&self) -> PathBuf {
        self.state.join("ui-state.json")
    }
    /// local IPC socket of the endpoint UIs (Linux)
    pub fn ui_socket(&self) -> PathBuf {
        self.run.join("ui.sock")
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
    /// Windows: VSS writer class ids (comma separated) that must not take part
    pub vss_exclude_writers: String,
    /// `self_update = on|off`; unset: on, except for package installs
    /// ([`crate::update::self_update_blocked`])
    pub self_update: Option<bool>,
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
            vss_exclude_writers: String::new(),
            self_update: None,
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
                "vss_exclude_writers" => s.vss_exclude_writers = v.to_string(),
                "self_update" => {
                    s.self_update = Some(match v {
                        "on" | "yes" | "true" => true,
                        "off" | "no" | "false" => false,
                        _ => return Err(format!("agent.conf line {}: self_update must be on or off", n + 1)),
                    })
                }
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

fn new_name(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".new");
    PathBuf::from(s)
}

/// Certificate renewal: replace `agent.key` + `agent.crt` so that a crash at any
/// point leaves a matching pair. Both are written as `*.new` first (the key, then
/// the certificate, whose presence marks a complete pair), then renamed key-first;
/// [`finish_identity_swap`] completes an interrupted swap at the next start.
pub fn swap_identity(paths: &Paths, key_pem: &str, cert_pem: &str) -> io::Result<()> {
    let (key, cert) = (paths.key(), paths.cert());
    let _ = fs::remove_file(new_name(&cert));
    write_atomic(&new_name(&key), key_pem.as_bytes(), 0o600)?;
    write_atomic(&new_name(&cert), cert_pem.as_bytes(), 0o644)?;
    finish_identity_swap(paths)
}

/// Rolls an interrupted [`swap_identity`] forward (`agent.crt.new` present) or
/// back (only `agent.key.new`: the certificate never arrived).
pub fn finish_identity_swap(paths: &Paths) -> io::Result<()> {
    let (key, cert) = (paths.key(), paths.cert());
    let (key_new, cert_new) = (new_name(&key), new_name(&cert));
    if cert_new.exists() {
        if key_new.exists() {
            fs::rename(&key_new, &key)?;
        }
        fs::rename(&cert_new, &cert)?;
    } else if key_new.exists() {
        fs::remove_file(&key_new)?;
    }
    if let Ok(d) = fs::File::open(&paths.config) {
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
        assert_eq!(s.self_update, None);
        assert_eq!(Settings::parse("self_update = on").unwrap().self_update, Some(true));
        assert_eq!(Settings::parse("self_update=off").unwrap().self_update, Some(false));
        assert!(Settings::parse("self_update = maybe").is_err());
    }

    #[test]
    fn identity_swap_rolls_forward_or_back() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: t.path().to_path_buf(),
            state: t.path().to_path_buf(),
            run: t.path().to_path_buf(),
        };
        let read = |p: PathBuf| fs::read_to_string(p).unwrap();
        fs::write(paths.key(), "k1").unwrap();
        fs::write(paths.cert(), "c1").unwrap();
        swap_identity(&paths, "k2", "c2").unwrap();
        assert_eq!((read(paths.key()), read(paths.cert())), ("k2".into(), "c2".into()));
        // crash after the key rename: the certificate follows at the next start
        fs::write(new_name(&paths.cert()), "c3").unwrap();
        fs::write(paths.key(), "k3").unwrap();
        finish_identity_swap(&paths).unwrap();
        assert_eq!((read(paths.key()), read(paths.cert())), ("k3".into(), "c3".into()));
        // crash before the certificate was written: the old pair stays
        fs::write(new_name(&paths.key()), "k4").unwrap();
        finish_identity_swap(&paths).unwrap();
        assert_eq!((read(paths.key()), read(paths.cert())), ("k3".into(), "c3".into()));
        assert!(!new_name(&paths.key()).exists());
        // both written, nothing renamed yet: forward
        fs::write(new_name(&paths.key()), "k5").unwrap();
        fs::write(new_name(&paths.cert()), "c5").unwrap();
        finish_identity_swap(&paths).unwrap();
        assert_eq!((read(paths.key()), read(paths.cert())), ("k5".into(), "c5".into()));
    }
}
