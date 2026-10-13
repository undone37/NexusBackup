//! Per-user settings: `%APPDATA%\NexusBackup\agent-gui.json` (Windows),
//! `$XDG_CONFIG_HOME/nexus-agent-gui/settings.json` (Linux, default `~/.config`).

use crate::model::Metric;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// desktop notification when a backup fails or ends with warnings (off by default)
    pub notify: bool,
    /// bar chart height
    pub metric: Metric,
}

pub fn default_path() -> Option<PathBuf> {
    let env = |k| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        env("APPDATA").map(|d| d.join("NexusBackup").join("agent-gui.json"))
    } else {
        env("XDG_CONFIG_HOME")
            .or_else(|| env("HOME").map(|h| h.join(".config")))
            .map(|d| d.join("nexus-agent-gui").join("settings.json"))
    }
}

/// Missing or unreadable file = defaults.
pub fn load(path: &Path) -> Settings {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, s: &Settings) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let dir = std::env::temp_dir().join(format!("nexus-agent-gui-settings-{}", std::process::id()));
        let path = dir.join("sub").join("settings.json");
        assert_eq!(load(&path), Settings::default());
        assert!(!Settings::default().notify, "notifications are opt-in");
        let s = Settings {
            notify: true,
            metric: Metric::Duration,
        };
        save(&path, &s).unwrap();
        assert_eq!(load(&path), s);
        std::fs::write(&path, b"{\"notify\":true}").unwrap();
        assert_eq!(load(&path).metric, Metric::Transferred, "missing fields default");
        std::fs::write(&path, b"garbage").unwrap();
        assert_eq!(load(&path), Settings::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
