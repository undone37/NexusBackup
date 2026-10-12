//! Disks excluded from VM backups (group `exclude_disks`, docs/pve-connector.md
//! "Excluded disks"). The provider API has no per-disk selection: PVE exports
//! every disk without `backup=0`, the appliance simply does not read the
//! excluded ones and records them in the snapshot's config index
//! ([`FILE`]), so a restore can recreate them empty ([`Mode::Placeholder`]) or
//! leave them out of the restored config ([`Mode::Omit`]).

use crate::ir::is_disk_key;
use serde::{Deserialize, Serialize};

/// Name of the record in the snapshot's `config` index.
pub const FILE: &str = "excluded-disks.json";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// restore creates the disk empty, with its original size and config line
    #[default]
    Placeholder,
    /// restore leaves the disk out of the VM config
    Omit,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Disk {
    /// provider device / snapshot index name, e.g. `drive-scsi1`
    pub device: String,
    /// config key, e.g. `scsi1`
    pub key: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Excluded {
    pub mode: Mode,
    pub disks: Vec<Disk>,
}

/// Config key of a provider device name (`drive-scsi1` → `scsi1`).
pub fn disk_key(device: &str) -> &str {
    device.strip_prefix("drive-").unwrap_or(device)
}

/// The disk keys a guest config marks `backup=0` (PVE skips them itself);
/// snapshot sections are ignored.
pub fn backup_off(config: &str) -> Vec<String> {
    config
        .lines()
        .take_while(|l| !l.starts_with('['))
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let k = k.trim();
            (is_disk_key(k) && v.split(',').any(|o| o.trim() == "backup=0")).then(|| k.to_owned())
        })
        .collect()
}

/// `config` without the lines of disks `keys` and their `#qmdump#map:` lines
/// (the restored VM does not get these disks at all). Snapshot sections are kept.
pub fn omit_config(config: &str, keys: &[String]) -> String {
    let mut in_snapshot = false;
    config
        .split_inclusive('\n')
        .filter(|l| {
            in_snapshot |= l.starts_with('[');
            if in_snapshot {
                return true;
            }
            let key = match l.strip_prefix("#qmdump#map:") {
                Some(m) => m.split(':').next(),
                None => l.split_once(':').map(|(k, _)| k.trim()),
            };
            !key.is_some_and(|k| keys.iter().any(|x| x == k))
        })
        .collect()
}

impl Excluded {
    pub fn keys(&self) -> Vec<String> {
        self.disks.iter().map(|d| d.key.clone()).collect()
    }

    /// Size of a placeholder device (mode placeholder only).
    pub fn placeholder(&self, device: &str) -> Option<u64> {
        (self.mode == Mode::Placeholder)
            .then(|| self.disks.iter().find(|d| d.device == device).map(|d| d.size))
            .flatten()
    }

    /// The catalog view of an archive: (config for PVE, extra `device_sizes`
    /// entries). Placeholder devices are listed with their size only, never in
    /// `devices` (the node plugin derives incremental bitmaps from `devices`).
    pub fn catalog(&self, config: &str) -> (String, Vec<(String, u64)>) {
        match self.mode {
            Mode::Placeholder => (
                config.to_owned(),
                self.disks.iter().map(|d| (d.device.clone(), d.size)).collect(),
            ),
            Mode::Omit => (omit_config(config, &self.keys()), Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "boot: order=scsi0
scsi0: local-lvm:vm-100-disk-0,size=4G
scsi1: local-lvm:vm-100-disk-1,size=8G
scsi2: local-lvm:vm-100-disk-2,backup=0,size=8G
virtio0: local-lvm:vm-100-disk-3,backup=1,size=1G
net0: virtio=BC:24:11:C0:4F:D0,bridge=vmbr1
#qmdump#map:scsi0:drive-scsi0:local-lvm:raw:
#qmdump#map:scsi1:drive-scsi1:local-lvm:raw:
#qmdump#map:virtio0:drive-virtio0:local-lvm:raw:

[snap1]
scsi1: local-lvm:vm-100-disk-1,size=8G
scsi3: local-lvm:vm-100-disk-5,backup=0,size=8G
";

    fn ex(mode: Mode) -> Excluded {
        Excluded {
            mode,
            disks: vec![Disk {
                device: "drive-scsi1".into(),
                key: "scsi1".into(),
                size: 8 << 30,
            }],
        }
    }

    #[test]
    fn backup_off_disks() {
        assert_eq!(backup_off(CONF), vec!["scsi2"]);
        assert_eq!(disk_key("drive-efidisk0"), "efidisk0");
        assert_eq!(disk_key("scsi1"), "scsi1");
    }

    #[test]
    fn omit_drops_disk_and_map_lines_only() {
        let c = omit_config(CONF, &["scsi1".into()]);
        assert!(!c.contains("vm-100-disk-1,size=8G\nscsi2"));
        assert!(!c.contains("#qmdump#map:scsi1:"));
        assert!(c.contains("scsi0: local-lvm:vm-100-disk-0"));
        assert!(c.contains("#qmdump#map:scsi0:drive-scsi0"));
        assert!(
            c.contains("[snap1]\nscsi1: local-lvm:vm-100-disk-1"),
            "snapshot sections kept"
        );
        assert_eq!(c.lines().count(), CONF.lines().count() - 2);
        assert_eq!(omit_config(CONF, &[]), CONF);
    }

    #[test]
    fn catalog_view_per_mode() {
        let (c, extra) = ex(Mode::Placeholder).catalog(CONF);
        assert_eq!(c, CONF, "placeholder keeps the config (PVE creates the disk)");
        assert_eq!(extra, vec![("drive-scsi1".to_string(), 8 << 30)]);
        assert_eq!(ex(Mode::Placeholder).placeholder("drive-scsi1"), Some(8 << 30));
        assert_eq!(ex(Mode::Placeholder).placeholder("drive-scsi0"), None);
        let (c, extra) = ex(Mode::Omit).catalog(CONF);
        assert!(extra.is_empty());
        assert!(!c.contains("#qmdump#map:scsi1:"));
        assert_eq!(ex(Mode::Omit).placeholder("drive-scsi1"), None);
        let json = serde_json::to_string(&ex(Mode::Omit)).unwrap();
        assert!(json.contains(r#""mode":"omit""#), "{json}");
        assert_eq!(serde_json::from_str::<Excluded>(&json).unwrap(), ex(Mode::Omit));
    }
}
