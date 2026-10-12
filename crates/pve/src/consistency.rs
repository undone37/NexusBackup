//! Consistency of a guest snapshot, read from the vzdump task log
//! (docs/pve-connector.md "Consistency").
//!
//! VMs: vzdump itself quiesces the guest through the QEMU guest agent around
//! `backup-access-setup` (qemu-server `PVE/VZDump/QemuServer.pm` `qga_fs_freeze` /
//! `qga_fs_thaw`, `PVE/QemuServer/Agent.pm` `guest_fs_freeze_applicable`). Task log
//! lines (`INFO:` / `WARN:` / `ERROR:` as written by `PVE::VZDump::Plugin::debugmsg`):
//! - `INFO: issuing guest-agent 'fs-freeze' command` and `… 'fs-thaw' command`;
//! - a failed freeze: `ERROR: unable to freeze guest fs - <reason>` (or
//!   `ERROR: querying status after freezing guest fs failed - …`);
//! - skipped: `INFO: skipping guest filesystem freeze - disabled in VM options` /
//!   `… - agent configured but not running?` / `… - already frozen`; PVE 8 wrote
//!   `skipping guest-agent 'fs-freeze', agent configured but not running?`;
//! - a stopped guest: `INFO: status = stopped` (`backup mode: stop`), no freeze.
//!
//! Containers (`PVE/VZDump/LXC.pm`): mode `snapshot` freezes the container's
//! cgroup, syncs its file systems and takes a storage snapshot
//! (`INFO: create storage snapshot 'vzdump'`): point in time, but applications are
//! not asked to flush (crash consistent). Mode `suspend` (fallback when a volume
//! cannot be snapshotted) rsyncs live, then again while frozen: crash consistent too.
//!
//! Levels: `application` (quiesced: guest-agent freeze and thaw, or the guest
//! was stopped: data at rest), `crash` (point in time without quiesce),
//! `unknown` (no status line in the log, e.g. the log could not be read).

/// Consistency levels, weakest last (snapshots of file sources also use `inconsistent`).
pub const LEVELS: &[&str] = &["application", "crash", "inconsistent", "unknown"];

/// (level, reason) of a VM snapshot from its vzdump task log.
pub fn vm_level(log: &[String]) -> (&'static str, String) {
    let body = |l: &str| l.split_once(": ").map_or(l, |(_, b)| b).trim().to_owned();
    let has = |needle: &str| log.iter().any(|l| l.contains(needle));
    if has("status = stopped") {
        return ("application", "guest was stopped (data at rest)".into());
    }
    if !has("status = running") && !has("status = paused") {
        return ("unknown", "no guest status in the vzdump log".into());
    }
    if let Some(l) = log
        .iter()
        .find(|l| l.contains("unable to freeze guest fs") || l.contains("freezing guest fs failed"))
    {
        return ("crash", format!("guest-agent fs-freeze failed: {}", body(l)));
    }
    if let Some(l) = log.iter().find(|l| {
        l.contains("skipping guest filesystem freeze") || l.contains("skipping guest-agent 'fs-freeze'")
    }) {
        return ("crash", body(l));
    }
    if has("issuing guest-agent 'fs-freeze' command") && has("issuing guest-agent 'fs-thaw' command") {
        return ("application", "guest-agent fs-freeze/fs-thaw".into());
    }
    ("crash", "no guest-agent file system freeze (agent not enabled)".into())
}

/// (level, reason) of a container snapshot from its vzdump task log.
pub fn ct_level(log: &[String]) -> (&'static str, String) {
    let has = |needle: &str| log.iter().any(|l| l.contains(needle));
    if has("status = stopped") {
        ("application", "container was stopped (data at rest)".into())
    } else if has("create storage snapshot") {
        ("crash", "frozen container, storage snapshot (no application quiesce)".into())
    } else if has("backup mode: suspend") {
        ("crash", "suspend mode: final sync while frozen (no application quiesce)".into())
    } else {
        ("unknown", "no snapshot or status line in the vzdump log".into())
    }
}

/// The line the scheduler reads (`crates/scheduler/src/consistency.rs`).
pub fn line(source: &str, time: u64, (level, why): (&str, String)) -> String {
    format!("consistency {source}/{time}: {level} ({why})")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|s| s.to_string()).collect()
    }

    // excerpts of PVE 9 vzdump task logs (the messages of qemu-server / pve-container)
    const HEAD: &[&str] = &[
        "INFO: starting new backup job: vzdump 100 --storage nexus --mode snapshot --fleecing enabled=1,storage=local-lvm",
        "INFO: Starting Backup of VM 100 (qemu)",
        "INFO: Backup started at 2026-10-12 22:00:01",
        "INFO: status = running",
        "INFO: VM Name: web1",
        "INFO: include disk 'scsi0' 'local-lvm:vm-100-disk-0' 32G",
        "INFO: backup mode: snapshot",
    ];

    fn vm(extra: &[&str]) -> (&'static str, String) {
        let mut l = log(HEAD);
        l.extend(log(extra));
        vm_level(&l)
    }

    #[test]
    fn freeze_and_thaw_is_application() {
        let r = vm(&[
            "INFO: issuing guest-agent 'fs-freeze' command",
            "INFO: setting up snapshot-access for backup",
            "INFO: issuing guest-agent 'fs-thaw' command",
            "INFO: started backup task 'b3c2…'",
        ]);
        assert_eq!(r.0, "application");
    }

    #[test]
    fn failed_or_skipped_freeze_is_crash() {
        let r = vm(&[
            "INFO: issuing guest-agent 'fs-freeze' command",
            "ERROR: unable to freeze guest fs - guest-fsfreeze-freeze failed: VSS writer failed",
            "INFO: issuing guest-agent 'fs-thaw' command",
        ]);
        assert_eq!(r.0, "crash");
        assert!(r.1.contains("VSS writer failed"), "{}", r.1);
        let r = vm(&["INFO: skipping guest filesystem freeze - agent configured but not running?"]);
        assert_eq!(r, ("crash", "skipping guest filesystem freeze - agent configured but not running?".into()));
        assert_eq!(
            vm(&["INFO: skipping guest filesystem freeze - disabled in VM options"]).0,
            "crash"
        );
        // PVE 8 wording
        assert_eq!(
            vm(&["INFO: skipping guest-agent 'fs-freeze', agent configured but not running?"]).0,
            "crash"
        );
        assert_eq!(
            vm(&["ERROR: querying status after freezing guest fs failed - timeout after 60 minutes"]).0,
            "crash"
        );
        // freeze without thaw (task killed in between)
        assert_eq!(vm(&["INFO: issuing guest-agent 'fs-freeze' command"]).0, "crash");
    }

    #[test]
    fn no_agent_is_crash_stopped_is_application() {
        assert_eq!(vm(&["INFO: started backup task 'x'"]).0, "crash");
        let stopped = log(&["INFO: Starting Backup of VM 101 (qemu)", "INFO: status = stopped", "INFO: backup mode: stop"]);
        assert_eq!(vm_level(&stopped).0, "application");
        assert_eq!(vm_level(&[]).0, "unknown");
    }

    #[test]
    fn containers() {
        let snap = log(&[
            "INFO: Starting Backup of VM 200 (lxc)",
            "INFO: status = running",
            "INFO: backup mode: snapshot",
            "INFO: create storage snapshot 'vzdump'",
        ]);
        assert_eq!(ct_level(&snap).0, "crash");
        let susp = log(&[
            "INFO: status = running",
            "INFO: mode failure - some volumes do not support snapshots",
            "INFO: trying 'suspend' mode instead",
            "INFO: backup mode: suspend",
        ]);
        assert_eq!(ct_level(&susp).0, "crash");
        assert_eq!(ct_level(&log(&["INFO: status = stopped"])).0, "application");
        assert_eq!(ct_level(&[]).0, "unknown");
    }

    #[test]
    fn line_format() {
        assert_eq!(
            line("vm-100", 17, ("crash", "x".into())),
            "consistency vm-100/17: crash (x)"
        );
    }
}
