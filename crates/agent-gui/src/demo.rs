//! Demo data: manual screenshots (tests/screenshots.rs) and the fake agent service
//! (`cargo run -p agent-gui --example fake-service`) used to try the GUI without an agent.

use crate::ipc::Snapshot;
use agent_ui_proto::*;

/// A laptop with a month of nightly backups, two with warnings, one failed.
pub fn snapshot(now: u64) -> Snapshot {
    let day = 86_400;
    let today = now - now % day;
    let sessions = (0..34u64)
        .map(|i| {
            let started = today - i * day - 2 * 3600;
            let (result, warnings, first_error) = match i {
                3 => (
                    SessionResult::Failed,
                    0,
                    Some("appliance: connection to the agent lost (laptop asleep)".into()),
                ),
                7 | 19 => (
                    SessionResult::Warning,
                    2,
                    Some("C:\\Users\\anna\\AppData\\Local\\Temp\\~lock.tmp: file in use, skipped".into()),
                ),
                12 => (SessionResult::Cancelled, 0, None),
                _ => (SessionResult::Success, 0, None),
            };
            let transferred = if result == SessionResult::Failed {
                0
            } else {
                (180 + (i * 37) % 900) * 1024 * 1024 + if i == 0 { 2 * 1024 * 1024 * 1024 } else { 0 }
            };
            let secs = 240 + (i * 53) % 900 + if i == 0 { 1500 } else { 0 };
            Session {
                id: 1000 - i,
                kind: SessionKind::Backup,
                started,
                ended: started + secs,
                result,
                read_bytes: transferred * 3,
                transferred_bytes: transferred,
                new_bytes: transferred / 2,
                warnings,
                first_error,
                snapshot_time: (result != SessionResult::Failed).then_some(started + 20),
            }
        })
        .collect();
    Snapshot {
        status: Status {
            agent_id: "anna-laptop".into(),
            appliance: Some("5f3a9c21".into()),
            managed_by: Some("nexus01.example.org".into()),
            enrolled: true,
            version: "0.1.0".into(),
            state: AgentState::Idle,
            running: None,
            last_success: Some(today - 2 * 3600 + 1800),
            next_run: Some(today + day - 2 * 3600),
            last_seen_by_appliance: Some(now - 70),
            reachable: true,
            ui_policy: UiPolicy::default(),
        },
        sessions,
        // Phase 38h: a standalone job next to the appliance's backups (a USB disk at home)
        jobs: vec![agent_ui_proto::Job {
            name: "usb-disk".into(),
            paths: vec!["C:\\Users\\anna".into()],
            repo: "E:\\nexus".into(),
            schedule: "daily 20:00".into(),
            next: Some(today + 18 * 3600),
            last_run: Some(today - 4 * 3600),
            last_ok: Some(today - 4 * 3600),
            last_summary: "snapshot: 18 204 files, 41.2 GiB, 312 new chunks".into(),
            last_error: None,
            waiting: None,
            queued: false,
        }],
    }
}

pub fn detail(s: &Session) -> SessionDetail {
    SessionDetail {
        session: s.clone(),
        log_tail: vec![
            "snapshot: VSS shadow copy created for C:".into(),
            "scan: 412 318 files, 1 204 changed since the last backup (USN journal)".into(),
            "C:\\Users\\anna\\AppData\\Local\\Temp\\~lock.tmp: file in use, skipped".into(),
            "upload: 3 812 chunks, 2 655 already on the appliance".into(),
            "backup finished with 2 warnings".into(),
        ],
    }
}
