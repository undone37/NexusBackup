//! Alert lifecycle pieces shared by the scheduler (raises, resolves and
//! delivers alerts) and the web-api (Alerts page, Settings → Alert delivery):
//! the "what to do" hint per alert kind, the notification rules (setting
//! `alert_rules`) and webhook body templates (docs/phase13-18-plan.md §13f).

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Notification rules (JSON array of [`Rule`]); absent = derived from the
/// pre-13f setting `alerts` ([`legacy_rules`]).
pub const RULES_SETTING: &str = "alert_rules";
/// `{"info": days, "warning": days, "critical": days}`: resolved alerts older than this are pruned.
pub const RETENTION_SETTING: &str = "alert_retention_days";
/// Hours after which an open, unacknowledged alert is delivered again (0 = never).
pub const REMINDER_SETTING: &str = "alert_reminder_hours";
pub const DEFAULT_REMINDER_HOURS: i64 = 24;
pub const SEVERITIES: &[&str] = &["info", "warning", "critical"];

pub fn rank(severity: &str) -> u8 {
    match severity {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    }
}

/// "What to do" per alert kind (English; the web UI has its own i18n texts).
const HINTS: &[(&str, &str)] = &[
    ("job_failed", "Open the job log on the Jobs page, fix the cause (source reachable, credentials, space) and run the job again. The alert resolves itself after the next successful run."),
    ("verify", "Stored data failed verification. Do not delete snapshots; check the store disks (SMART) and the offsite target, then run Verify again. Resolves after a successful verify."),
    ("snapshot_damaged", "Snapshots reference chunks that failed verification. Do not delete them; run Repair on the Snapshots page (fetches the chunks from the offsite target or the replication primary). The next backup of each affected source reads its data in full. Resolves when no snapshot is damaged any more."),
    ("inventory", "Snapshots disappeared or differ from the catalog. Check the store and the offsite target for manual deletion or tampering and review the audit log. Resolves after a clean offsite check."),
    ("capacity", "The store is filling up. Shorten retention, run GC or add disks. Resolves when usage drops below the threshold."),
    ("offsite_lag", "Offsite copies are behind. Check the offsite target (reachable, credentials, quota) and the offsite job logs. Resolves when the copy has caught up."),
    ("gc_quorum", "A garbage collection would delete an unusually large amount of data. Find out why (retention change, deleted group), then approve or reject the request on the Approvals page."),
    ("gc_confirm", "A garbage collection would delete an unusually large amount of data and approvals are disabled. Find out why, then confirm or leave it on the Approvals page."),
    ("config", "A schedule or setting is invalid. Correct it on the named group or replication source."),
    ("backup_inconsistent", "The backup is not point-in-time consistent. Enable snapshots on the source (NAS, LVM, ZFS, btrfs or plugin quiescing) or back it up while it is idle."),
    ("consistency", "A snapshot is less consistent than the policy requires. Enable the QEMU guest agent (VMs), hooks or VSS (agents), or snapshots on the source; resolves with the next snapshot that meets the policy."),
    ("replication_lag", "Replication from the primary is behind. Check the network path to the primary and the replica_sync job logs. Resolves after the next successful sync."),
    ("replication_verify", "Replicated data failed verification and was not imported. Check the primary's store and run the sync again."),
    ("vault_closed", "A replication source was closed with Close vault (pause pulling now): no syncs, the primary is not reachable from here. Nothing to do while that is intended; reopening needs approval (Replication page). Resolves when the source is reopened."),
    ("replication_keys", "The tenant keys on this secondary do not match the primary. Re-export the keys on the primary (needs approval)."),
    ("break_glass", "An administrator account was reset, or approvals were switched off, at the console. Confirm with the person who did it, then acknowledge to clear the banner."),
    ("cert_expiry", "A certificate, secret or API token expires soon. Renew it as the message says (web certificate: Settings → Certificate; agents and replication secondaries: enroll again; IdP secret: Settings → Single sign-on; tokens: create a new one). Resolves once renewed."),
    ("forwarding", "Audit and alert forwarding to the named syslog or HTTPS sink has failed for 15 minutes. Check the receiver (reachable, certificate, credentials) and Settings → Forwarding; nothing is lost, the backlog is sent when it works again. Resolves after the next delivered batch."),
    ("account_dormant", "An account was disabled because nobody logged in with it for the configured number of days (Settings → Security). If it is still needed, an admin re-enables it on the Users page; otherwise delete or leave it disabled."),
    ("mgmt_allow_reset", "The management allow-list was cleared at the console (nexus-setup reset-mgmt-allow). Confirm with the person who did it, then set a correct list in Settings → Security."),
    ("firewall_reset", "Every inbound firewall restriction was cleared at the console (nexus-setup reset-firewall): the web UI and the other services accept connections from any address again. Confirm with the person who did it, then set correct source lists in Settings → Firewall."),
    ("report", "A scheduled report could not be mailed. Check the SMTP server under Settings → Alert delivery (reachable, credentials) and the report's recipients on the Reports page, then use Send now. Resolves after the next successful send."),
    ("legal_hold_advisory", "The primary holds this replicated snapshot under a legal hold. Holds are not applied here automatically: a security officer applies it with Apply hold (Alerts or Snapshots page). Resolves once applied or when the primary releases its hold."),
    ("clock_skew", "System time and the compliance clock (retention locks) differ. A lag after a restart is normal: the compliance clock catches up slowly and locks last longer meanwhile. A jump while running or a clock that is ahead means system time was changed by hand or a time source is wrong: check Diagnostics (time.sync, time.nts) and the audit log. Resolves when the difference is below a minute."),
    ("fleecing_space", "The fleecing storage of a Proxmox node (usually local-lvm) is nearly full. A full LVM-thin pool pauses every VM on it, so guests are skipped below the guard and a running backup is cancelled below the critical level. Free space in that storage (or use a larger one as the source's fleecing storage) and adjust the guard on the source if needed. Resolves when a backup finds enough space again."),
    ("disk", "A disk or RAID array needs attention (SMART failing, bad sectors, temperature, NVMe wear, degraded or rebuilding array). Open Configuration → Hardware; replace a failed disk as the troubleshooting chapter describes. Resolves when the disk or array is healthy again."),
    ("tenant_disabled", "The tenant is deactivated (Tenants page): no backups, offsite copies or replication run for it and its accounts cannot sign in; its other alerts are suppressed. Retention keeps running. Reactivate it on the Tenants page when it is needed again."),
    ("vault_disabled", "Vault mode was switched off at the console with the recovery key after an approved request. Confirm with the people who requested and approved it (audit: vault.disable)."),
    ("config_backup", "The appliance configuration backup (catalog, key files) could not be made or uploaded to an offsite target. Open Configuration → Settings → Backup of this appliance and the job log; check that nexus-keyd runs and the offsite target is reachable, then Run now. Resolves after the next successful run (per target)."),
    ("restore_test", "A restore test of a guest's snapshot failed: the isolated test copy did not start, its guest agent did not answer, a port was not listening or the custom check failed (details on the Restore tests page). Check the guest (agent installed and enabled, services start without network) and the snapshot; run the test again. Resolves after the next passed test of that guest."),
    ("recovery_plan", "A recovery plan is not ready (a snapshot older than its RPO, the target node offline, too little space on the target storage, a missing bridge, a blocking alert) or its test run or execution failed. Open the Recovery plans page for the failed checks. Resolves after the next passed readiness check or test run."),
    ("incident", "A security officer put the appliance into incident mode: snapshots in the chosen range are held, backup groups are paused, every other session and all API tokens were ended. Investigate; leaving incident mode needs a second approver (Settings → Incident mode). Resolves when incident mode ends."),
    ("dek_rotation", "The tenant's data encryption key is older than the configured rotation interval (Settings → Security). Rotate it at the appliance console (root shell): runuser -u nexus-keyd -- /usr/libexec/nexus/keyd tenant-rotate /var/lib/nexus/keyd <tenant>. New snapshots use the new key, older ones stay readable; on a replication primary export the keys again afterwards. Resolves once rotated."),
    ("vmid_reused", "A VM's identity (vmgenid / SMBIOS UUID) changed between two backups: its VMID now belongs to another VM (deleted and re-created, or replaced by a restore). The newest snapshot starts a new chain (read in full); older snapshots of that VMID belong to the previous VM and age out with retention. Check that the right VM is protected; put a legal hold on the old snapshots if they must be kept. Resolve the alert once checked."),
    ("restore_priority", "Restore priority is on (Dashboard): scheduled backups, GC, verify, file indexing, offsite uploads and replication syncs wait so restores get the disks and network. It ends on its own after at most 24 hours, or turn it off on the Dashboard when the recovery is done. Resolves when it is off."),
    ("malware", "The YARA scan found matches of the administrators' rules in a snapshot (rule and path: Snapshots page, scan results). The snapshot is flagged as anomalous, so restores and holds default to an earlier clean snapshot, and restores with Scan first are refused or run with the network disconnected. Check the files and the source; if a rule was too broad, a security officer clears the flag on the Snapshots page. Resolve the alert by hand."),
    ("agent_update_failed", "An agent update failed (signature, version, package install or the agent did not come back with the new version). Open the job log of the agent_update job and the agent's update state on Agents > Updates; fix the cause and update again. Resolves after the next successful update of that agent."),
    ("rollout_paused", "An agent rollout was paused: a canary failed or the failure threshold was reached. Check the failed agents on Agents > Updates, then resume or cancel the rollout. Resolves when the rollout is resumed, cancelled or done."),
    ("scan_hit", "The scheduled YARA scan of a protection group found matches of the administrators' rules in the newest snapshot of a source (rule and path: Snapshots page, scan results; the recovery calendar shows the snapshot red). The snapshot is flagged as anomalous, so restores and holds default to the latest scanned-clean snapshot. Check the files and the source; if a rule was too broad, a security officer clears the flag on the Snapshots page. Resolve the alert by hand."),
    ("hash_hunt_hit", "An IOC hash hunt found files whose SHA-256 is on an uploaded hash list (results: Hash hunt page). The snapshots that contain them are flagged as anomalous. Check the source machine for the files; restore a clean version from an earlier snapshot with the results page's restore action; if the list entry was wrong, a security officer clears the flags on the Snapshots page. Resolve the alert by hand."),
    ("tenant_lockdown", "A security officer or administrator locked one tenant down: its snapshots are held, its groups paused, its users' sessions and API tokens ended and its accounts cannot sign in; deletes, overwriting restores and configuration changes for it are refused. Other tenants keep running. Investigate; lifting the lockdown needs a second approver (Tenants page). Resolves when the lockdown is lifted."),
    ("login_new_device", "An account signed in from a browser family and client network it never used before (the message names both). If that was the account owner (new laptop, travel, a changed network), acknowledge and resolve the alert. If not, disable the account on the Users page, end its sessions and review the audit log for what it did."),
    ("change_tracking", "A scheduled full read of a source found data that changed since the previous snapshot although its change tracking (Proxmox VE dirty bitmap, agent metadata cache or USN journal, NAS metadata cache, ZFS diff) had not reported it (examples in the message and on the Dashboard, Change tracking). Snapshots taken with change tracking since the last verified full read may miss these changes. The newest snapshot is complete (it was read in full). Find the cause (storage or hypervisor bug, restored or cloned disks, tools that preserve timestamps, ransomware that does), keep the full-read interval short until it is understood, and resolve the alert by hand."),
    ("user_risk", "An account did something unusual for it (the message names the rule: sign-in at an hour it never used, a burst of requests that weaken protection, many deletes in a short time, far more downloads than usual). Until the mark ends or a security officer clears it, the account must re-enter its password and second factor before its next change in each session, and its API tokens cannot change anything. Ask the account owner; if it was not them, disable the account, end its sessions and review the audit log."),
    ("test", "A test alert from Settings → Alert delivery; nothing to do."),
];

/// Stable category of every alert kind (SIEM routing, Alerts page filter);
/// `audit` is the category of forwarded audit records. Unknown kinds: `system`.
pub const CATEGORIES: &[&str] = &["security", "backup", "replication", "hardware", "system", "audit"];

const CATEGORY: &[(&str, &str)] = &[
    ("anomaly", "security"),
    ("malware", "security"),
    ("console_unlock", "security"),
    ("console_root_shell", "security"),
    ("break_glass", "security"),
    ("mgmt_allow_reset", "security"),
    ("firewall_reset", "security"),
    ("legal_hold_advisory", "security"),
    ("cert_expiry", "security"),
    ("account_dormant", "security"),
    ("inventory", "security"),
    ("clock_skew", "security"),
    ("gc_quorum", "security"),
    ("gc_confirm", "security"),
    ("vault_disabled", "security"),
    ("incident", "security"),
    ("scan_hit", "security"),
    ("hash_hunt_hit", "security"),
    ("tenant_lockdown", "security"),
    ("login_new_device", "security"),
    ("user_risk", "security"),
    ("dek_rotation", "security"),
    ("job_failed", "backup"),
    ("sla_missed", "backup"),
    ("paused", "backup"),
    ("consistency", "backup"),
    ("backup_inconsistent", "backup"),
    ("orphaned", "backup"),
    ("verify", "backup"),
    ("snapshot_damaged", "backup"),
    ("offsite_lag", "backup"),
    ("inventory_refresh", "backup"),
    ("config", "backup"),
    ("vmid_reused", "backup"),
    ("restore_priority", "backup"),
    ("change_tracking", "backup"),
    ("disk", "hardware"),
    ("fleecing_space", "hardware"),
];

pub fn category(kind: &str) -> &'static str {
    if kind.starts_with("replication_") {
        return "replication";
    }
    CATEGORY.iter().find(|(k, _)| *k == kind).map_or("system", |(_, c)| c)
}

/// [`category`] as an SQL expression over the column `kind` (filters).
pub fn category_sql() -> String {
    let mut s = String::from("CASE WHEN substr(kind, 1, 12) = 'replication_' THEN 'replication'");
    for (k, c) in CATEGORY {
        s.push_str(&format!(" WHEN kind = '{k}' THEN '{c}'"));
    }
    s.push_str(" ELSE 'system' END");
    s
}

pub fn hint(kind: &str) -> &'static str {
    HINTS
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or("See the alerts chapter of the user manual.", |(_, h)| h)
}

/// A notification rule: alerts of at least `min_severity` whose kind is in
/// `kinds` and tenant in `tenants` (empty = any) go to its channels.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default = "warning")]
    pub min_severity: String,
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub tenants: Vec<String>,
    #[serde(default)]
    pub channels: Channels,
}

fn warning() -> String {
    "warning".into()
}

/// Delivery channels of a rule (the SMTP server is global, setting `alerts`).
/// Phase 14 adds `syslog` and `https` members here.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Channels {
    #[serde(default)]
    pub email: Vec<String>,
    #[serde(default)]
    pub webhook: Option<Webhook>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub url: String,
    /// in the catalog: values sealed to the scheduler at [`header_location`]
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// JSON body with `{{field}}` placeholders ([`render`]); None = the default payload
    #[serde(default)]
    pub template: Option<String>,
}

impl Rule {
    /// Alerts without a tenant (appliance-wide) only match rules for any tenant.
    pub fn matches(&self, severity: &str, kind: &str, tenant: Option<&str>) -> bool {
        rank(severity) >= rank(&self.min_severity)
            && (self.kinds.is_empty() || self.kinds.iter().any(|k| k == kind))
            && (self.tenants.is_empty() || tenant.is_some_and(|t| self.tenants.iter().any(|x| x == t)))
    }
}

/// Where a webhook header value is sealed: bound to the rule, header and URL,
/// so a value never follows the rule to another endpoint.
pub fn header_location(rule: &str, header: &str, url: &str) -> String {
    format!("settings/alert_rules/{rule}/{header}@{url}")
}

/// The pre-13f single configuration (`{webhook_url, smtp: {to, …}, min_severity}`)
/// as one rule `default` (none if it delivers nowhere).
pub fn legacy_rules(alerts: &Value) -> Vec<Rule> {
    let email: Vec<String> = alerts["smtp"]["to"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    let webhook = alerts["webhook_url"].as_str().map(|u| Webhook {
        url: u.to_owned(),
        headers: BTreeMap::new(),
        template: None,
    });
    if email.is_empty() && webhook.is_none() {
        return Vec::new();
    }
    vec![Rule {
        name: "default".into(),
        min_severity: alerts["min_severity"].as_str().unwrap_or("warning").to_owned(),
        kinds: Vec::new(),
        tenants: Vec::new(),
        channels: Channels { email, webhook },
    }]
}

/// The rules as stored (header values sealed), or the legacy configuration's.
pub fn load_rules(c: &Connection) -> anyhow::Result<Vec<Rule>> {
    if let Some(raw) = crate::setting(c, RULES_SETTING)? {
        return Ok(serde_json::from_str(&raw)?);
    }
    let alerts = crate::setting(c, "alerts")?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or(Value::Null);
    Ok(legacy_rules(&alerts))
}

/// Retention per severity in days (defaults: info 14, warning and critical 180).
pub fn retention_days(c: &Connection) -> rusqlite::Result<BTreeMap<String, i64>> {
    let v: Value = crate::setting(c, RETENTION_SETTING)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or(Value::Null);
    Ok(SEVERITIES
        .iter()
        .map(|s| {
            let def = if *s == "info" { 14 } else { 180 };
            (s.to_string(), v[*s].as_i64().filter(|d| *d > 0).unwrap_or(def))
        })
        .collect())
}

pub fn reminder_hours(c: &Connection) -> rusqlite::Result<i64> {
    Ok(crate::setting(c, REMINDER_SETTING)?
        .and_then(|v| v.trim().parse().ok())
        .filter(|h: &i64| *h >= 0)
        .unwrap_or(DEFAULT_REMINDER_HOURS))
}

/// Placeholders a webhook template may use.
pub const TEMPLATE_FIELDS: &[&str] = &[
    "id",
    "ts",
    "first_ts",
    "last_ts",
    "count",
    "severity",
    "kind",
    "category",
    "message",
    "hint",
    "tenant",
    "host",
    "alert_url",
];

/// Replaces each `{{field}}` with the field's value, JSON-string escaped
/// (without quotes, so placeholders sit inside string literals; numbers render
/// as digits, a missing tenant as empty). Unknown fields are an error.
pub fn render(template: &str, fields: &Value) -> Result<String, String> {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let j = after.find("}}").ok_or("unclosed {{")?;
        let name = after[..j].trim();
        if !TEMPLATE_FIELDS.contains(&name) {
            return Err(format!("unknown placeholder {{{{{name}}}}}"));
        }
        match &fields[name] {
            Value::String(s) => {
                let q = serde_json::to_string(s).unwrap_or_default();
                out.push_str(&q[1..q.len() - 1]);
            }
            Value::Null => {}
            v => out.push_str(&v.to_string()),
        }
        rest = &after[j + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// A template must render to valid JSON (checked with values that need escaping).
pub fn check_template(template: &str) -> Result<(), String> {
    if template.len() > 8192 {
        return Err("at most 8192 bytes".into());
    }
    let sample = json!({"id": 42, "ts": 1760000000, "first_ts": 1760000000, "last_ts": 1760003600, "count": 3,
        "severity": "critical", "kind": "job_failed", "category": "backup", "message": "backup \"nightly\" failed:\n\tC:\\data \u{1}",
        "hint": hint("job_failed"), "tenant": null, "host": "nexus", "alert_url": "https://nexus/#/alerts?id=42"});
    let body = render(template, &sample)?;
    serde_json::from_str::<Value>(&body).map_err(|e| format!("does not render to valid JSON: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_matching() {
        let r = Rule {
            name: "acme".into(),
            min_severity: "warning".into(),
            kinds: vec!["job_failed".into(), "capacity".into()],
            tenants: vec!["acme".into()],
            channels: Channels::default(),
        };
        assert!(r.matches("critical", "job_failed", Some("acme")));
        assert!(!r.matches("info", "job_failed", Some("acme")), "below min severity");
        assert!(!r.matches("critical", "verify", Some("acme")), "other kind");
        assert!(!r.matches("critical", "job_failed", Some("globex")), "other tenant");
        assert!(!r.matches("critical", "job_failed", None), "appliance-wide");
        let any: Rule = serde_json::from_value(json!({"name": "all", "min_severity": "info"})).unwrap();
        assert!(any.matches("info", "x", None) && any.matches("critical", "y", Some("t")));
        assert!(serde_json::from_value::<Rule>(json!({"name": "x", "bogus": 1})).is_err());
    }

    #[test]
    fn legacy_configuration_becomes_one_rule() {
        let r = legacy_rules(&json!({"webhook_url": "https://h/x", "min_severity": "critical",
                                     "smtp": {"host": "m", "to": ["a@b.c"]}}));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].min_severity, "critical");
        assert_eq!(r[0].channels.email, vec!["a@b.c".to_owned()]);
        assert_eq!(r[0].channels.webhook.as_ref().unwrap().url, "https://h/x");
        assert!(legacy_rules(&json!({"webhook_url": null, "smtp": null})).is_empty());
        assert!(legacy_rules(&Value::Null).is_empty());
    }

    #[test]
    fn templates_escape_and_validate() {
        let f = json!({"id": 7, "message": "a \"b\"\n\\c", "tenant": null, "count": 2});
        let out = render(
            r##"{"text": "#{{id}} {{ message }} ({{tenant}})", "n": {{count}}}"##,
            &f,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["text"], "#7 a \"b\"\n\\c ()");
        assert_eq!(v["n"], 2);
        assert!(render("{{nope}}", &f).unwrap_err().contains("unknown placeholder"));
        assert!(render("{{id", &f).is_err());
        assert!(check_template(r#"{"text": "{{severity}}: {{message}}", "url": "{{alert_url}}"}"#).is_ok());
        assert!(check_template(r#"{"text": {{message}}}"#).is_err(), "unquoted string");
        assert!(check_template(r#"{"text": "x""#).is_err());
        assert!(check_template(&"x".repeat(9000)).is_err());
    }

    #[test]
    fn categories() {
        for (kind, cat) in [
            ("anomaly", "security"),
            ("malware", "security"),
            ("console_root_shell", "security"),
            ("legal_hold_advisory", "security"),
            ("firewall_reset", "security"),
            ("cert_expiry", "security"),
            ("job_failed", "backup"),
            ("sla_missed", "backup"),
            ("consistency", "backup"),
            ("orphaned", "backup"),
            ("replication_lag", "replication"),
            ("replication_keys", "replication"),
            ("disk", "hardware"),
            ("fleecing_space", "hardware"),
            ("capacity", "system"),
            ("quota", "system"),
            ("forwarding", "system"),
            ("report", "system"),
            ("vault_disabled", "security"),
            ("tenant_disabled", "system"),
            ("scan_hit", "security"),
            ("hash_hunt_hit", "security"),
            ("tenant_lockdown", "security"),
            ("login_new_device", "security"),
            ("user_risk", "security"),
            ("change_tracking", "backup"),
            ("something_new", "system"),
        ] {
            assert_eq!(category(kind), cat, "{kind}");
            assert!(CATEGORIES.contains(&cat));
        }
        // the SQL expression agrees
        let c = Connection::open_in_memory().unwrap();
        for kind in [
            "anomaly",
            "replication_verify",
            "replicationx",
            "disk",
            "capacity",
            "x'y",
        ] {
            let sql: String = c
                .query_row(
                    &format!("SELECT {} FROM (SELECT ?1 AS kind)", category_sql()),
                    [kind],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(sql, category(kind), "{kind}");
        }
    }

    #[test]
    fn hints_for_known_kinds() {
        assert!(hint("capacity").contains("retention"));
        assert!(hint("whatever").contains("manual"));
    }
}
