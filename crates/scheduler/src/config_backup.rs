//! Appliance configuration backup (docs/control-plane.md "Configuration backup").
//!
//! - `config_backup` (appliance job, daily on [`Config::config_backup`] and "Run now"
//!   in Settings): writes `request.json` into the helper's control dir
//!   ([`Config::config_backup_dir`]); `nexus-config-backup.path` starts the root
//!   helper, which seals the bundle to keyd's public key and answers in
//!   `status.json` + `latest.bundle`. The scheduler never sees the key files.
//! - on success one `config_upload {target, appliance, created}` per tenant with an
//!   offsite target: `nexus-offsite config-put` uploads `latest.bundle` to
//!   `config/<appliance-id>/<created>.bundle` and keeps 14 daily + 12 monthly.
//! - alerts (warning): `config_backup` (bundle not made), `config_backup:<tenant>`
//!   (upload to that tenant's target failed); each resolves after the next success.
//!
//! - after `nexus-setup restore-config` (same KEK as the lost appliance) the setting
//!   [`REKEY_PENDING`] lists the tenants with an offsite target: no local DEK is created
//!   for them and no other job runs until `config_rekey {target}` (`nexus-offsite rekey`)
//!   has installed their DEKs from the offsite escrow (wrapped under the restored KEK, no
//!   recovery key needed) and indexed the copy. Failure: warning `config_restore:<tenant>`,
//!   retried hourly.
//!
//! The appliance id (setting [`APPLIANCE_ID`]) is created on the first run and is
//! part of the catalog, so a restored appliance keeps writing to the same folder.
//!
//! [`Config::config_backup`]: crate::Config::config_backup
//! [`Config::config_backup_dir`]: crate::Config::config_backup_dir

use crate::run::{InProc, Plan, Step};
use crate::{Job, Scheduler};
use anyhow::{Context, Result};
use catalog::rusqlite::params;
use catalog::schedule::Schedule;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const APPLIANCE_ID: &str = "appliance_id";
pub const ALERT: &str = "config_backup";
pub const LATEST: &str = "latest.bundle";
/// written by nexus-setup restore-config: tenants whose DEKs come from their offsite escrow
pub const REKEY_PENDING: &str = "config_restore_keys";
const REKEY_RETRY_SECS: i64 = 3600;

pub(crate) fn upload_alert_key(tenant: &str) -> String {
    format!("{ALERT}:{tenant}")
}

/// Writes the helper request (tmp + rename; group nexus-catalog through the setgid dir).
fn request(dir: &Path, id: i64, appliance: &str) -> std::io::Result<()> {
    let tmp = dir.join(".request.json.tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o660)
        .open(&tmp)?;
    std::io::Write::write_all(&mut f, json!({"id": id, "appliance": appliance}).to_string().as_bytes())?;
    // the scheduler runs with UMask=0077; root reads it through the group anyway
    f.set_permissions(fs::Permissions::from_mode(0o660))?;
    fs::rename(&tmp, dir.join("request.json"))
}

/// Waits for the helper's `status.json` of job `id`.
fn wait(dir: &Path, id: i64, timeout: Duration) -> Result<Value, String> {
    let start = Instant::now();
    loop {
        if let Some(s) = fs::read(dir.join("status.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .filter(|s| s["id"].as_i64() == Some(id))
        {
            return match s["state"].as_str() {
                Some("done") => Ok(s),
                _ => Err(format!(
                    "nexus-config-backup: {}",
                    s["error"].as_str().unwrap_or("failed (see its journal)")
                )),
            };
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "nexus-config-backup did not answer within {} s (is nexus-config-backup.path enabled?)",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

impl Scheduler {
    /// Tenants still waiting for their DEKs after a configuration restore.
    pub(crate) fn rekey_pending(&self) -> Result<Vec<String>> {
        Ok(catalog::setting(&self.db.conn(), REKEY_PENDING)?
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default())
    }

    fn rekey_done(&self, tenant: &str, job: Option<i64>) -> Result<()> {
        let left: Vec<String> = self.rekey_pending()?.into_iter().filter(|t| t != tenant).collect();
        catalog::set_setting(&self.db.conn(), REKEY_PENDING, &json!(left).to_string())?;
        self.db.audit(
            crate::ACTOR,
            "tenant.keys_restored",
            &format!("tenant/{tenant}"),
            &json!({"job": job, "after": "config_restore"}),
        )?;
        self.resolve(&format!("config_restore:{tenant}"))
    }

    /// One `config_rekey` per pending tenant (retried hourly after a failure); a
    /// tenant whose keys keyd already has (console `nexus-offsite dr`) is done.
    pub(crate) fn queue_rekeys(&mut self, now: i64) -> Result<()> {
        for t in self.rekey_pending()? {
            if keyd::fetch_keyring(&self.cfg.keyd_socket, &t).is_ok_and(|k| !k.versions().is_empty()) {
                self.rekey_done(&t, None)?;
                continue;
            }
            let blocked: i64 = self.db.conn().query_row(
                "SELECT COUNT(*) FROM jobs WHERE kind = 'config_rekey' AND json_extract(params, '$.target') = ?1
                 AND (state IN ('queued', 'running') OR (state = 'failed' AND finished > ?2))",
                params![t, now - REKEY_RETRY_SECS],
                |r| r.get(0),
            )?;
            if blocked == 0 {
                self.insert_job("config_rekey", "-", &json!({"target": t}))?;
            }
        }
        Ok(())
    }

    /// The appliance id (16 hex digits), created on first use.
    pub(crate) fn appliance_id(&self) -> Result<String> {
        let c = self.db.conn();
        if let Some(id) = catalog::setting(&c, APPLIANCE_ID)? {
            return Ok(id);
        }
        let id: String = rand::random::<[u8; 8]>().iter().map(|b| format!("{b:02x}")).collect();
        catalog::set_setting(&c, APPLIANCE_ID, &id)?;
        Ok(id)
    }

    /// Queues the daily `config_backup` (only where the helper is installed).
    pub(crate) fn queue_config_backup(&mut self, now: i64) -> Result<()> {
        if !self.cfg.config_backup_dir.is_dir() {
            return Ok(());
        }
        let sched = Schedule::parse(&self.cfg.config_backup)?;
        let busy: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM jobs WHERE kind = 'config_backup' AND state IN ('queued', 'running')",
            [],
            |r| r.get(0),
        )?;
        let last = self.last_run(
            "config_backup",
            "SELECT MAX(created) FROM jobs WHERE kind = 'config_backup' AND requested_by = 'scheduler'",
            &[],
            now,
        )?;
        if busy == 0 && sched.due(last, now) {
            self.insert_job("config_backup", "-", &json!({}))?;
        }
        Ok(())
    }

    pub(crate) fn plan_config(&self, job: &Job) -> Result<Option<Plan>> {
        let dir: PathBuf = self.cfg.config_backup_dir.clone();
        let (key, steps, files) = match job.kind.as_str() {
            "config_backup" => {
                let (id, appliance) = (job.id, self.appliance_id()?);
                let timeout = Duration::from_secs(self.cfg.config_backup_timeout_secs);
                let step = Box::new(move || {
                    request(&dir, id, &appliance).map_err(|e| format!("writing the request: {e}"))?;
                    let s = wait(&dir, id, timeout)?;
                    Ok(
                        json!({"appliance": s["appliance"], "created": s["created"], "bytes": s["bytes"],
                              "sha256": s["sha256"], "files": s["files"]})
                        .to_string(),
                    )
                });
                (
                    "appliance:config_backup".to_owned(),
                    vec![Step::Func(InProc(step))],
                    vec![],
                )
            }
            "config_rekey" => {
                let target = job.params["target"].as_str().context("target missing")?;
                let o = self
                    .offsite_cfg(target)?
                    .with_context(|| format!("tenant {target} has no offsite target"))?;
                let jd = self.job_dir(job.id);
                let files = self.offsite_files(target, &o, &jd)?;
                let step = Step::Cli {
                    bin: self.cfg.offsite_bin.clone(),
                    args: vec![jd.join("offsite.json").to_string_lossy().into_owned(), "rekey".into()],
                    alert: None,
                    capture: false,
                };
                (format!("config_rekey:{target}"), vec![step], files)
            }
            "config_upload" => {
                let p = &job.params;
                let target = p["target"].as_str().context("target missing")?;
                let appliance = p["appliance"].as_str().context("appliance missing")?;
                let created = p["created"].as_i64().context("created missing")?;
                let o = self
                    .offsite_cfg(target)?
                    .with_context(|| format!("tenant {target} has no offsite target"))?;
                let jd = self.job_dir(job.id);
                let files = self.offsite_files(target, &o, &jd)?;
                let step = Step::Cli {
                    bin: self.cfg.offsite_bin.clone(),
                    args: vec![
                        jd.join("offsite.json").to_string_lossy().into_owned(),
                        "config-put".into(),
                        dir.join(LATEST).to_string_lossy().into_owned(),
                        appliance.into(),
                        created.to_string(),
                    ],
                    alert: None,
                    capture: false,
                };
                (format!("config_upload:{target}"), vec![step], files)
            }
            _ => return Ok(None),
        };
        Ok(Some(Plan {
            key,
            tenant: job.tenant.clone(),
            store: PathBuf::new(),
            dir: self.job_dir(job.id),
            files,
            steps,
            download: None,
            held: Default::default(),
        }))
    }

    /// After `config_backup` / `config_upload`: alerts, and the uploads after a new bundle.
    pub(crate) fn config_finished(&mut self, job: &Job, ok: bool, log: &str, result: Option<&Value>) -> Result<()> {
        let why = log
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("see the job log");
        if job.kind == "config_rekey" {
            let t = job.params["target"].as_str().unwrap_or_default();
            if ok {
                return self.rekey_done(t, Some(job.id));
            }
            return self.raise(
                "warning",
                ALERT,
                &format!("config_restore:{t}"),
                &format!(
                    "the keys of tenant {t} could not be restored from its offsite copy after the configuration restore \
                     (job {}, retried hourly): {why}",
                    job.id
                ),
                Some(t),
            );
        }
        if job.kind == "config_upload" {
            let t = job.params["target"].as_str().unwrap_or_default();
            if ok {
                return self.resolve(&upload_alert_key(t));
            }
            return self.raise(
                "warning",
                ALERT,
                &upload_alert_key(t),
                &format!(
                    "the configuration backup could not be uploaded to the offsite target of tenant {t} (job {}): {why}",
                    job.id
                ),
                None,
            );
        }
        if !ok {
            return self.raise(
                "warning",
                ALERT,
                ALERT,
                &format!("the appliance configuration backup failed (job {}): {why}", job.id),
                None,
            );
        }
        self.resolve(ALERT)?;
        let (appliance, created) = (
            result.and_then(|r| r["appliance"].as_str()).unwrap_or_default(),
            result.and_then(|r| r["created"].as_i64()).unwrap_or_default(),
        );
        for (t, _) in self.tenants()? {
            // a deactivated tenant's target gets nothing (its offsite runs are paused too)
            let off = catalog::tenants::disabled(&self.db.conn(), &t)?;
            if !off && self.offsite_cfg(&t).ok().flatten().is_some() {
                self.insert_job(
                    "config_upload",
                    "-",
                    &json!({"target": t, "appliance": appliance, "created": created, "backup_job": job.id}),
                )?;
            }
        }
        Ok(())
    }
}
