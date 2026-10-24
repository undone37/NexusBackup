//! Appliance updates that greenboot rolled back (#29): nexus-update notices at its next tick that the appliance
//! did not boot the image it applied and records `last_result.result = "rolled back from <digest>"` in its
//! `status.json` (and never applies that digest again by itself). Without an alert an admin would learn this only
//! on the Updates page, and an automatic update in the night window would fail unnoticed. The alert
//! `update_rolled_back` is raised once per digest and stays until it is resolved by hand.

use crate::Scheduler;
use anyhow::Result;
use serde_json::Value;
use std::fs;

/// The digests already reported (a JSON list, newest last), so a resolved alert does not come back.
const SEEN_SETTING: &str = "os_update.rolled_back_seen";
const PREFIX: &str = "rolled back from ";

impl Scheduler {
    pub(crate) fn check_os_update(&self) -> Result<()> {
        // no status: no update helper here (dev control plane, tests)
        let Some(st) = fs::read(self.cfg.update_dir.join("status.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            return Ok(());
        };
        let Some(digest) = st["last_result"]["result"]
            .as_str()
            .and_then(|r| r.strip_prefix(PREFIX))
            .map(str::trim)
            .filter(|d| !d.is_empty())
        else {
            return Ok(());
        };
        let c = self.db.conn();
        let mut seen: Vec<String> = catalog::setting(&c, SEEN_SETTING)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if seen.iter().any(|d| d == digest) {
            return Ok(());
        }
        let booted = st["booted"]["version"].as_str().unwrap_or("the previous version");
        drop(c);
        self.raise(
            "warning",
            "update_rolled_back",
            &format!("update_rolled_back:{digest}"),
            &format!(
                "The appliance update to {digest} did not pass the health checks after its reboot and was rolled back \
                 (greenboot): the appliance runs {booted} again. That image is not applied again automatically; see \
                 Settings > Updates and the diagnostics bundle (nexus-update, greenboot) before trying again."
            ),
            None,
        )?;
        seen.push(digest.to_owned());
        let keep = seen.len().saturating_sub(20);
        catalog::set_setting(&self.db.conn(), SEEN_SETTING, &serde_json::to_string(&seen[keep..])?)?;
        Ok(())
    }
}
