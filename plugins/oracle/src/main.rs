//! Oracle Database plugin (#42, docs/database-logs-design.md, plugins/oracle/README.md).
//!
//! The appliance logs in to the database host over SSH as the Oracle software owner and runs RMAN there (`rman
//! target /`, OS authentication): backup pieces go to a staging directory on the host, are streamed into the
//! snapshot and deleted. Level 0, level 1 (block change tracking when enabled) and archived log runs; every
//! snapshot holds the newest level 0, the level 1s and all archived logs since it, a control file and the spfile,
//! so it is restorable on its own. Point-in-time restore: the pieces back into staging, then RESTORE / RECOVER
//! UNTIL and OPEN RESETLOGS on the source host.

mod rman;
use plugin_ssh as ssh;

use anyhow::Result;
use plugin_sdk::{error, BackupResult, Ctx, Guest, Plugin, Sink, Source, Validation};

struct Oracle;

fn invalid(field: &str, message: impl Into<String>) -> Validation {
    Validation::Invalid {
        field: field.into(),
        message: message.into(),
    }
}

impl Plugin for Oracle {
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
        let cfg = match rman::Config::of(&ctx.config) {
            Ok(c) => c,
            Err(e) => return Ok(invalid("sid", format!("{e:#}"))),
        };
        let ssh = match cfg.ssh() {
            Ok(s) => s,
            Err(e) => return Ok(invalid("host", format!("{e:#}"))),
        };
        let db = match rman::database(&ssh, &cfg) {
            Ok(d) => d,
            Err(e) => return Ok(invalid("sid", format!("{e:#}"))),
        };
        if db.log_mode != "ARCHIVELOG" {
            return Ok(invalid(
                "sid",
                format!(
                    "{} runs in {}: backups of an open database and point-in-time restores need ARCHIVELOG mode",
                    cfg.sid, db.log_mode
                ),
            ));
        }
        if let Err(e) = ssh.run(&format!("mkdir -p {s} && test -w {s}", s = ssh::sh_quote(&cfg.staging))) {
            return Ok(invalid("staging", format!("staging directory not writable: {e:#}")));
        }
        Ok(Validation::Valid)
    }

    fn list_guests(&mut self, _ctx: &Ctx) -> Result<Vec<Guest>> {
        // ponytail: the whole database (CDB with its PDBs) only; per-PDB groups when someone needs them
        Ok(Vec::new())
    }

    fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
        let cfg = rman::Config::of(&ctx.config)?;
        let ssh = cfg.ssh()?;
        let r = rman::backup(ctx, sink, &ssh, &cfg)?;
        sink.snapshot_meta(&r.meta)?;
        Ok(BackupResult {
            state: Some(serde_json::to_vec(&r.state)?),
            consistent: true,
            summary: r.summary,
        })
    }

    fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String> {
        match ctx.params["restore"].as_str() {
            Some("pitr") => {
                let cfg = rman::Config::of(&ctx.config)?;
                rman::pitr(ctx, src, &cfg.ssh()?, &cfg)
            }
            r => Err(error(95, format!("unknown restore {r:?}"))),
        }
    }
}

fn main() {
    plugin_sdk::run(Oracle)
}
