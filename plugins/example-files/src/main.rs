//! Example plugin (docs/plugin-sdk.md): backs up the local directory named in its
//! source config and restores it into a target directory. Small on purpose — it
//! shows the whole SDK surface: validate, backup with incremental `Unchanged`
//! decisions (via `Sink::walk_dir`), a state blob, restore and the error path.
//!
//! Config: `{"path": "/abs/dir", "excludes": ["*.tmp", "cache/*"]}`.
//! Restores: `download` (done by the host), `to_dir` `{"target": "/abs/dir", "overwrite": false}`.

use plugin_sdk::{error, BackupResult, Ctx, Plugin, RestoreOptions, Result, Sink, Source, Validation, WalkOptions};
use std::path::Path;

struct ExampleFiles;

fn excludes(ctx: &Ctx) -> Vec<String> {
    ctx.config["excludes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

impl Plugin for ExampleFiles {
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
        let p = ctx.config_str("path")?;
        Ok(match std::fs::read_dir(p) {
            Ok(_) if p.starts_with('/') => Validation::Valid,
            Ok(_) => Validation::Invalid {
                field: "path".into(),
                message: "must be absolute".into(),
            },
            Err(e) => Validation::Invalid {
                field: "path".into(),
                message: format!("cannot read the directory: {e}"),
            },
        })
    }

    fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
        let root = ctx.config_str("path")?;
        let runs = ctx
            .state
            .as_deref()
            .and_then(|s| std::str::from_utf8(s).ok()?.strip_prefix("runs=")?.parse::<u64>().ok())
            .unwrap_or(0);
        ctx.info(format!("backing up {root} (run {})", runs + 1));
        let st = sink.walk_dir(
            Path::new(root),
            &WalkOptions {
                excludes: excludes(ctx),
                xattrs: true,
            },
        )?;
        Ok(BackupResult {
            state: Some(format!("runs={}", runs + 1).into_bytes()),
            // a live directory without a file system snapshot: not crash-consistent
            consistent: false,
            summary: format!(
                "{} entries, {} files ({} read, {} unchanged), {} bytes, {} vanished, {} errors",
                st.entries, st.files, st.files_read, st.unchanged, st.bytes, st.vanished, st.errors
            ),
        })
    }

    fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String> {
        if ctx.params["restore"] != "to_dir" {
            return Err(error(95, format!("unknown restore {}", ctx.params["restore"])));
        }
        let p = &ctx.params["params"];
        let target = p["target"].as_str().ok_or_else(|| error(22, "params.target missing"))?;
        let top: Vec<Vec<u8>> = ctx.params["top"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(|s| s.as_bytes().to_vec()))
            .collect();
        let st = src.restore_tree(
            &top,
            Path::new(target),
            &RestoreOptions {
                overwrite: p["overwrite"].as_bool().unwrap_or(false),
                owners: false,
                xattrs: true,
            },
        )?;
        for m in &st.messages {
            ctx.warn(m.clone());
        }
        if st.errors > 0 {
            return Err(error(5, format!("{} entries could not be restored", st.errors)));
        }
        Ok(format!(
            "{} files, {} dirs, {} other, {} bytes restored to {target}",
            st.files, st.dirs, st.other, st.bytes
        ))
    }
}

fn main() {
    plugin_sdk::run(ExampleFiles)
}
