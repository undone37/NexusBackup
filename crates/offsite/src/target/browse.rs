//! Offsite in the web UI (Phase 17d, docs/control-plane.md "Offsite in the
//! UI"): what the box holds, cross-checked against the local inventory and the
//! local store, and fetching one snapshot back for the normal restores.

use super::{snap_key, Target};
use anyhow::{Context, Result};
use chunkstore::Manifest;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;

/// One snapshot of the box listing (`nexus-offsite list --json`).
#[derive(Debug, Serialize, PartialEq)]
pub struct Listed {
    pub source: String,
    pub time: u64,
    /// logical size from its indexes (`None`: not in the local inventory)
    pub size: Option<u64>,
    /// offsite retention lock (unix seconds, 0 = none / unknown)
    pub lock_until: u64,
    /// in this appliance's offsite inventory
    pub inventory: bool,
    /// its manifest is on the box (`false`: the inventory knows it, the box lost it)
    pub remote: bool,
    /// a local copy exists in the store (else: "Fetch from offsite")
    pub local: bool,
}

impl Target<'_> {
    /// Every snapshot the inventory or the box knows, sorted.
    pub fn listing(&self) -> Result<Vec<Listed>> {
        let mut out: BTreeMap<(String, u64), Listed> = BTreeMap::new();
        for (source, time) in self.snapshots()? {
            let dir = self.state.join(snap_key(&source, time));
            let m = self
                .store
                .decode_manifest(&source, time, &fs::read(dir.join("manifest"))?)?;
            let mut size = 0;
            for name in &m.indexes {
                let blob = fs::read(dir.join(format!("{name}.idx")))?;
                size += self.store.decode_index(&source, time, name, &blob)?.size();
            }
            let l = Listed {
                lock_until: self.offsite_lock(&source, time).unwrap_or(0),
                local: self.store.load_manifest(&source, time).is_ok(),
                source,
                time,
                size: Some(size),
                inventory: true,
                remote: false,
            };
            out.insert((l.source.clone(), time), l);
        }
        for (source, _, dir) in self.remote.list("snapshots")? {
            if !dir || !super::safe_name(&source) {
                continue;
            }
            for (t, _, _) in self.remote.list(&format!("snapshots/{source}"))? {
                let Ok(time) = t.parse::<u64>() else { continue };
                let key = snap_key(&source, time);
                if !self.remote.list(&key)?.iter().any(|(n, _, _)| n == "manifest") {
                    continue;
                }
                out.entry((source.clone(), time))
                    .or_insert_with(|| Listed {
                        local: self.store.load_manifest(&source, time).is_ok(),
                        source: source.clone(),
                        time,
                        size: None,
                        lock_until: 0,
                        inventory: false,
                        remote: false,
                    })
                    .remote = true;
            }
        }
        Ok(out.into_values().collect())
    }

    /// [`Target::restore`] plus a local lock of at least `keep_secs` from now
    /// (compliance clock), so local retention does not delete the fetched copy
    /// again before it was used. Locks only grow: a longer lock stays.
    pub fn fetch(&self, source: &str, time: u64, keep_secs: u64) -> Result<Manifest> {
        let m = self.restore(source, time)?;
        let until = self.store.compliance_now()? + keep_secs;
        self.store
            .extend_lock(source, time, until)
            .with_context(|| format!("lock {source}/{time}"))?;
        Ok(m)
    }
}
