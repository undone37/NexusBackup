//! Plain BLAKE3 → keyed chunk ID mapping (`<store>/agent-map.db`, SQLite,
//! 0600). Appliance-local, never uploaded offsite. Only a cache: a missing
//! or stale entry costs one re-transfer, because every mapped ID is checked
//! (and touched against GC) in the store before a `Want` is skipped, and
//! entries are written only for chunks whose data matched their plain hash.

use agent_proto::Hash;
use anyhow::{Context, Result};
use chunkstore::ChunkId;
use rusqlite::{params, Connection, OptionalExtension};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const FILE: &str = "agent-map.db";

pub struct MapDb {
    c: Connection,
}

impl MapDb {
    pub fn open(store_root: &Path) -> Result<MapDb> {
        let path = store_root.join(FILE);
        let c = Connection::open(&path).with_context(|| format!("{}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
        c.busy_timeout(std::time::Duration::from_secs(60))?;
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS map (plain BLOB PRIMARY KEY, keyed BLOB NOT NULL, len INTEGER NOT NULL) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS map_keyed ON map(keyed);",
        )?;
        Ok(MapDb { c })
    }

    pub fn get(&self, plain: &Hash) -> Result<Option<ChunkId>> {
        let v: Option<Vec<u8>> = self
            .c
            .prepare_cached("SELECT keyed FROM map WHERE plain = ?1")?
            .query_row([&plain[..]], |r| r.get(0))
            .optional()?;
        Ok(v.and_then(|v| v.try_into().ok()))
    }

    /// Reverse lookup (restore sends plain hashes to the agent): (plain hash, length).
    pub fn plain_of(&self, id: &ChunkId) -> Result<Option<(Hash, u32)>> {
        let v: Option<(Vec<u8>, u32)> = self
            .c
            .prepare_cached("SELECT plain, len FROM map WHERE keyed = ?1 LIMIT 1")?
            .query_row([&id[..]], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        Ok(v.and_then(|(p, l)| Some((p.try_into().ok()?, l))))
    }

    /// (plain hash, keyed id, length) of verified chunks.
    pub fn put_all(&mut self, pairs: &[(Hash, ChunkId, u32)]) -> Result<()> {
        let tx = self.c.transaction()?;
        {
            let mut st = tx.prepare_cached("INSERT OR REPLACE INTO map (plain, keyed, len) VALUES (?1, ?2, ?3)")?;
            for (p, k, l) in pairs {
                st.execute(params![&p[..], &k[..], l])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn len(&self) -> Result<u64> {
        Ok(self.c.query_row("SELECT COUNT(*) FROM map", [], |r| r.get(0))?)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}
