//! The generic `download` restore (no plugin involved): the snapshot's files plus
//! its streams below `.nexus-streams/<name>`, listed and written as tar/zip with
//! the agents' file module (same JSON listing as the other connectors). The view
//! itself lives in `agent_conn::files::with_streams` (restores to a host use it too).

use crate::restore::Snapshot;
use anyhow::Result;
use chunkstore::TreeEntry;

/// Files + streams as one tree (streams as regular files, mode 0600, snapshot time).
pub fn view(s: &Snapshot) -> Vec<TreeEntry> {
    agent_conn::files::with_streams(s.files.clone(), &s.streams, s.time)
}

pub fn list(s: &Snapshot, dir: &str) -> Result<Vec<agent_conn::files::ListEntry>> {
    agent_conn::files::list(&view(s), dir)
}

#[cfg(test)]
mod tests {
    #[test]
    fn streams_dir_matches_the_protocol() {
        assert_eq!(agent_conn::files::STREAMS_DIR, plugin_proto::STREAMS_DIR);
    }
}
