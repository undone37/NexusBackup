//! NexusBackup chunk store: dedup -> compress -> encrypt, forever-full snapshots.

pub mod clock;
pub mod crypto;
pub mod drift;
pub mod health;
pub mod names;
pub mod pipeline;
pub mod progress;
/// GFS retention (its own crate so the web-api can preview it without linking the store)
pub use retention;
pub mod store;

pub use crypto::{ChunkId, Keyring};
pub use names::NameIndex;
pub use pipeline::ChunkSink;
pub use store::{
    chunk_list_key, FileEntry, FileStats, HashStats, Index, Manifest, Options, Store, TreeEntry, TreeKind, Written,
};
