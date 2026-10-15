//! NexusBackup chunk store: dedup -> compress -> encrypt, forever-full snapshots.

#![warn(missing_docs)]

pub mod clock;
pub mod crypto;
pub mod drift;
pub mod health;
pub mod names;
pub mod pipeline;
pub mod progress;
pub mod snapfile;
/// GFS retention (its own crate so the web-api can preview it without linking the store)
pub use retention;
pub mod store;
pub mod synthetic;

pub use crypto::{ChunkId, Keyring};
pub use names::NameIndex;
pub use pipeline::ChunkSink;
pub use store::{
    chunk_list_key, FileEntry, FileStats, HashStats, Index, Manifest, Options, Store, TreeEntry, TreeKind, Written,
};
