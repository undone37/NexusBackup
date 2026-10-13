//! NexusBackup chunk store: dedup -> compress -> encrypt, forever-full snapshots.

pub mod clock;
pub mod crypto;
pub mod health;
pub mod names;
pub mod retention;
pub mod store;

pub use crypto::{ChunkId, Keyring};
pub use names::NameIndex;
pub use store::{FileEntry, FileStats, Index, Manifest, Options, Store, TreeEntry, TreeKind, Written};
