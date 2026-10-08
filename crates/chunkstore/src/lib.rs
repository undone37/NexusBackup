//! NexusBackup chunk store: dedup -> compress -> encrypt, forever-full snapshots.

pub mod clock;
pub mod crypto;
pub mod store;

pub use crypto::{ChunkId, Keyring};
pub use store::{FileEntry, Index, Manifest, Options, Store};
