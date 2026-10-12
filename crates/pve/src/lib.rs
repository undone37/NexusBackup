//! Proxmox VE connector (pull model): PVE API + NBD over SSH into the chunk store.

pub mod api;
pub mod backup;
pub mod ct;
pub mod exclude;
pub mod files;
pub mod inventory;
pub mod ir;
pub mod parallel;
pub mod restorevm;
