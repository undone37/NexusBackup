//! Proxmox VE connector (pull model): PVE API + NBD over SSH into the chunk store.

pub mod api;
pub mod backup;
pub mod consistency;
pub mod ct;
pub mod exclude;
pub mod files;
pub mod fleecing;
pub mod fsindex;
pub mod idr;
pub mod inventory;
pub mod ir;
pub mod p2v;
pub mod parallel;
pub mod restore;
pub mod restoretest;
pub mod restorevm;
pub mod rollback;
pub mod scan;
