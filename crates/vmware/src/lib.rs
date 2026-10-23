//! VMware ESXi / vCenter backups (plan.md Phase 41, docs/vmware-design.md): the vSphere client, the two disk
//! transports (NFC and the hot-add proxy, an enrolled agent with `block-read`) and the backup. Without the
//! `connector` feature only [`names`] (snapshot source names for web-api and scheduler).

#[cfg(feature = "connector")]
pub mod backup;
pub mod names;
#[cfg(feature = "connector")]
pub mod nfc;
#[cfg(feature = "connector")]
pub mod vsphere;
