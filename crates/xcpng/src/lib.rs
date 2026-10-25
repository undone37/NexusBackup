//! XCP-ng / XenServer connector (Phase 42, #40, docs/xcpng-design.md): XAPI over HTTPS, the VM's disks read from
//! a snapshot over NBD/TLS (no proxy), stored in the PVE VM layout (one fixed index per disk, `xcpng.json`). Without
//! the `connector` feature only [`names`].

#[cfg(feature = "connector")]
pub mod backup;
pub mod names;
#[cfg(feature = "connector")]
pub mod nbdtls;
#[cfg(feature = "connector")]
pub mod xapi;
