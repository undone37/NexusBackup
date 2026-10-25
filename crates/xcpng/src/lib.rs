//! XCP-ng / XenServer connector (Phase 42, #40, docs/xcpng-design.md): XAPI over HTTPS, the VM's disks read from
//! a snapshot over NBD/TLS (no proxy), stored in the PVE VM layout (one fixed index per disk, `xcpng.json`).

pub mod backup;
pub mod nbdtls;
pub mod xapi;
