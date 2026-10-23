//! VMware ESXi / vCenter backups (plan.md Phase 41, docs/vmware-design.md): the vSphere client and
//! the backup through a hot-add proxy (an enrolled agent with `block-read`).

pub mod backup;
pub mod vsphere;
