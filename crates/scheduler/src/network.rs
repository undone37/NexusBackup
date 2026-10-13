//! Network interfaces (Phase 22a, catalog::network): the root helper nexus-net applies them and
//! writes `<net_dir>/status.json`. Here: interface-bound egress (the roles' destinations go into
//! the firewall file with the role's interface, see `sync_firewall`) and the audit of the
//! helper's finished operations (`network.op`: applied, refused, failed, rolled back).

use super::*;
use nftsync::RoleTargets;

/// ids of nexus-net operations already audited (the newest 100)
const AUDITED_SETTING: &str = "net_ops_audited";
const ACTOR_NET: &str = "nexus-net";

fn read(p: &Path) -> Option<Value> {
    let b = fs::read(p).ok()?;
    (b.len() <= 4 << 20).then(|| serde_json::from_slice(&b).ok())?
}

impl Scheduler {
    /// role → interface from the applied configuration (empty without a status: any interface).
    pub fn net_egress(&self) -> BTreeMap<&'static str, String> {
        read(&self.cfg.net_dir.join("status.json"))
            .map(|s| catalog::network::egress(&catalog::network::applied(&s)))
            .unwrap_or_default()
    }

    /// The firewall file's `roles`: each role's resolved destinations with its interface.
    pub(crate) fn egress_roles<const N: usize>(
        &self,
        by_role: [(&str, Vec<(String, u16)>); N],
    ) -> BTreeMap<String, RoleTargets> {
        let egress = self.net_egress();
        by_role
            .into_iter()
            .map(|(role, targets)| {
                (
                    role.to_owned(),
                    RoleTargets {
                        iface: egress.get(role).cloned(),
                        endpoints: firewall::resolve(&targets),
                    },
                )
            })
            .collect()
    }

    /// Audits the operations nexus-net finished (once each).
    pub fn audit_net_ops(&self) -> Result<()> {
        match read(&self.cfg.net_dir.join("ops.json")) {
            Some(ops) => self.audit_helper_ops(&ops, AUDITED_SETTING, ACTOR_NET, "network"),
            None => Ok(()),
        }
    }
}
