//! Entra ID directory objects (`entra` in the source config, off by default; guest
//! `e.directory`, one per source), **export only**:
//!
//! ```text
//! e.directory  users/<UPN> ~<hash>.json                    user (directory properties, licenses)
//!              groups/<name> ~<hash>.json                  group + "members" and "owners" (id, name, UPN)
//!              devices/<name> ~<hash>.json                 device
//!              applications/<name> ~<hash>.json            app registration (credential metadata only)
//!              service-principals/<name> ~<hash>.json      enterprise application
//! ```
//!
//! One Graph JSON per object, as Graph returns it (Graph never returns secrets:
//! `passwordCredentials` carry a hint, `keyCredentials` the public part). Every
//! run lists the directory completely (no directory delta: one delta link per
//! object type would buy little for metadata of this size); an object whose JSON
//! is byte-identical to the base is sent as `Unchanged` (the version tag is a hash
//! of the JSON). A type the app may not read (403) is reported as a warning and
//! keeps its base files, like any other failed listing.
//!
//! Permissions beyond User.Read.All: Group.Read.All (or GroupMember.Read.All) for
//! groups with members and owners, Device.Read.All, Application.Read.All (app
//! registrations and service principals). Download only — Graph cannot re-create
//! directory objects faithfully (ids, sync anchors, credentials), so `to_original`
//! / `to_other` refuse this guest.

use super::{time_ns, Item, Run};
use crate::format::{item_name, short_hash};
use crate::graph::enc;
use plugin_sdk::Result;
use serde_json::json;

struct Type {
    dir: &'static str,
    url: &'static str,
    /// property used as the file name
    label: &'static str,
    perm: &'static str,
    /// groups: also read members and owners
    members: bool,
}

const TYPES: &[Type] = &[
    Type {
        dir: "users",
        url: "/users?$select=id,userPrincipalName,displayName,givenName,surname,mail,otherMails,proxyAddresses,\
              userType,accountEnabled,jobTitle,department,companyName,employeeId,officeLocation,city,country,\
              usageLocation,preferredLanguage,mobilePhone,businessPhones,assignedLicenses,onPremisesSyncEnabled,\
              onPremisesImmutableId,onPremisesSamAccountName,createdDateTime&$top=999",
        label: "userPrincipalName",
        perm: "User.Read.All",
        members: false,
    },
    Type {
        dir: "groups",
        url: "/groups?$select=id,displayName,description,mail,mailEnabled,mailNickname,securityEnabled,groupTypes,\
              visibility,membershipRule,membershipRuleProcessingState,isAssignableToRole,proxyAddresses,\
              onPremisesSyncEnabled,resourceProvisioningOptions,createdDateTime&$top=999",
        label: "displayName",
        perm: "Group.Read.All (or GroupMember.Read.All)",
        members: true,
    },
    Type {
        dir: "devices",
        url: "/devices?$top=999",
        label: "displayName",
        perm: "Device.Read.All",
        members: false,
    },
    Type {
        dir: "applications",
        url: "/applications?$top=999",
        label: "displayName",
        perm: "Application.Read.All",
        members: false,
    },
    Type {
        dir: "service-principals",
        url: "/servicePrincipals?$top=999",
        label: "displayName",
        perm: "Application.Read.All",
        members: false,
    },
];

/// Validation probes of the extra permissions (users are checked anyway).
pub const CHECKS: [(&str, &str); 3] = [
    ("/groups?$select=id&$top=1", "Group.Read.All (or GroupMember.Read.All)"),
    ("/devices?$select=id&$top=1", "Device.Read.All"),
    ("/applications?$select=id&$top=1", "Application.Read.All"),
];

impl Run<'_, '_> {
    /// The base file of object `xid`, taken over (its read failed this time).
    fn keep_object(&mut self, xid: &str) -> Result<()> {
        if let Some(b) = self.prev.get(xid).cloned() {
            if self.out.used.insert(b.path.clone()) {
                self.out.sink.unchanged(&b.path, b.meta)?;
                self.out.items += 1;
                self.out.unchanged += 1;
            }
        }
        Ok(())
    }

    pub(super) fn directory(&mut self) -> Result<()> {
        let mut counts = Vec::new();
        for t in TYPES {
            let xid = format!("entra:{}", t.dir);
            self.out.dir(t.dir, &xid)?;
            let mut objs = Vec::new();
            if let Err(e) = self.g.pages(t.url, &[], |o| {
                objs.push(o);
                Ok(())
            }) {
                let e = e.context(format!("needs the application permission {}", t.perm));
                self.item_failed(t.dir, e)?;
                self.keep_base(&xid, t.dir)?;
                continue;
            }
            counts.push(format!("{} {}", objs.len(), t.dir));
            'obj: for mut o in objs {
                let Some(id) = o["id"].as_str().map(str::to_owned) else {
                    continue;
                };
                let oid = format!("entra:{id}");
                if t.members {
                    for rel in ["members", "owners"] {
                        let mut v = Vec::new();
                        let url = format!(
                            "/groups/{}/{rel}?$select=id,displayName,userPrincipalName&$top=999",
                            enc(&id)
                        );
                        match self.g.pages(&url, &[], |m| {
                            v.push(m);
                            Ok(())
                        }) {
                            Ok(_) => o[rel] = json!(v),
                            Err(e) => {
                                if self.item_failed(&format!("{}/{id} ({rel})", t.dir), e)? {
                                    self.keep_object(&oid)?;
                                }
                                continue 'obj;
                            }
                        }
                    }
                }
                let b = serde_json::to_vec_pretty(&o)?;
                let label = o[t.label].as_str().or(o["displayName"].as_str()).unwrap_or(&id);
                let it = Item {
                    name: item_name(label, &id, "json"),
                    tag: short_hash(&String::from_utf8_lossy(&b)),
                    mtime_ns: time_ns(&o["createdDateTime"]),
                };
                let path = self.out.claim(format!("{}/{}", t.dir, it.name), &oid);
                if !self.out.unchanged(&self.prev, &path, &oid, &it, Some(b.len() as u64))? {
                    self.out.bytes(&path, &oid, &it, &b)?;
                }
            }
        }
        self.note(&format!("Entra ID: {}", counts.join(", ")));
        Ok(())
    }
}
