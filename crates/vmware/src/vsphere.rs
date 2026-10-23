//! vSphere Web Services (SOAP, `vim25`) client for what backups need: the session, VM and snapshot
//! disks, snapshots, changed block tracking (`QueryChangedDiskAreas`) and reconfiguring the proxy
//! (hot-adding a snapshot's base disk and removing it again). Plain XML over HTTPS (reqwest,
//! blocking); answers are parsed with roxmltree. TLS trusts exactly the configured certificate
//! (the host's own, ESXi's default is self-signed) or a CA that signed it.

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client as Http;
use std::time::{Duration, Instant};

/// A managed object reference: `type` and value (`vm-12`, `snapshot-3`, `ha-host`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoRef {
    pub kind: String,
    pub value: String,
}

impl MoRef {
    pub fn new(kind: &str, value: &str) -> MoRef {
        MoRef {
            kind: kind.into(),
            value: value.into(),
        }
    }
    fn xml(&self, tag: &str) -> String {
        format!(
            r#"<urn:{tag} type="{}">{}</urn:{tag}>"#,
            esc(&self.kind),
            esc(&self.value)
        )
    }
}

/// One virtual disk of a VM or snapshot configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    /// device key (2000, 2001, ...)
    pub key: i32,
    pub controller_key: i32,
    pub unit: i32,
    pub capacity: u64,
    /// `[datastore] dir/name.vmdk` of the disk as configured (a snapshot's delta for a running
    /// VM with snapshots)
    pub file: String,
    /// the base disk of the chain (`backing.parent` followed to its end): what a hot-add reads
    pub base_file: String,
    /// CBT change id of this disk state (`None`: CBT off)
    pub change_id: Option<String>,
}

/// Where a VM's devices are attached, for the proxy's free SCSI unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Controller {
    pub key: i32,
    pub bus: i32,
    /// `scsi` (lsilogic, pvscsi, ...), `sata`, `nvme`, `ide` or `other`: the prefix of the disk names
    pub kind: &'static str,
}

/// What a backup needs to know about a VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmInfo {
    pub name: String,
    /// `config.instanceUuid` (vCenter; stable across renames and re-registrations), on a standalone host
    /// `config.uuid` (the BIOS UUID: a clone made outside vCenter keeps it), the snapshot source
    pub uuid: String,
    /// `[datastore] dir/name.vmx`
    pub vmx: String,
    pub cbt: bool,
    /// VMware Tools run (a quiesced snapshot is possible)
    pub tools: bool,
}

/// A one-time NFC ticket (`vim.HostServiceTicket` from `NfcGetVmFiles`): where and how to reach the ESXi NFC
/// service (authd on TCP 902) to read a VM's disk files without a proxy VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfcTicket {
    /// ESXi management / NFC address
    pub host: String,
    pub port: u16,
    /// SHA-1 of the ESXi TLS certificate, colon-separated hex (pin the authd TLS to it)
    pub ssl_thumbprint: String,
    /// authd `PROXY` argument (`vpxa-nfc` on vCenter, `ha-nfc` on a host)
    pub service: String,
    /// one-time authd `SESSION` token
    pub session_id: String,
}

/// `[datastore] dir/file` into (datastore, path).
pub fn split_ds_path(p: &str) -> Option<(&str, &str)> {
    let (ds, path) = p.strip_prefix('[')?.split_once("] ")?;
    Some((ds, path))
}

pub struct Client {
    http: Http,
    url: String,
    content: Content,
    /// `vmware_soap_session=...` from the login answer
    cookie: String,
    /// the host this client connected to (fallback for a ticket with an empty host)
    host: String,
}

/// The service content morefs this client uses.
#[derive(Debug, Clone)]
struct Content {
    property_collector: MoRef,
    root_folder: MoRef,
    session_manager: MoRef,
    view_manager: MoRef,
    about: String,
}

/// XML text escaping for element content and attribute values.
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn envelope(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"#
    )
}

/// Children of `n` with the local name `name`.
fn kids<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &'a str) -> impl Iterator<Item = roxmltree::Node<'a, 'i>> + 'a {
    n.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == name)
}

fn kid<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &'a str) -> Option<roxmltree::Node<'a, 'i>> {
    kids(n, name).next()
}

fn text(n: Option<roxmltree::Node>) -> Option<String> {
    n.and_then(|n| n.text()).map(str::to_owned)
}

/// A child element's text parsed as a number.
fn num<T: std::str::FromStr>(n: roxmltree::Node, name: &str) -> Option<T> {
    text(kid(n, name)).and_then(|v| v.parse().ok())
}

fn moref(n: Option<roxmltree::Node>) -> Option<MoRef> {
    let n = n?;
    Some(MoRef::new(n.attribute("type")?, n.text()?))
}

/// `xsi:type` without its prefix.
fn xsi_type<'a>(n: roxmltree::Node<'a, '_>) -> &'a str {
    n.attributes()
        .find(|a| a.name() == "type" && a.namespace() == Some("http://www.w3.org/2001/XMLSchema-instance"))
        .map(|a| a.value())
        .map_or("", |v| v.rsplit(':').next().unwrap_or(v))
}

/// The disks of an `ArrayOfVirtualDevice` value.
pub fn parse_disks(devices: roxmltree::Node) -> Vec<Disk> {
    devices
        .children()
        .filter(|d| d.is_element() && xsi_type(*d) == "VirtualDisk")
        .filter_map(|d| {
            let backing = kid(d, "backing")?;
            let mut base = backing;
            while let Some(p) = kid(base, "parent") {
                base = p;
            }
            Some(Disk {
                key: num(d, "key")?,
                controller_key: num(d, "controllerKey")?,
                unit: num(d, "unitNumber").unwrap_or(0),
                capacity: num(d, "capacityInBytes")
                    .or_else(|| num(d, "capacityInKB").map(|k: u64| k * 1024))
                    .unwrap_or(0),
                file: text(kid(backing, "fileName"))?,
                base_file: text(kid(base, "fileName"))?,
                change_id: text(kid(backing, "changeId")).filter(|c| !c.is_empty()),
            })
        })
        .collect()
}

/// The controllers of an `ArrayOfVirtualDevice` value.
pub fn parse_controllers(devices: roxmltree::Node) -> Vec<Controller> {
    devices
        .children()
        .filter(roxmltree::Node::is_element)
        .filter_map(|d| {
            let kind = match xsi_type(d) {
                "ParaVirtualSCSIController"
                | "VirtualLsiLogicController"
                | "VirtualLsiLogicSASController"
                | "VirtualBusLogicController" => "scsi",
                "VirtualAHCIController" => "sata",
                "VirtualNVMEController" => "nvme",
                "VirtualIDEController" => "ide",
                t if t.ends_with("Controller") => "other",
                _ => return None,
            };
            Some(Controller {
                key: text(kid(d, "key"))?.parse().ok()?,
                bus: text(kid(d, "busNumber")).and_then(|b| b.parse().ok()).unwrap_or(0),
                kind,
            })
        })
        .collect()
}

impl Client {
    /// Connects to `https://host:port/sdk` trusting `ca_pem` (the host's certificate or its CA) and logs in.
    pub fn login(host: &str, port: u16, ca_pem: &[u8], user: &str, password: &str) -> Result<Client> {
        let tls = truenas::api::tls_config(ca_pem).context("the vSphere certificate (ca_pem)")?;
        let http = Http::builder()
            .use_preconfigured_tls(tls)
            .timeout(Duration::from_secs(300))
            .build()?;
        let url = format!("https://{host}:{port}/sdk");
        let mut c = Client {
            http,
            url,
            content: Content {
                property_collector: MoRef::new("PropertyCollector", ""),
                root_folder: MoRef::new("Folder", ""),
                session_manager: MoRef::new("SessionManager", ""),
                view_manager: MoRef::new("ViewManager", ""),
                about: String::new(),
            },
            cookie: String::new(),
            host: host.to_string(),
        };
        c.content = c.service_content()?;
        let body = format!(
            "<urn:Login>{}<urn:userName>{}</urn:userName><urn:password>{}</urn:password></urn:Login>",
            c.content.session_manager.xml("_this"),
            esc(user),
            esc(password)
        );
        let (_, cookie) = c.post(&body).context("vSphere login")?;
        c.cookie = cookie.context("vSphere login: no session cookie")?;
        Ok(c)
    }

    /// `ESXi 8.0.3 build-24280767` / the vCenter version.
    pub fn about(&self) -> &str {
        &self.content.about
    }

    /// One SOAP request; Err with the fault's message for a SOAP fault.
    fn call(&self, body: &str) -> Result<String> {
        self.post(body).map(|(t, _)| t)
    }

    /// The answer and the session cookie it set, if any.
    fn post(&self, body: &str) -> Result<(String, Option<String>)> {
        let mut rq = self
            .http
            .post(&self.url)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("SOAPAction", "urn:vim25/7.0")
            .body(envelope(body));
        if !self.cookie.is_empty() {
            rq = rq.header("Cookie", &self.cookie);
        }
        let r = rq.send().with_context(|| format!("vSphere request to {}", self.url))?;
        let cookie = r
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("vmware_soap_session="))
            .map(|v| v.split(';').next().unwrap_or(v).to_owned());
        let status = r.status();
        let text = r.text()?;
        if !status.is_success() {
            let doc = roxmltree::Document::parse(&text).ok();
            let fault = doc
                .as_ref()
                .and_then(|d| d.descendants().find(|n| n.tag_name().name() == "faultstring"))
                .and_then(|n| n.text())
                .unwrap_or("no fault string");
            bail!("vSphere answered {status}: {fault}");
        }
        Ok((text, cookie))
    }

    fn service_content(&self) -> Result<Content> {
        let t = self.call(r#"<urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance</urn:_this></urn:RetrieveServiceContent>"#)?;
        let doc = roxmltree::Document::parse(&t)?;
        let rv = doc
            .descendants()
            .find(|n| n.tag_name().name() == "returnval")
            .context("RetrieveServiceContent: no returnval")?;
        let get = |name| moref(kid(rv, name)).with_context(|| format!("service content without {name}"));
        Ok(Content {
            property_collector: get("propertyCollector")?,
            root_folder: get("rootFolder")?,
            session_manager: get("sessionManager")?,
            view_manager: get("viewManager")?,
            about: kid(rv, "about")
                .and_then(|a| text(kid(a, "fullName")))
                .unwrap_or_default(),
        })
    }

    /// `RetrievePropertiesEx` of `paths` of one object; the document of the answer (`propSet`s).
    fn properties(&self, obj: &MoRef, paths: &[&str]) -> Result<String> {
        let sets: String = paths
            .iter()
            .map(|p| format!("<urn:pathSet>{}</urn:pathSet>", esc(p)))
            .collect();
        self.call(&format!(
            "<urn:RetrievePropertiesEx>{}<urn:specSet><urn:propSet><urn:type>{}</urn:type>{sets}</urn:propSet>\
             <urn:objectSet>{}<urn:skip>false</urn:skip></urn:objectSet></urn:specSet><urn:options/></urn:RetrievePropertiesEx>",
            self.content.property_collector.xml("_this"),
            esc(&obj.kind),
            obj.xml("obj")
        ))
    }

    /// Every VM: (moref, name). ponytail: one page of RetrievePropertiesEx (no
    /// ContinueRetrievePropertiesEx); a host or vCenter with more VMs than a page needs paging.
    pub fn vms(&self) -> Result<Vec<(MoRef, String)>> {
        let t = self.call(&format!(
            "<urn:CreateContainerView>{}{}<urn:type>VirtualMachine</urn:type><urn:recursive>true</urn:recursive></urn:CreateContainerView>",
            self.content.view_manager.xml("_this"),
            self.content.root_folder.xml("container")
        ))?;
        let doc = roxmltree::Document::parse(&t)?;
        let view =
            moref(doc.descendants().find(|n| n.tag_name().name() == "returnval")).context("no container view")?;
        let t = self.call(&format!(
            r#"<urn:RetrievePropertiesEx>{}<urn:specSet><urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>name</urn:pathSet></urn:propSet><urn:objectSet>{}<urn:skip>true</urn:skip><urn:selectSet xsi:type="urn:TraversalSpec"><urn:type>ContainerView</urn:type><urn:path>view</urn:path><urn:skip>false</urn:skip></urn:selectSet></urn:objectSet></urn:specSet><urn:options/></urn:RetrievePropertiesEx>"#,
            self.content.property_collector.xml("_this"),
            view.xml("obj")
        ))?;
        let _ = self.call(&format!("<urn:DestroyView>{}</urn:DestroyView>", view.xml("_this")));
        let doc = roxmltree::Document::parse(&t)?;
        Ok(doc
            .descendants()
            .filter(|n| n.tag_name().name() == "objects")
            .filter_map(|o| {
                let m = moref(kid(o, "obj"))?;
                let name = kids(o, "propSet").find_map(|p| text(kid(p, "val")))?;
                Some((m, name))
            })
            .collect())
    }

    /// Disks and controllers of a VM or a snapshot (`config.hardware.device`).
    pub fn devices(&self, obj: &MoRef) -> Result<(Vec<Disk>, Vec<Controller>)> {
        let t = self.properties(obj, &["config.hardware.device"])?;
        let doc = roxmltree::Document::parse(&t)?;
        let val = doc
            .descendants()
            .find(|n| n.tag_name().name() == "val")
            .with_context(|| format!("{}: no devices", obj.value))?;
        Ok((parse_disks(val), parse_controllers(val)))
    }

    /// Every VM with its [`VmInfo`] (the UUID is the guest id of the inventory and the snapshot source).
    /// ponytail: one property call per VM; a large vCenter would want one RetrievePropertiesEx over the view.
    pub fn vm_list(&self) -> Result<Vec<(MoRef, VmInfo)>> {
        self.vms()?
            .into_iter()
            .map(|(m, _)| Ok((m.clone(), self.vm_info(&m)?)))
            .collect()
    }

    /// Name, instance UUID, `.vmx` path, CBT and Tools state of a VM.
    pub fn vm_info(&self, vm: &MoRef) -> Result<VmInfo> {
        let t = self.properties(
            vm,
            &[
                "name",
                "config.instanceUuid",
                "config.uuid",
                "config.files.vmPathName",
                "config.changeTrackingEnabled",
                "guest.toolsRunningStatus",
            ],
        )?;
        let doc = roxmltree::Document::parse(&t)?;
        let get = |p: &str| {
            doc.descendants()
                .filter(|n| n.tag_name().name() == "propSet")
                .find(|n| text(kid(*n, "name")).as_deref() == Some(p))
                .and_then(|n| text(kid(n, "val")))
                .filter(|v| !v.trim().is_empty())
        };
        let need = |p: &str| get(p).with_context(|| format!("{}: no {p}", vm.value));
        Ok(VmInfo {
            name: need("name")?,
            uuid: get("config.instanceUuid").map_or_else(|| need("config.uuid"), Ok)?,
            vmx: need("config.files.vmPathName")?,
            cbt: get("config.changeTrackingEnabled").as_deref() == Some("true"),
            tools: get("guest.toolsRunningStatus").as_deref() == Some("guestToolsRunning"),
        })
    }

    /// A datastore file (`[ds] dir/file`) through `/folder`, at most `max` bytes. `dc`: the datacenter
    /// (`ha-datacenter` on a standalone host).
    pub fn download(&self, ds_path: &str, dc: &str, max: usize) -> Result<Vec<u8>> {
        let (ds, path) = split_ds_path(ds_path).with_context(|| format!("not a datastore path: {ds_path:?}"))?;
        let mut url = reqwest::Url::parse(&self.url)?;
        url.set_path(&format!("folder/{path}"));
        url.query_pairs_mut()
            .append_pair("dcPath", dc)
            .append_pair("dsName", ds);
        let r = self
            .http
            .get(url)
            .header("Cookie", &self.cookie)
            .send()
            .with_context(|| format!("download of {ds_path}"))?;
        if !r.status().is_success() {
            bail!("download of {ds_path}: {}", r.status());
        }
        let b = r.bytes()?;
        if b.len() > max {
            bail!("{ds_path}: {} bytes, more than the {max} expected", b.len());
        }
        Ok(b.to_vec())
    }

    /// `config.changeTrackingEnabled` of a VM.
    pub fn cbt_enabled(&self, vm: &MoRef) -> Result<bool> {
        let t = self.properties(vm, &["config.changeTrackingEnabled"])?;
        let doc = roxmltree::Document::parse(&t)?;
        Ok(doc
            .descendants()
            .find(|n| n.tag_name().name() == "val")
            .and_then(|n| n.text())
            == Some("true"))
    }

    /// Waits for a task; its result (a moref for `CreateSnapshot_Task`) when it has one.
    pub fn wait(&self, task: &MoRef, timeout: Duration) -> Result<Option<MoRef>> {
        let t0 = Instant::now();
        loop {
            let t = self.properties(task, &["info"])?;
            let doc = roxmltree::Document::parse(&t)?;
            let info = doc
                .descendants()
                .find(|n| n.tag_name().name() == "val")
                .context("task without info")?;
            match text(kid(info, "state")).as_deref() {
                Some("success") => return Ok(moref(kid(info, "result"))),
                Some("error") => {
                    let msg = kid(info, "error")
                        .and_then(|e| text(kid(e, "localizedMessage")))
                        .unwrap_or_else(|| "unknown error".into());
                    bail!("vSphere task {} failed: {msg}", task.value);
                }
                _ if t0.elapsed() > timeout => bail!("vSphere task {} still running after {timeout:?}", task.value),
                _ => std::thread::sleep(Duration::from_millis(500)),
            }
        }
    }

    fn task(&self, body: &str) -> Result<MoRef> {
        let t = self.call(body)?;
        let doc = roxmltree::Document::parse(&t)?;
        moref(doc.descendants().find(|n| n.tag_name().name() == "returnval")).context("no task")
    }

    /// Crash-consistent or quiesced snapshot of a VM, waited for: the snapshot's moref.
    pub fn create_snapshot(&self, vm: &MoRef, name: &str, quiesce: bool) -> Result<MoRef> {
        let task = self.task(&format!(
            "<urn:CreateSnapshot_Task>{}<urn:name>{}</urn:name><urn:description>NexusBackup</urn:description>\
             <urn:memory>false</urn:memory><urn:quiesce>{quiesce}</urn:quiesce></urn:CreateSnapshot_Task>",
            vm.xml("_this"),
            esc(name)
        ))?;
        self.wait(&task, Duration::from_secs(3600))?
            .context("CreateSnapshot_Task without a snapshot")
    }

    pub fn remove_snapshot(&self, snap: &MoRef) -> Result<()> {
        let task = self.task(&format!(
            "<urn:RemoveSnapshot_Task>{}<urn:removeChildren>false</urn:removeChildren></urn:RemoveSnapshot_Task>",
            snap.xml("_this")
        ))?;
        self.wait(&task, Duration::from_secs(3 * 3600)).map(|_| ())
    }

    /// Turns CBT on or off (`ctkEnabled`); it takes effect at the VM's next snapshot. Off and on again
    /// resets unclean tracking (a host crash or a hard power-off of a running VM): the next backup of
    /// the VM is then a full read.
    pub fn set_cbt(&self, vm: &MoRef, on: bool) -> Result<()> {
        let task = self.task(&format!(
            "<urn:ReconfigVM_Task>{}<urn:spec><urn:changeTrackingEnabled>{on}</urn:changeTrackingEnabled></urn:spec></urn:ReconfigVM_Task>",
            vm.xml("_this")
        ))?;
        self.wait(&task, Duration::from_secs(600)).map(|_| ())
    }

    /// `QueryChangedDiskAreas` over the whole disk: the changed extents `(offset, length)` since
    /// `change_id` (`"*"`: every allocated extent), merged where adjacent.
    pub fn changed_areas(&self, vm: &MoRef, snap: &MoRef, disk: &Disk, change_id: &str) -> Result<Vec<(u64, u64)>> {
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut off = 0u64;
        while off < disk.capacity {
            let t = self.call(&format!(
                "<urn:QueryChangedDiskAreas>{}{}<urn:deviceKey>{}</urn:deviceKey><urn:startOffset>{off}</urn:startOffset>\
                 <urn:changeId>{}</urn:changeId></urn:QueryChangedDiskAreas>",
                vm.xml("_this"),
                snap.xml("snapshot"),
                disk.key,
                esc(change_id)
            ))?;
            let doc = roxmltree::Document::parse(&t)?;
            let rv = doc
                .descendants()
                .find(|n| n.tag_name().name() == "returnval")
                .context("QueryChangedDiskAreas: no answer")?;
            for a in kids(rv, "changedArea") {
                let (Some(s), Some(l)) = (num::<u64>(a, "start"), num::<u64>(a, "length")) else {
                    continue;
                };
                match out.last_mut() {
                    Some(last) if last.0 + last.1 == s => last.1 += l,
                    _ => out.push((s, l)),
                }
            }
            let next = num(rv, "startOffset").unwrap_or(off) + num::<u64>(rv, "length").unwrap_or(0);
            if next <= off {
                break;
            }
            off = next;
        }
        Ok(out)
    }

    /// Hot-adds the disk file `file` (`[ds] dir/x.vmdk`, a snapshot's base) to the proxy VM at
    /// `controller_key`:`unit`, read-only for the disk (independent-nonpersistent: the proxy's
    /// writes would go to a redo log that is discarded).
    pub fn attach(&self, proxy: &MoRef, controller_key: i32, unit: i32, file: &str, capacity: u64) -> Result<()> {
        let task = self.task(&format!(
            r#"<urn:ReconfigVM_Task>{}<urn:spec><urn:deviceChange><urn:operation>add</urn:operation><urn:device xsi:type="urn:VirtualDisk"><urn:key>-100</urn:key><urn:backing xsi:type="urn:VirtualDiskFlatVer2BackingInfo"><urn:fileName>{}</urn:fileName><urn:diskMode>independent_nonpersistent</urn:diskMode></urn:backing><urn:controllerKey>{controller_key}</urn:controllerKey><urn:unitNumber>{unit}</urn:unitNumber><urn:capacityInKB>{}</urn:capacityInKB></urn:device></urn:deviceChange></urn:spec></urn:ReconfigVM_Task>"#,
            proxy.xml("_this"),
            esc(file),
            capacity / 1024
        ))?;
        self.wait(&task, Duration::from_secs(600)).map(|_| ())
    }

    /// Removes a hot-added disk from the proxy again, without a file operation: the disk file
    /// belongs to the protected VM and stays.
    pub fn detach(&self, proxy: &MoRef, disk: &Disk) -> Result<()> {
        let task = self.task(&format!(
            r#"<urn:ReconfigVM_Task>{}<urn:spec><urn:deviceChange><urn:operation>remove</urn:operation><urn:device xsi:type="urn:VirtualDisk"><urn:key>{}</urn:key><urn:backing xsi:type="urn:VirtualDiskFlatVer2BackingInfo"><urn:fileName>{}</urn:fileName><urn:diskMode>independent_nonpersistent</urn:diskMode></urn:backing><urn:controllerKey>{}</urn:controllerKey><urn:unitNumber>{}</urn:unitNumber><urn:capacityInKB>{}</urn:capacityInKB></urn:device></urn:deviceChange></urn:spec></urn:ReconfigVM_Task>"#,
            proxy.xml("_this"),
            disk.key,
            esc(&disk.file),
            disk.controller_key,
            disk.unit,
            disk.capacity / 1024
        ))?;
        self.wait(&task, Duration::from_secs(600)).map(|_| ())
    }

    pub fn logout(&self) {
        let _ = self.call(&format!(
            "<urn:Logout>{}</urn:Logout>",
            self.content.session_manager.xml("_this")
        ));
    }

    /// A read-only NFC ticket for a VM's files (`NfcGetVmFiles`): it opens the authd NFC service to read any of
    /// the VM's disk files (a snapshot's delta or base included) over NFC. Single-use: each call issues a new one.
    pub fn nfc_ticket(&self, vm: &MoRef) -> Result<NfcTicket> {
        // the NfcService moref differs between a host and vCenter
        let svc = if self.content.about.contains("vCenter") {
            "nfcService"
        } else {
            "ha-nfc"
        };
        let t = self.call(&format!(
            r#"<urn:NfcGetVmFiles><urn:_this type="NfcService">{svc}</urn:_this>{}</urn:NfcGetVmFiles>"#,
            vm.xml("vm")
        ))?;
        let doc = roxmltree::Document::parse(&t)?;
        let rv = doc
            .descendants()
            .find(|n| n.tag_name().name() == "returnval")
            .context("NfcGetVmFiles: no ticket in the answer")?;
        Ok(NfcTicket {
            host: text(kid(rv, "host"))
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| self.host.clone()),
            port: text(kid(rv, "port")).and_then(|p| p.parse().ok()).unwrap_or(902),
            ssl_thumbprint: text(kid(rv, "sslThumbprint")).context("NFC ticket without sslThumbprint")?,
            service: text(kid(rv, "service")).unwrap_or_else(|| "ha-nfc".into()),
            session_id: text(kid(rv, "sessionId")).context("NFC ticket without sessionId")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // trimmed from ESXi 8.0.3's answer for nx-cbt's snapshot (lab 2026-10-23)
    const DEVICES: &str = r#"<val xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ArrayOfVirtualDevice">
      <VirtualDevice xsi:type="VirtualIDEController"><key>200</key><busNumber>0</busNumber></VirtualDevice>
      <VirtualDevice xsi:type="ParaVirtualSCSIController"><key>1000</key><busNumber>0</busNumber></VirtualDevice>
      <VirtualDevice xsi:type="VirtualDisk"><key>2000</key>
        <backing xsi:type="VirtualDiskFlatVer2BackingInfo"><fileName>[datastore1] nx-cbt/nx-cbt-000001.vmdk</fileName>
          <diskMode>persistent</diskMode><changeId>52 9e 55 6b-7f 5c/7</changeId>
          <parent xsi:type="VirtualDiskFlatVer2BackingInfo"><fileName>[datastore1] nx-cbt/nx-cbt.vmdk</fileName></parent>
        </backing><controllerKey>1000</controllerKey><unitNumber>0</unitNumber>
        <capacityInKB>16777216</capacityInKB><capacityInBytes>17179869184</capacityInBytes></VirtualDevice>
      <VirtualDevice xsi:type="VirtualCdrom"><key>3000</key><controllerKey>200</controllerKey><unitNumber>0</unitNumber></VirtualDevice>
    </val>"#;

    #[test]
    fn disks_and_controllers() {
        let doc = roxmltree::Document::parse(DEVICES).unwrap();
        let disks = parse_disks(doc.root_element());
        assert_eq!(
            disks,
            [Disk {
                key: 2000,
                controller_key: 1000,
                unit: 0,
                capacity: 17_179_869_184,
                file: "[datastore1] nx-cbt/nx-cbt-000001.vmdk".into(),
                base_file: "[datastore1] nx-cbt/nx-cbt.vmdk".into(),
                change_id: Some("52 9e 55 6b-7f 5c/7".into()),
            }]
        );
        let c = parse_controllers(doc.root_element());
        assert!(c.contains(&Controller {
            key: 1000,
            bus: 0,
            kind: "scsi"
        }));
        assert!(c.contains(&Controller {
            key: 200,
            bus: 0,
            kind: "ide"
        }));
        assert_eq!(
            split_ds_path("[datastore1] nx-cbt/nx-cbt.vmx"),
            Some(("datastore1", "nx-cbt/nx-cbt.vmx"))
        );
    }

    #[test]
    fn requests_escape_their_values() {
        assert_eq!(esc(r#"a<b>&"c'"#), "a&lt;b&gt;&amp;&quot;c&apos;");
        assert_eq!(
            MoRef::new("VirtualMachine", "vm-<1>").xml("_this"),
            r#"<urn:_this type="VirtualMachine">vm-&lt;1&gt;</urn:_this>"#
        );
        assert!(envelope("<x/>").contains("<soapenv:Body><x/></soapenv:Body>"));
    }
}
