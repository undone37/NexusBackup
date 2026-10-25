//! Restore of an `xcp-<uuid>` snapshot into the pool as a new VM (docs/xcpng-design.md "Restore", M4): the VM made
//! from the "Other install media" template with the stored settings, one new VDI per stored disk on the chosen SR
//! filled over HTTP (`PUT /import_raw_vdi`), the NICs on the chosen network with new MACs. Never over the original.

use crate::xapi::Xapi;
use anyhow::{bail, Context, Result};
use chunkstore::{Index, Store};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use serde_json::{json, Value};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Where the restored VM goes: a new VM `name` (empty: the stored name plus " (restored)"), its disks on SR `sr`
/// and its NICs on network `network` (UUIDs; `None`: the pool's default SR, the management network).
pub struct Target<'a> {
    pub name: &'a str,
    pub sr: Option<&'a str>,
    pub network: Option<&'a str>,
}

/// The new VM's UUID.
pub fn restore_vm(x: &Xapi, store: &Store, source: &str, time: u64, t: &Target, timeout: Duration) -> Result<String> {
    if crate::names::parse_source_name(source).is_none() {
        bail!("{source}: not an XCP-ng VM snapshot");
    }
    let m = store.load_manifest(source, time)?;
    let Index::Dynamic { entries } = store.load_index(&m, "config")? else {
        bail!("{source}/{time}: config index is not dynamic");
    };
    let e = entries.iter().find(|e| e.path == "xcpng.json").context("xcpng.json")?;
    let mut b = Vec::new();
    store.write_chunks(&e.chunks, &mut b)?;
    let cfg: Value = serde_json::from_slice(&b).context("xcpng.json")?;
    let vmc = &cfg["vm"];
    let name = if t.name.is_empty() {
        format!("{} (restored)", vmc["name_label"].as_str().unwrap_or(source))
    } else {
        t.name.to_owned()
    };
    let sr = match t.sr {
        Some(u) => x.call("SR.get_by_uuid", &[json!(u)])?,
        None => {
            let pool = x.call("pool.get_all", &[])?[0].clone();
            x.call("pool.get_default_SR", &[pool])?
        }
    };
    let net = match t.network {
        Some(u) => x.call("network.get_by_uuid", &[json!(u)])?,
        None => {
            let pifs = x.call("PIF.get_all", &[])?;
            let mut mgmt = None;
            for p in pifs.as_array().context("PIF.get_all")? {
                if x.call("PIF.get_management", std::slice::from_ref(p))?.as_bool() == Some(true) {
                    mgmt = Some(x.call("PIF.get_network", std::slice::from_ref(p))?);
                    break;
                }
            }
            mgmt.context("no management network")?
        }
    };
    let tpl = x
        .call("VM.get_by_name_label", &[json!("Other install media")])?
        .as_array()
        .and_then(|a| a.first().cloned())
        .context("template \"Other install media\" not found")?;
    let vm = x.call("VM.clone", &[tpl, json!(name)])?;
    let mut vdis = Vec::new();
    let r = build(x, store, &m, &cfg, &vm, &sr, &net, &mut vdis, timeout);
    if let Err(e) = r {
        // nothing half-restored stays in the pool
        let _ = x.call("VM.destroy", std::slice::from_ref(&vm));
        for v in vdis {
            let _ = x.call("VDI.destroy", &[v]);
        }
        return Err(e.context(format!("restore of {source}/{time} into the pool")));
    }
    Ok(x.call("VM.get_uuid", &[vm])?.as_str().unwrap_or_default().to_owned())
}

#[allow(clippy::too_many_arguments)]
fn build(
    x: &Xapi,
    store: &Store,
    m: &chunkstore::Manifest,
    cfg: &Value,
    vm: &Value,
    sr: &Value,
    net: &Value,
    vdis: &mut Vec<Value>,
    timeout: Duration,
) -> Result<()> {
    let vmc = &cfg["vm"];
    let s = |v: &Value| v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string());
    x.call("VM.set_is_a_template", &[vm.clone(), json!(false)])?;
    let mem = s(&vmc["memory_static_max"]);
    x.call(
        "VM.set_memory_limits",
        &[vm.clone(), json!(mem), json!(mem), json!(mem), json!(mem)],
    )?;
    let cpus = s(&vmc["VCPUs_max"]);
    x.call("VM.set_VCPUs_max", &[vm.clone(), json!(cpus)])?;
    x.call("VM.set_VCPUs_at_startup", &[vm.clone(), json!(cpus)])?;
    for (k, f) in [
        ("platform", "VM.set_platform"),
        ("HVM_boot_params", "VM.set_HVM_boot_params"),
        ("HVM_boot_policy", "VM.set_HVM_boot_policy"),
        ("name_description", "VM.set_name_description"),
    ] {
        if !vmc[k].is_null() {
            x.call(f, &[vm.clone(), vmc[k].clone()])?;
        }
    }
    if let Some(t) = vmc["other_config"]["base_template_name"].as_str() {
        // the template's own value comes with the clone
        x.call(
            "VM.remove_from_other_config",
            &[vm.clone(), json!("base_template_name")],
        )?;
        x.call(
            "VM.add_to_other_config",
            &[vm.clone(), json!("base_template_name"), json!(t)],
        )?;
    }
    let name = x.call("VM.get_name_label", std::slice::from_ref(vm))?;
    for d in cfg["disks"].as_array().context("xcpng.json: disks")? {
        let disk = d["name"].as_str().context("disk name")?;
        let Index::Fixed { size, chunks, .. } = store.load_index(m, disk)? else {
            bail!("{disk}: not a disk image");
        };
        let vdi = x.call(
            "VDI.create",
            &[
                json!({"name_label": format!("{} {disk}", name.as_str().unwrap_or("")), "name_description": "",
                     "SR": sr, "virtual_size": size.to_string(), "type": "user", "sharable": false,
                     "read_only": false, "other_config": {}, "xenstore_data": {}, "sm_config": {}, "tags": []}),
            ],
        )?;
        vdis.push(vdi.clone());
        import_raw(x, vdi.as_str().context("VDI ref")?, size, timeout, |w| {
            store.write_chunks(&chunks, w)
        })
        .with_context(|| format!("{disk}: upload"))?;
        let dev = d["userdevice"].as_str().unwrap_or("0");
        x.call(
            "VBD.create",
            &[
                json!({"VM": vm, "VDI": vdi, "userdevice": dev, "bootable": dev == "0", "mode": "RW",
                     "type": "Disk", "empty": false, "other_config": {}, "qos_algorithm_type": "",
                     "qos_algorithm_params": {}}),
            ],
        )?;
    }
    for v in cfg["vifs"].as_array().into_iter().flatten() {
        // new MACs: the original VM may still run on the same network
        x.call(
            "VIF.create",
            &[
                json!({"device": v["device"], "network": net, "VM": vm, "MAC": "", "MTU": "1500",
                     "other_config": {}, "qos_algorithm_type": "", "qos_algorithm_params": {},
                     "locking_mode": "network_default", "ipv4_allowed": [], "ipv6_allowed": []}),
            ],
        )?;
    }
    Ok(())
}

/// `PUT /import_raw_vdi?vdi=<ref>&format=raw` on the pool master with `size` bytes from `body`. ponytail: the whole
/// image goes over the wire, zeros included; `format=vhd` with only the allocated blocks if restores get slow.
fn import_raw(
    x: &Xapi,
    vdi: &str,
    size: u64,
    timeout: Duration,
    body: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
) -> Result<()> {
    let tcp = TcpStream::connect((x.host.as_str(), x.port)).with_context(|| format!("connect {}", x.host))?;
    tcp.set_read_timeout(Some(timeout.max(Duration::from_secs(600))))?;
    tcp.set_write_timeout(Some(timeout))?;
    let name = ServerName::try_from(x.host.clone()).context("server name")?;
    let mut tls = StreamOwned::new(ClientConnection::new(x.tls.clone(), name)?, tcp);
    write!(
        tls,
        "PUT /import_raw_vdi?session_id={}&vdi={vdi}&format=raw HTTP/1.1\r\nHost: {}\r\nContent-Length: {size}\r\n\
         Connection: close\r\n\r\n",
        x.session(),
        x.host
    )?;
    let mut w = std::io::BufWriter::with_capacity(1 << 20, &mut tls);
    body(&mut w)?;
    w.flush()?;
    drop(w);
    // the whole response until XAPI closes: closing earlier skips its detach of the VDI from dom0 (left plugged,
    // the VDI cannot be destroyed or used)
    let mut resp = String::new();
    BufReader::new(&mut tls).read_to_string(&mut resp).or_else(|e| {
        // XAPI closes without TLS close_notify
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Ok(0)
        } else {
            Err(e)
        }
    })?;
    let status = resp.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        bail!("import_raw_vdi: {}", status.trim());
    }
    Ok(())
}
