//! "Restore as PVE VM" (P2V, docs/bmr.md): a VM with one disk per disk of the
//! snapshot's machine layout (same size, rounded up to GiB), UEFI if the original
//! booted UEFI, the rescue ISO and a small config disk (ISO 9660, label NEXUSCFG,
//! `rescue.json` with the appliance address and the one-time recovery token). The
//! rescue system boots, checks in, and the appliance recovers the machine onto the
//! VM's disks unattended. Boot order disk-then-CD: the empty disk falls through to
//! the rescue ISO, the restored disk boots after the rescue's reboot.

use crate::api::Api;
use agent_proto::layout::Layout;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Deserialize, Debug)]
pub struct Req {
    pub session: String,
    pub node: String,
    #[serde(default)]
    pub vmid: u32,
    #[serde(default)]
    pub name: String,
    pub storage: String,
    pub iso: String,
    pub iso_storage: String,
    pub bridge: String,
    pub memory: u32,
    pub cores: u32,
    /// the rescue config written onto the config disk
    pub rescue: Value,
    #[serde(flatten)]
    pub _rest: serde_json::Map<String, Value>,
}

/// File name of the config disk on the ISO storage.
pub fn config_iso_name(session: &str) -> String {
    format!("nexus-rescue-cfg-{session}.iso")
}

/// DNS-safe VM name from the layout's host name.
pub fn vm_name(req: &Req, l: &Layout) -> String {
    let base = if req.name.is_empty() { &l.hostname } else { &req.name };
    let n: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(50)
        .collect();
    if n.is_empty() {
        "nexus-p2v".into()
    } else {
        format!("{n}-p2v")
    }
}

/// `POST /nodes/{node}/qemu` parameters.
pub fn vm_params(req: &Req, l: &Layout, vmid: u32, config_volid: &str) -> Result<Vec<(String, String)>> {
    if l.disks.is_empty() {
        bail!("the snapshot's layout records no disks");
    }
    if l.disks.len() > 30 {
        bail!("{} disks: more than a VM's SCSI bus takes", l.disks.len());
    }
    let mut p: Vec<(String, String)> = vec![
        ("vmid".into(), vmid.to_string()),
        ("name".into(), vm_name(req, l)),
        ("memory".into(), req.memory.to_string()),
        ("cores".into(), req.cores.to_string()),
        ("machine".into(), "q35".into()),
        ("ostype".into(), "l26".into()),
        ("scsihw".into(), "virtio-scsi-single".into()),
        ("net0".into(), format!("virtio,bridge={}", req.bridge)),
        ("ide2".into(), format!("{},media=cdrom", req.iso)),
        ("ide3".into(), format!("{config_volid},media=cdrom")),
        ("boot".into(), "order=scsi0;ide2".into()),
        (
            "description".into(),
            format!("NexusBackup P2V of {} (rescue session {})", l.hostname, req.session),
        ),
    ];
    for (i, d) in l.disks.iter().enumerate() {
        let gib = d.size.div_ceil(1 << 30).max(1);
        p.push((format!("scsi{i}"), format!("{}:{gib}", req.storage)));
    }
    if l.firmware == "uefi" {
        p.push(("bios".into(), "ovmf".into()));
        p.push((
            "efidisk0".into(),
            format!("{}:1,efitype=4m,pre-enrolled-keys=0", req.storage),
        ));
    }
    Ok(p)
}

/// `nexus-pve <cfg> p2v <p2v.json> <layout.json>`
pub fn run(api: &Api, req: &Req, l: &Layout) -> Result<()> {
    let vmid = if req.vmid != 0 {
        req.vmid
    } else {
        let v = api.get("/cluster/nextid")?;
        v.as_str()
            .and_then(|s| s.parse().ok())
            .or(v.as_u64().map(|n| n as u32))
            .context("cluster/nextid")?
    };
    let cfg = serde_json::to_vec_pretty(&req.rescue)?;
    let iso = iso9660("NEXUSCFG", &[("RESCUE.JSON", &cfg)]);
    let file = config_iso_name(&req.session);
    let volid = format!("{}:iso/{file}", req.iso_storage);
    println!("uploading the config disk {volid}");
    let upid = api.upload(
        &format!("/nodes/{}/storage/{}/upload", req.node, req.iso_storage),
        "iso",
        &file,
        &iso,
    )?;
    if let Some(u) = upid {
        api.run_task(&req.node, &u, Duration::from_secs(300))?;
    }
    // recorded before the VM exists: cleanup finds the config disk even if creation fails
    println!(
        "p2v-vm {}",
        json!({"vmid": vmid, "node": req.node, "config_volid": volid})
    );
    let params = vm_params(req, l, vmid, &volid)?;
    println!(
        "creating VM {vmid} on {}: {} disk(s), {} firmware",
        req.node,
        l.disks.len(),
        if l.firmware == "uefi" { "UEFI" } else { "BIOS" }
    );
    let form: Vec<(&str, &str)> = params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let upid = api.post_task(&format!("/nodes/{}/qemu", req.node), &form)?;
    api.run_task(&req.node, &upid, Duration::from_secs(900))?;
    api.guest_power(&req.node, "qemu", vmid, "start", &[])?;
    println!("VM {vmid} started from the rescue ISO; it checks in with the appliance and is recovered unattended");
    Ok(())
}

/// `nexus-pve <cfg> p2v-cleanup <node> <vmid> <volid>`: config disk detached and deleted.
pub fn cleanup(api: &Api, node: &str, vmid: u32, volid: &str) -> Result<()> {
    if let Err(e) = api.set_config(node, "qemu", vmid, &[("ide3".into(), None)]) {
        eprintln!("detaching the config disk: {e:#}");
    }
    let (storage, _) = volid.split_once(':').context("volid")?;
    api.delete(&format!("/nodes/{node}/storage/{storage}/content/{volid}"))?;
    println!("config disk {volid} removed");
    Ok(())
}

fn both16(v: u16) -> [u8; 4] {
    let (l, b) = (v.to_le_bytes(), v.to_be_bytes());
    [l[0], l[1], b[0], b[1]]
}

fn both32(v: u32) -> [u8; 8] {
    let (l, b) = (v.to_le_bytes(), v.to_be_bytes());
    [l[0], l[1], l[2], l[3], b[0], b[1], b[2], b[3]]
}

fn dir_record(name: &[u8], extent: u32, len: u32, dir: bool) -> Vec<u8> {
    let mut r = vec![0u8; 33];
    r[2..10].copy_from_slice(&both32(extent));
    r[10..18].copy_from_slice(&both32(len));
    r[18..25].copy_from_slice(&[126, 1, 1, 0, 0, 0, 0]); // 2026-01-01
    r[25] = if dir { 2 } else { 0 };
    r[28..32].copy_from_slice(&both16(1));
    r[32] = name.len() as u8;
    r.extend_from_slice(name);
    if r.len() % 2 == 1 {
        r.push(0);
    }
    r[0] = r.len() as u8;
    r
}

fn padded(s: &str, n: usize) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.resize(n, b' ');
    v
}

/// Minimal ISO 9660 image: one root directory with the given files (names in
/// 8.3-ish upper case, `;1` appended), files below 2 KiB × 2^31. Enough for the
/// config disk; Linux shows the names in lower case.
pub fn iso9660(label: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    const S: usize = 2048;
    let sectors = |n: usize| n.div_ceil(S).max(1);
    let root_lba = 20u32;
    let mut lba = root_lba + 1;
    let mut recs = vec![
        dir_record(&[0], root_lba, S as u32, true),
        dir_record(&[1], root_lba, S as u32, true),
    ];
    let mut data = vec![];
    for (name, body) in files {
        recs.push(dir_record(
            format!("{name};1").as_bytes(),
            lba,
            body.len() as u32,
            false,
        ));
        data.push((lba, *body));
        lba += sectors(body.len()) as u32;
    }
    let total = lba as usize;
    let mut img = vec![0u8; total * S];
    // primary volume descriptor
    let pvd = &mut img[16 * S..17 * S];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[8..40].copy_from_slice(&padded("LINUX", 32));
    pvd[40..72].copy_from_slice(&padded(label, 32));
    pvd[80..88].copy_from_slice(&both32(total as u32));
    pvd[120..124].copy_from_slice(&both16(1));
    pvd[124..128].copy_from_slice(&both16(1));
    pvd[128..132].copy_from_slice(&both16(S as u16));
    pvd[132..140].copy_from_slice(&both32(10));
    pvd[140..144].copy_from_slice(&18u32.to_le_bytes());
    pvd[148..152].copy_from_slice(&19u32.to_be_bytes());
    pvd[156..190].copy_from_slice(&recs[0][..34]);
    for (off, len) in [
        (190, 128),
        (318, 128),
        (446, 128),
        (574, 128),
        (702, 37),
        (739, 37),
        (776, 37),
    ] {
        pvd[off..off + len].copy_from_slice(&padded("", len));
    }
    for off in [813, 830, 847, 864] {
        pvd[off..off + 16].copy_from_slice(b"2026010100000000");
    }
    pvd[881] = 1;
    // terminator
    let t = &mut img[17 * S..18 * S];
    t[0] = 255;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 1;
    // path tables (root only): L at 18, M at 19
    for (sec, le) in [(18, true), (19, false)] {
        let p = &mut img[sec * S..sec * S + 10];
        p[0] = 1;
        p[2..6].copy_from_slice(&if le {
            root_lba.to_le_bytes()
        } else {
            root_lba.to_be_bytes()
        });
        p[6..8].copy_from_slice(&if le { 1u16.to_le_bytes() } else { 1u16.to_be_bytes() });
    }
    let mut off = root_lba as usize * S;
    for r in &recs {
        img[off..off + r.len()].copy_from_slice(r);
        off += r.len();
    }
    for (lba, body) in data {
        let o = lba as usize * S;
        img[o..o + body.len()].copy_from_slice(body);
    }
    img
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_proto::layout::Disk;

    fn req() -> Req {
        serde_json::from_value(json!({
            "session": "fedcba9876543210", "node": "pve1", "vmid": 0, "name": "", "storage": "local-lvm",
            "iso": "local:iso/nexus-rescue-0.2.0.iso", "iso_storage": "local", "bridge": "vmbr0",
            "memory": 2048, "cores": 2, "source_id": 3, "rescue": {"token": "T"}
        }))
        .unwrap()
    }

    #[test]
    fn vm_parameters_from_layout() {
        let l = Layout {
            hostname: "Web01.example".into(),
            firmware: "uefi".into(),
            disks: vec![
                Disk {
                    size: (12 << 30) + 1,
                    ..Default::default()
                },
                Disk {
                    size: 8 << 30,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let p = vm_params(&req(), &l, 123, "local:iso/x.iso").unwrap();
        let get = |k: &str| p.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
        assert_eq!(get("name"), Some("web01-example-p2v"));
        assert_eq!(get("scsi0"), Some("local-lvm:13"), "rounded up: never smaller");
        assert_eq!(get("scsi1"), Some("local-lvm:8"));
        assert_eq!(get("bios"), Some("ovmf"));
        assert!(get("efidisk0").unwrap().contains("pre-enrolled-keys=0"));
        assert_eq!(get("boot"), Some("order=scsi0;ide2"));
        assert_eq!(get("ide3"), Some("local:iso/x.iso,media=cdrom"));
        let bios = Layout {
            firmware: "bios".into(),
            ..l
        };
        assert!(vm_params(&req(), &bios, 1, "v")
            .unwrap()
            .iter()
            .all(|(k, _)| k != "bios"));
        assert!(vm_params(&req(), &Layout::default(), 1, "v").is_err());
    }

    #[test]
    fn config_disk_iso() {
        let body = br#"{"token":"T"}"#;
        let img = iso9660("NEXUSCFG", &[("RESCUE.JSON", body)]);
        assert_eq!(img.len() % 2048, 0);
        assert_eq!(&img[16 * 2048 + 1..16 * 2048 + 6], b"CD001");
        assert_eq!(&img[16 * 2048 + 40..16 * 2048 + 48], b"NEXUSCFG");
        assert_eq!(&img[21 * 2048..21 * 2048 + body.len()], body);
        // cross-check with xorriso where installed
        let Ok(dir) = tempfile::tempdir() else { return };
        let iso = dir.path().join("c.iso");
        std::fs::write(&iso, &img).unwrap();
        let out = std::process::Command::new("xorriso")
            .args(["-indev", iso.to_str().unwrap(), "-pvd_info", "-ls", "/"])
            .output();
        if let Ok(o) = out {
            let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
            assert!(text.contains("NEXUSCFG"), "{text}");
            assert!(text.contains("RESCUE.JSON"), "{text}");
        }
    }
}
