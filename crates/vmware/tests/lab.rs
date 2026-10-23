//! The vSphere client against the nested ESXi lab (lab/pvehost/esxi.sh): runs only with `NEXUS_ESXI` set (the
//! host), `NEXUS_ESXI_PASSWORD` (root) and `NEXUS_ESXI_CERT` (its certificate, PEM). Snapshot of `nx-cbt`, its
//! disks and changed areas, the base disk hot-added to `nx-proxy` and removed again, the snapshot removed.

use vmware::vsphere::Client;

#[test]
fn snapshot_cbt_and_hot_add() {
    let Ok(host) = std::env::var("NEXUS_ESXI") else {
        eprintln!("NEXUS_ESXI not set, skipped");
        return;
    };
    let pw = std::env::var("NEXUS_ESXI_PASSWORD").unwrap();
    let pem = std::fs::read(std::env::var("NEXUS_ESXI_CERT").unwrap()).unwrap();
    let c = Client::login(&host, 443, &pem, "root", &pw).unwrap();
    eprintln!("{}", c.about());
    let vms = c.vms().unwrap();
    let find = |n: &str| {
        vms.iter()
            .find(|(_, name)| name == n)
            .unwrap_or_else(|| panic!("no VM {n}: {vms:?}"))
            .0
            .clone()
    };
    let (vm, proxy) = (find("nx-cbt"), find("nx-proxy"));
    if !c.cbt_enabled(&vm).unwrap() {
        c.set_cbt(&vm, true).unwrap();
    }
    let mut snap = c.create_snapshot(&vm, "nexus-backup-lab", false).unwrap();
    // a hard power-off of the lab leaves the tracking unclean: reset it, as the connector does
    let (disks, _) = c.devices(&snap).unwrap();
    if let Err(e) = c.changed_areas(&vm, &snap, &disks[0], "*") {
        eprintln!("resetting CBT: {e:#}");
        c.remove_snapshot(&snap).unwrap();
        c.set_cbt(&vm, false).unwrap();
        c.set_cbt(&vm, true).unwrap();
        snap = c.create_snapshot(&vm, "nexus-backup-lab", false).unwrap();
    }
    // the snapshot is removed even when a check fails
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (disks, _) = c.devices(&snap).unwrap();
        let d = disks.first().expect("nx-cbt has a disk").clone();
        assert!(d.capacity > 0 && d.base_file.ends_with(".vmdk"), "{d:?}");
        let id = d.change_id.clone().expect("CBT is on: a change id");
        let all = c.changed_areas(&vm, &snap, &d, "*").unwrap();
        let none = c.changed_areas(&vm, &snap, &d, &id).unwrap();
        eprintln!(
            "{}: {} extents allocated, {} changed since its own id",
            d.base_file,
            all.len(),
            none.len()
        );
        assert!(!all.is_empty() && none.is_empty());
        assert!(all.iter().all(|&(s, l)| l > 0 && s + l <= d.capacity));

        let (pd, pc) = c.devices(&proxy).unwrap();
        let scsi = pc
            .iter()
            .find(|c| c.scsi && c.bus == 0)
            .expect("proxy SCSI controller 0");
        let unit = (1..16)
            .find(|u| *u != 7 && !pd.iter().any(|x| x.controller_key == scsi.key && x.unit == *u))
            .unwrap();
        c.attach(&proxy, scsi.key, unit, &d.base_file, d.capacity).unwrap();
        let added = c
            .devices(&proxy)
            .unwrap()
            .0
            .into_iter()
            .find(|x| x.controller_key == scsi.key && x.unit == unit);
        let added = added.expect("the hot-added disk on the proxy");
        assert_eq!(added.file, d.base_file);
        c.detach(&proxy, &added).unwrap();
        assert!(!c.devices(&proxy).unwrap().0.iter().any(|x| x.file == d.base_file));
    }));
    c.remove_snapshot(&snap).unwrap();
    c.logout();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
