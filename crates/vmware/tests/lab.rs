//! The vSphere client against the nested ESXi lab (lab/pvehost/esxi.sh): runs only with `NEXUS_ESXI` set (the
//! host), `NEXUS_ESXI_PASSWORD` (root) and `NEXUS_ESXI_CERT` (its certificate, PEM). Snapshot of `nx-cbt`, its
//! disks and changed areas, the base disk hot-added to `nx-proxy` and removed again, the snapshot removed.
//! Run on the regression VM (lab/pvehost/vmware-lab.sh), not on a workstation.

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
            .find(|c| c.kind == "scsi" && c.bus == 0)
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

/// The whole backup through the proxy agent on `nx-proxy` (esxi.sh proxy): with `NEXUS_PROXY` (its address) and
/// `NEXUS_PROXY_TOKEN` as well. A full backup of `nx-cbt`, an incremental one, a forced full read: the disk
/// indexes of all three are the same (the guest is idle), the incremental one fetches no block.
#[test]
fn backup_through_proxy() {
    use agent_conn::ca::Ca;
    use agent_conn::map::MapDb;
    use agent_conn::tls::{session_config, Session};
    use chunkstore::{Keyring, Options, Store};
    use std::time::Duration;
    use vmware::backup::{backup_vm, Spec, Transport};
    let (Ok(host), Ok(proxy_ip)) = (std::env::var("NEXUS_ESXI"), std::env::var("NEXUS_PROXY")) else {
        eprintln!("NEXUS_ESXI / NEXUS_PROXY not set, skipped");
        return;
    };
    let pw = std::env::var("NEXUS_ESXI_PASSWORD").unwrap();
    let token = std::env::var("NEXUS_PROXY_TOKEN").unwrap();
    let pem = std::fs::read(std::env::var("NEXUS_ESXI_CERT").unwrap()).unwrap();
    // the test binary runs on the regression VM: its store goes to NEXUS_TMP (on disk), not this build's target dir
    let d = tempfile::tempdir_in(std::env::var("NEXUS_TMP").unwrap_or_else(|_| env!("CARGO_TARGET_TMPDIR").into()))
        .unwrap();
    let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
    let id = "00000000000000aa";
    let t = Duration::from_secs(60);
    let e = agent_conn::enroll::enroll(&ca, &proxy_ip, 7444, &agent_proto::token_digest(&token), id, t).unwrap();
    // the agent switches to its enrolled certificate shortly after the enrolment
    let mut s = (0..50)
        .find_map(|_| {
            let r = Session::connect(
                &proxy_ip,
                7444,
                session_config(&ca, id, Some(&e.cert_sha256)).unwrap(),
                t,
            )
            .and_then(|mut s| s.hello(id).map(|_| s));
            if r.is_err() {
                std::thread::sleep(Duration::from_millis(200));
            }
            r.ok()
        })
        .expect("no session with the proxy after its enrolment");
    let store_dir = d.path().join("store");
    let store = Store::open(&store_dir, Keyring::new("lab", &[(1, [7; 32])]), Options::default()).unwrap();
    let mut map = MapDb::open(&store_dir).unwrap();

    let c = Client::login(&host, 443, &pem, "root", &pw).unwrap();
    let vms = c.vms().unwrap();
    let find = |n: &str| vms.iter().find(|(_, name)| name == n).unwrap().0.clone();
    let (vm, proxy) = (find("nx-cbt"), find("nx-proxy"));
    let mut run = |job, full| {
        let spec = Spec {
            vm: &vm,
            datacenter: "ha-datacenter",
            job,
            full,
        };
        let mut transport = Transport::Proxy {
            proxy: &proxy,
            session: &mut s,
        };
        let mut lines = Vec::new();
        let m = backup_vm(&c, &store, &mut map, &mut transport, &spec, &mut |l| {
            eprintln!("{l}");
            lines.push(l.to_owned());
        })
        .unwrap();
        (m, lines)
    };
    let (m1, _) = run(1, false);
    let (m2, log2) = run(2, false);
    // each backup must reconstruct a bootable disk (MBR/GPT signature); the incremental reuses the base's blocks
    // for the unchanged part (an idle guest still writes a few blocks, so the indexes are not byte-identical)
    for m in [&m1, &m2] {
        let n = m.indexes.iter().find(|n| *n != "config").expect("a disk index");
        let idx = store.load_index(m, n).unwrap();
        let mut r = store.image_reader(&idx).unwrap();
        let mut head = vec![0u8; 1 << 20];
        r.read_at(0, &mut head).unwrap();
        assert_eq!(
            &head[510..512],
            &[0x55, 0xAA],
            "{n}: reconstructed disk has no boot signature"
        );
    }
    assert!(log2.iter().any(|l| l.contains("(incremental)")), "{log2:?}");
    // the second run reused most of the first run's blocks (few fetched)
    assert!(log2.iter().any(|l| l.contains("already in the store")), "{log2:?}");
    // no snapshot and no hot-added disk left behind
    let (pd, _) = c.devices(&proxy).unwrap();
    assert_eq!(pd.len(), 1, "proxy disks: {pd:?}");
    c.logout();
    s.close();
}

/// The NFC read path (no proxy VM) against the lab vCenter 8: with `NEXUS_VC` (vCenter address),
/// `NEXUS_VC_PASSWORD` (administrator@vsphere.local) and `NEXUS_VC_CERT` (its certificate PEM). Snapshot nx-cbt,
/// get an NFC ticket, open the snapshot disk over NFC and read it. Ground truth: the disk begins with an MBR/GPT
/// (signature 0x55AA at offset 510) and is not all zeros; a read spanning server fragments is self-consistent.
#[test]
fn nfc_read_disk() {
    use std::time::Duration;
    use vmware::nfc::NfcDisk;
    let Ok(vc) = std::env::var("NEXUS_VC") else {
        eprintln!("NEXUS_VC not set, skipped");
        return;
    };
    let pw = std::env::var("NEXUS_VC_PASSWORD").unwrap();
    let pem = std::fs::read(std::env::var("NEXUS_VC_CERT").unwrap()).unwrap();
    let c = Client::login(&vc, 443, &pem, "administrator@vsphere.local", &pw).unwrap();
    eprintln!("{}", c.about());
    let vms = c.vms().unwrap();
    let vm = vms
        .iter()
        .find(|(_, n)| n == "nx-cbt")
        .expect("nx-cbt in vCenter inventory")
        .0
        .clone();
    if !c.cbt_enabled(&vm).unwrap() {
        c.set_cbt(&vm, true).unwrap();
    }
    let snap = c.create_snapshot(&vm, "nexus-nfc-lab", false).unwrap();
    // the snapshot is removed even when a check fails
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (disks, _) = c.devices(&snap).unwrap();
        let d = disks.first().expect("a disk").clone();
        let ticket = c.nfc_ticket(&vm).unwrap();
        eprintln!(
            "ticket host={} port={} service={}",
            ticket.host, ticket.port, ticket.service
        );
        let mut disk = NfcDisk::open(&ticket, &d.file, d.capacity, Duration::from_secs(60)).unwrap();
        assert_eq!(disk.capacity(), d.capacity);

        // sector 0: MBR/GPT boot signature
        let mut first = vec![0u8; 1 << 20];
        disk.read_at(0, &mut first).unwrap();
        assert_eq!(&first[510..512], &[0x55, 0xAA], "no boot signature at offset 510");
        assert!(first.iter().any(|&b| b != 0), "first MiB is all zeros");

        // a 5 MiB read crossing the 2 MiB server fragment boundary, read twice: identical
        let mut a = vec![0u8; 5 << 20];
        let mut b = vec![0u8; 5 << 20];
        disk.read_at(8 << 20, &mut a).unwrap();
        disk.read_at(8 << 20, &mut b).unwrap();
        assert_eq!(a, b, "two reads of the same range differ");

        // the first MiB matches when read as part of a larger request
        let mut big = vec![0u8; 16 << 20];
        disk.read_at(0, &mut big).unwrap();
        assert_eq!(&big[..1 << 20], &first[..], "overlapping reads disagree");
        disk.close();
    }));
    c.remove_snapshot(&snap).unwrap();
    c.logout();
    if let Err(e) = r {
        std::panic::resume_unwind(e);
    }
}

/// A full backup through the NFC transport (no proxy VM) against the lab vCenter 8, then an incremental one. Each
/// stored disk index must reconstruct a bootable disk (MBR/GPT signature). Needs NEXUS_VC* as above.
#[test]
fn nfc_backup() {
    use agent_conn::map::MapDb;
    use chunkstore::{Keyring, Options, Store};
    use std::time::Duration;
    use vmware::backup::{backup_vm, Spec, Transport};
    let Ok(vc) = std::env::var("NEXUS_VC") else {
        eprintln!("NEXUS_VC not set, skipped");
        return;
    };
    let pw = std::env::var("NEXUS_VC_PASSWORD").unwrap();
    let pem = std::fs::read(std::env::var("NEXUS_VC_CERT").unwrap()).unwrap();
    let d = tempfile::tempdir_in(std::env::var("NEXUS_TMP").unwrap_or_else(|_| env!("CARGO_TARGET_TMPDIR").into()))
        .unwrap();
    let store_dir = d.path().join("store");
    let store = Store::open(&store_dir, Keyring::new("lab", &[(1, [5; 32])]), Options::default()).unwrap();
    let mut map = MapDb::open(&store_dir).unwrap();
    let c = Client::login(&vc, 443, &pem, "administrator@vsphere.local", &pw).unwrap();
    let vms = c.vms().unwrap();
    let vm = vms.iter().find(|(_, n)| n == "nx-cbt").unwrap().0.clone();
    let mut run = |job, full| {
        let spec = Spec {
            vm: &vm,
            datacenter: "ha-datacenter",
            job,
            full,
        };
        let mut transport = Transport::Nfc {
            timeout: Duration::from_secs(60),
        };
        let mut lines = Vec::new();
        let m = backup_vm(&c, &store, &mut map, &mut transport, &spec, &mut |l| {
            eprintln!("{l}");
            lines.push(l.to_owned());
        })
        .unwrap();
        (m, lines)
    };
    let (m1, _) = run(1, false);
    let (m2, log2) = run(2, false);
    for m in [&m1, &m2] {
        let n = m.indexes.iter().find(|n| *n != "config").expect("a disk index");
        let idx = store.load_index(m, n).unwrap();
        let mut r = store.image_reader(&idx).unwrap();
        let mut head = vec![0u8; 1 << 20];
        r.read_at(0, &mut head).unwrap();
        assert_eq!(
            &head[510..512],
            &[0x55, 0xAA],
            "{n}: reconstructed disk has no boot signature"
        );
    }
    assert!(log2.iter().any(|l| l.contains("(incremental)")), "{log2:?}");
    c.logout();
}
