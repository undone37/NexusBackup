//! Against the TrueNAS lab VM (lab/truenas/, skipped unless configured):
//!
//! ```sh
//! NEXUS_TRUENAS_LAB=/home/ah/nexus-lab/truenas/lab-cli.json \
//! NEXUS_TRUENAS_STORE=/home/ah/nexus-lab/truenas/store \
//! NEXUS_TRUENAS_SUMS=<output of `sh.py data.sh sums`> \
//!   cargo test -p truenas --test lab -- --nocapture
//! ```
//! One backup round with the real API client, SSH forced command, sudo and
//! `zfs allow`; every regular file of the new trees must match the sums taken
//! on TrueNAS. The store keeps its state between runs (incremental rounds).

mod support;

use chunkstore::{Index, Keyring, Options, Store, TreeKind};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use truenas::api::{Api, ApiConfig, Nas};
use truenas::backup::{backup, Spec};
use truenas::remote::Ssh;

fn cfg() -> Option<serde_json::Value> {
    let p = std::env::var("NEXUS_TRUENAS_LAB").ok()?;
    Some(serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
}

#[test]
fn lab_backup_round() {
    let Some(c) = cfg() else {
        eprintln!("NEXUS_TRUENAS_LAB not set: skipped");
        return;
    };
    let s = |v: &serde_json::Value| v.as_str().unwrap().to_owned();
    let a = &c["api"];
    let mut api = Api::connect(&ApiConfig {
        host: s(&a["host"]),
        port: a["port"].as_u64().unwrap() as u16,
        connect_addr: a["connect_addr"].as_str().map(|x| x.parse().unwrap()),
        ca_pem: std::fs::read(s(&a["ca_file"])).unwrap(),
        user: s(&a["user"]),
        api_key: std::fs::read_to_string(s(&a["key_file"])).unwrap().trim().to_owned(),
        timeout: std::time::Duration::from_secs(120),
    })
    .unwrap();
    let h = &c["ssh"];
    let ssh = Ssh {
        host: s(&h["host"]),
        port: h["port"].as_u64().unwrap() as u16,
        user: s(&h["user"]),
        key: s(&h["key_file"]).into(),
        known_hosts: s(&h["known_hosts_file"]).into(),
    };
    let store_dir = std::env::var("NEXUS_TRUENAS_STORE").unwrap();
    let store = Store::open(&store_dir, Keyring::new("lab", &[(1, [5; 32])]), Options::default()).unwrap();
    let spec = Spec {
        source_id: c["source_id"].as_u64().unwrap(),
        datasets: c["datasets"].as_array().unwrap().iter().map(s).collect(),
        recursive: c["recursive"].as_bool().unwrap_or(false),
    };
    let t = std::time::Instant::now();
    let r = backup(&store, &mut api, &ssh, &spec, &mut |l| println!("{l}")).unwrap();
    println!("round: {:.1?}", t.elapsed());
    for d in &r.committed {
        println!("report {}", serde_json::to_string(d).unwrap());
    }
    println!("deleted {:?}", r.deleted_snapshots);
    assert!(r.failed.is_empty(), "{:?}", r.failed);
    // rotation: exactly one snapshot of this source per dataset is left
    for d in &r.committed {
        let ours: Vec<String> = api
            .snapshots(&d.dataset)
            .unwrap()
            .into_iter()
            .filter(|n| truenas::parse_snap_name(spec.source_id, n).is_some())
            .collect();
        assert_eq!(ours, vec![truenas::snap_name(spec.source_id, r.time)], "{}", d.dataset);
    }
    if let Ok(f) = std::env::var("NEXUS_TRUENAS_SUMS") {
        let want = support::sums(&std::fs::read_to_string(f).unwrap());
        for d in &r.committed {
            let m = store.load_manifest(&d.source, d.time).unwrap();
            let Index::Tree { entries } = store.load_index(&m, "tree").unwrap() else {
                panic!()
            };
            let mut got = BTreeMap::new();
            for e in entries.iter().filter(|e| e.kind == TreeKind::File) {
                let mut h = Sha256::new();
                let mut rd = store.chunk_reader(&e.chunks);
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let n = rd.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                got.insert(e.path.clone(), format!("{:x}", h.finalize()));
            }
            // hard links: the second name is a Hardlink entry; sums list every name
            let links: BTreeMap<Vec<u8>, Vec<u8>> = entries
                .iter()
                .filter(|e| e.kind == TreeKind::Hardlink)
                .map(|e| (e.path.clone(), e.link_target.clone().unwrap()))
                .collect();
            for (l, target) in &links {
                let v = got[target].clone();
                got.insert(l.clone(), v);
            }
            let exp = want.get(&d.dataset).cloned().unwrap_or_default();
            assert_eq!(got.len(), exp.len(), "{}: file count", d.dataset);
            for (p, hsum) in &exp {
                assert_eq!(got.get(p), Some(hsum), "{}: {}", d.dataset, String::from_utf8_lossy(p));
            }
            println!("verified {} files of {}", exp.len(), d.dataset);
        }
    }
    // xattrs (POSIX ACLs, NFSv4 ACLs, user.*) against `getfattr -d -m - -e hex` on TrueNAS
    if let Ok(f) = std::env::var("NEXUS_TRUENAS_XATTRS") {
        let text = std::fs::read_to_string(f).unwrap();
        let mut want: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
        let (mut ds, mut file) = (String::new(), String::new());
        for l in text.lines() {
            if let Some(d) = l.strip_prefix("== ") {
                ds = format!("tank/{d}");
            } else if let Some(p) = l.strip_prefix("# file: ") {
                file = p.to_owned();
            } else if let Some((k, v)) = l.split_once("=0x") {
                want.entry((ds.clone(), file.clone()))
                    .or_default()
                    .push((k.to_owned(), v.to_owned()));
            }
        }
        let mut checked = 0;
        for d in &r.committed {
            let m = store.load_manifest(&d.source, d.time).unwrap();
            let Index::Tree { entries } = store.load_index(&m, "tree").unwrap() else {
                panic!()
            };
            for e in &entries {
                let p = String::from_utf8_lossy(&e.path).into_owned();
                let mut got: Vec<(String, String)> = e
                    .xattrs
                    .iter()
                    .map(|(k, v)| {
                        (
                            String::from_utf8_lossy(k).into_owned(),
                            v.iter().map(|b| format!("{b:02x}")).collect(),
                        )
                    })
                    .collect();
                got.sort();
                let mut exp = want.get(&(d.dataset.clone(), p.clone())).cloned().unwrap_or_default();
                exp.sort();
                if p.contains('\\') || p.contains('\n') || e.kind == TreeKind::Symlink {
                    continue; // getfattr escapes such names; symlinks are not read
                }
                assert_eq!(got, exp, "{}: {p}", d.dataset);
                checked += usize::from(!exp.is_empty());
            }
        }
        println!("verified xattrs of {checked} entries");
        assert!(checked >= 3);
    }
    api.close();
}
