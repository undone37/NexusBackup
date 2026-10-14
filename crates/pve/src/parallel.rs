//! Several guests of one `backup-all` at once (group `parallel_guests`,
//! docs/pve-connector.md "Parallel guests"): up to `n` workers, each takes the
//! next guest on the node with the fewest running backups, so the load spreads
//! over the cluster (PVE may serialise vzdump runs on one node with its global
//! vzdump lock: guests of that node then simply wait for each other).
//!
//! Per-storage caps (source `storage_caps`, Phase 22b): a guest with a disk on a
//! storage that already has its cap of running backups waits; other guests pass it.
//!
//! Lock files (Phase 32): an item runs only while it holds all of its `locks`
//! (`File::try_lock`, exclusive), across every `nexus-pve` process of the
//! appliance: one per node (PVE runs one vzdump per node anyway, so a second
//! backup there would only wait inside its task, holding a worker) and one per
//! guest (a guest in two groups is never backed up twice at once). A worker
//! whose candidates are all locked by another process looks again every
//! [`RETRY`].

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// How often a worker looks again for an item whose locks another process holds.
pub const RETRY: Duration = Duration::from_secs(2);

/// One guest to back up: its node, the PVE storages of its disks and the lock
/// files it must hold while it runs.
pub struct Item<T> {
    pub item: T,
    pub node: String,
    pub storages: Vec<String>,
    pub locks: Vec<PathBuf>,
}

/// All of `paths`, exclusively, or none (one is held elsewhere or unusable).
fn try_lock_all(paths: &[PathBuf]) -> Option<Vec<File>> {
    let mut held = Vec::new();
    for p in paths {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(p)
            .ok()?;
        f.try_lock().ok()?;
        held.push(f);
    }
    Some(held)
}

#[derive(Default)]
struct State {
    pending: Vec<usize>,
    /// running backups per node and per storage
    nodes: HashMap<String, usize>,
    storages: HashMap<String, usize>,
}

/// Index into `pending` of the next item with its locks: the first one whose
/// node has the fewest running backups among those whose storages are all below
/// their cap and whose lock files are free.
fn pick<T>(st: &State, items: &[Item<T>], caps: &HashMap<String, usize>) -> Option<(usize, Vec<File>)> {
    let mut cands: Vec<(usize, usize)> = st
        .pending
        .iter()
        .enumerate()
        .filter(|(_, &i)| {
            items[i].storages.iter().all(|s| {
                caps.get(s)
                    .is_none_or(|c| st.storages.get(s).copied().unwrap_or(0) < (*c).max(1))
            })
        })
        .map(|(pos, &i)| (pos, i))
        .collect();
    cands.sort_by_key(|&(pos, i)| (st.nodes.get(&items[i].node).copied().unwrap_or(0), pos));
    cands
        .into_iter()
        .find_map(|(pos, i)| try_lock_all(&items[i].locks).map(|held| (pos, held)))
}

/// Runs `work` for every item with at most `n` at once and at most `caps[s]`
/// running on storage `s`; results in item order.
pub fn run<T: Sync, R: Send>(
    items: &[Item<T>],
    n: usize,
    caps: &HashMap<String, usize>,
    work: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let state = Mutex::new(State {
        pending: (0..items.len()).collect(),
        ..Default::default()
    });
    let freed = Condvar::new();
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..n.clamp(1, items.len().max(1)) {
            s.spawn(|| loop {
                let i = {
                    let mut st = state.lock().unwrap();
                    let picked = loop {
                        if st.pending.is_empty() {
                            break None;
                        }
                        match pick(&st, items, caps) {
                            Some(p) => break Some(p),
                            // every pending guest waits for a capped storage or a lock
                            // (another process frees those without notifying: look again)
                            None => st = freed.wait_timeout(st, RETRY).unwrap().0,
                        }
                    };
                    let Some((pos, held)) = picked else { break };
                    let i = st.pending.remove(pos);
                    *st.nodes.entry(items[i].node.clone()).or_default() += 1;
                    for x in &items[i].storages {
                        *st.storages.entry(x.clone()).or_default() += 1;
                    }
                    (i, held)
                };
                let (i, held) = i;
                let r = work(&items[i].item);
                drop(held);
                let mut st = state.lock().unwrap();
                *st.nodes.entry(items[i].node.clone()).or_default() -= 1;
                for x in &items[i].storages {
                    *st.storages.entry(x.clone()).or_default() -= 1;
                }
                results.lock().unwrap()[i] = Some(r);
                drop(st);
                freed.notify_all();
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|r| r.expect("every item ran"))
        .collect()
}

/// PVE storages of a guest config (`/nodes/<n>/qemu|lxc/<id>/config`): the
/// storage of every disk volume (VM disks, container rootfs / mount points);
/// CD-ROMs, `none` and bind mounts (absolute paths) are not storages.
pub fn guest_storages(cfg: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut out: Vec<String> = cfg
        .iter()
        .filter(|(k, _)| crate::ir::is_disk_key(k) || *k == "rootfs" || is_mp(k))
        .filter_map(|(_, v)| v.as_str())
        .filter(|v| !v.split(',').any(|o| o == "media=cdrom"))
        .filter_map(|v| v.split(',').next()?.split_once(':').map(|(s, _)| s.to_owned()))
        .filter(|s| !s.is_empty() && !s.starts_with('/'))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn is_mp(k: &str) -> bool {
    k.strip_prefix("mp")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn it(i: u32, node: &str, storages: &[&str]) -> Item<u32> {
        Item {
            item: i,
            node: node.into(),
            storages: storages.iter().map(|s| s.to_string()).collect(),
            locks: Vec::new(),
        }
    }

    #[test]
    fn lock_files_serialise_across_workers_and_processes() {
        let d = tempfile::tempdir().unwrap();
        let (na, nb, g1) = (
            d.path().join("node-a"),
            d.path().join("node-b"),
            d.path().join("guest-1"),
        );
        let with = |i: u32, locks: &[&std::path::PathBuf]| Item {
            locks: locks.iter().map(|p| p.to_path_buf()).collect(),
            ..it(i, "x", &[])
        };
        // 0 and 1 share node a; 2 is on node b but its guest lock is held by "another process"
        let items = [with(0, &[&na]), with(1, &[&na]), with(2, &[&nb, &g1])];
        let other = File::create(&g1).unwrap();
        other.lock().unwrap();
        let on_a = AtomicUsize::new(0);
        let max_a = AtomicUsize::new(0);
        let order = Mutex::new(Vec::new());
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(other); // the other process ends
        });
        run(&items, 3, &HashMap::new(), |&i| {
            if i < 2 {
                let n = on_a.fetch_add(1, Ordering::SeqCst) + 1;
                max_a.fetch_max(n, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(100));
                on_a.fetch_sub(1, Ordering::SeqCst);
            }
            order.lock().unwrap().push(i);
        });
        releaser.join().unwrap();
        assert_eq!(max_a.load(Ordering::SeqCst), 1, "one backup per node at a time");
        assert_eq!(
            order.into_inner().unwrap().last(),
            Some(&2),
            "waited for the other process' lock"
        );
    }

    #[test]
    fn picks_the_least_busy_node_in_order() {
        let items = [it(0, "a", &[]), it(1, "a", &[]), it(2, "b", &[]), it(3, "c", &[])];
        let caps = HashMap::new();
        let mut st = State {
            pending: vec![0, 1, 2, 3],
            ..Default::default()
        };
        assert_eq!(pick(&st, &items, &caps).map(|p| p.0), Some(0), "idle: list order");
        st.pending = vec![1, 2, 3];
        st.nodes.insert("a".into(), 1);
        assert_eq!(pick(&st, &items, &caps).map(|p| p.0), Some(1), "b before the busy a");
        st.nodes.insert("b".into(), 1);
        st.nodes.insert("c".into(), 2);
        st.pending = vec![1, 3];
        assert_eq!(pick(&st, &items, &caps).map(|p| p.0), Some(0), "a(1) before c(2)");
        st.pending.clear();
        assert_eq!(pick(&st, &items, &caps).map(|p| p.0), None);
    }

    #[test]
    fn storage_cap_lets_others_pass() {
        let items = [
            it(0, "a", &["ceph"]),
            it(1, "b", &["ceph", "lvm"]),
            it(2, "a", &["lvm"]),
        ];
        let caps = HashMap::from([("ceph".to_string(), 1)]);
        let mut st = State {
            pending: vec![1, 2],
            ..Default::default()
        };
        st.storages.insert("ceph".into(), 1);
        assert_eq!(
            pick(&st, &items, &caps).map(|p| p.0),
            Some(1),
            "guest 1 waits for ceph, guest 2 passes"
        );
        st.pending = vec![1];
        assert_eq!(pick(&st, &items, &caps).map(|p| p.0), None);
    }

    #[test]
    fn runs_at_most_n_and_keeps_order() {
        let items: Vec<Item<u32>> = (0..12).map(|i| it(i, &format!("n{}", i % 3), &[])).collect();
        let (now, max) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let out = run(&items, 3, &HashMap::new(), |&i| {
            let c = now.fetch_add(1, Ordering::SeqCst) + 1;
            max.fetch_max(c, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            now.fetch_sub(1, Ordering::SeqCst);
            i * 2
        });
        assert_eq!(out, (0..12).map(|i| i * 2).collect::<Vec<_>>());
        assert_eq!(max.load(Ordering::SeqCst), 3);
        assert!(run(&Vec::<Item<u32>>::new(), 4, &HashMap::new(), |&i| i).is_empty());
        assert_eq!(run(&items[..1], 8, &HashMap::new(), |&i| i + 1), vec![1]);
    }

    #[test]
    fn storage_cap_bounds_concurrency() {
        // 8 guests on ceph (cap 2) and 4 on lvm: never more than 2 ceph backups at once
        let items: Vec<Item<u32>> = (0..12)
            .map(|i| it(i, &format!("n{}", i % 3), if i < 8 { &["ceph"] } else { &["lvm"] }))
            .collect();
        let caps = HashMap::from([("ceph".to_string(), 2)]);
        let (ceph, ceph_max, all, all_max) = (
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        );
        let out = run(&items, 6, &caps, |&i| {
            let c = all.fetch_add(1, Ordering::SeqCst) + 1;
            all_max.fetch_max(c, Ordering::SeqCst);
            if i < 8 {
                let c = ceph.fetch_add(1, Ordering::SeqCst) + 1;
                ceph_max.fetch_max(c, Ordering::SeqCst);
            }
            std::thread::sleep(Duration::from_millis(20));
            if i < 8 {
                ceph.fetch_sub(1, Ordering::SeqCst);
            }
            all.fetch_sub(1, Ordering::SeqCst);
            i
        });
        assert_eq!(out, (0..12).collect::<Vec<_>>());
        assert_eq!(ceph_max.load(Ordering::SeqCst), 2, "ceph capped at 2");
        assert!(all_max.load(Ordering::SeqCst) > 2, "lvm guests ran beside them");
    }

    #[test]
    fn storages_of_a_config() {
        let vm: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{"scsi0":"ceph:vm-100-disk-0,size=4G","virtio1":"local-lvm:vm-100-disk-1,size=1G",
                "ide2":"local:iso/x.iso,media=cdrom","efidisk0":"ceph:vm-100-disk-2,size=1M",
                "sata0":"none,media=cdrom","net0":"virtio=AA:BB,bridge=vmbr0","memory":1024}"#,
        )
        .unwrap();
        assert_eq!(guest_storages(&vm), vec!["ceph", "local-lvm"]);
        let ct: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{"rootfs":"local-zfs:subvol-200-disk-0,size=8G","mp0":"tank:subvol-200-disk-1,mp=/data",
                "mp1":"/srv/bind,mp=/bind"}"#,
        )
        .unwrap();
        assert_eq!(guest_storages(&ct), vec!["local-zfs", "tank"]);
    }
}
