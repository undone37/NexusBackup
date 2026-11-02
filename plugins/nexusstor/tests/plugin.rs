//! The NexusStor plugin against the real host code (plugin_sdk::testing) and an
//! in-process NexusStor (tests/fake) over real TLS: pairing, pinning, guests,
//! full and incremental backups, LUN and definition streams, base release, and
//! hostile answers.

mod fake;

use chunkstore::TreeKind;
use fake::*;
use nexusstor_plugin::NexusStorPlugin;
use plugin_sdk::testing::Host;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");
const SRC: &str = "plugin-nexusstor-7-acme";

fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn acme() -> VStor {
    let mut live = BTreeMap::new();
    let mut root = dir();
    root.xattrs.insert("user.DOSATTRIB".into(), b"0x10".to_vec());
    root.acl = Some(vec![0, 0, 0, 1, 7]);
    live.insert("data".into(), root);
    let mut a = file(b"hello nexusstor\n");
    a.xattrs.insert("security.NTACL".into(), vec![1, 2, 3]);
    a.acl = Some(vec![0, 0, 0, 2, 9, 9]);
    live.insert("data/a.txt".into(), a);
    live.insert("data/sp ace.txt".into(), file(b"space\n"));
    live.insert("data/big.bin".into(), file(&pseudo_random(3 << 20, 1)));
    live.insert("data/link".into(), symlink("a.txt"));
    live.insert("data/docs".into(), dir());
    for i in 1..=5 {
        live.insert(format!("data/docs/r{i}.txt"), file(format!("doc {i}\n").as_bytes()));
    }
    live.insert("data/docs/sub".into(), dir());
    live.insert("data/docs/sub/deep.txt".into(), file(b"deep\n"));
    live.insert("data/projects".into(), dir());
    live.insert("data/projects/p.txt".into(), file(b"project\n"));
    live.insert("s3".into(), dir());
    live.insert("s3/bucket1".into(), dir());
    live.insert("s3/bucket1/obj".into(), file(&pseudo_random(100_000, 2)));
    let mut luns = BTreeMap::new();
    luns.insert("vm1".to_owned(), pseudo_random((5 << 20) + 4096, 3));
    VStor {
        dirs: vec!["data".into(), "data/projects".into(), "s3".into()],
        live,
        luns,
        ..VStor::default()
    }
}

fn other() -> VStor {
    let mut live = BTreeMap::new();
    live.insert("data".into(), dir());
    VStor {
        dirs: vec!["data".into()],
        live,
        ..VStor::default()
    }
}

struct Lab {
    fake: Fake,
    host: Host,
    cfg: Value,
}

fn config(fake: &Fake, expires: u64) -> Value {
    let (cert, key, _) = cert("nexusbackup-test");
    json!({
        "token": token(fake.port, &fake.fingerprint, expires),
        "host": "127.0.0.1", "port": fake.port, "fingerprint": fake.fingerprint,
        "client_cert": cert, "client_key": key, "appliance": "nb-test",
    })
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn lab() -> Lab {
    let mut st = State {
        name: "nas1".into(),
        ..State::default()
    };
    st.vstors.insert("acme".into(), acme());
    st.vstors.insert("beta".into(), other());
    let fake = Fake::start(st);
    let mut host = Host::in_process(MANIFEST.as_ref(), "nexusstor", || NexusStorPlugin).unwrap();
    host.source_id = 7;
    let cfg = config(&fake, now() + 900);
    Lab { fake, host, cfg }
}

/// A paired lab.
fn paired() -> Lab {
    let l = lab();
    let v = l.host.validate(&l.cfg).unwrap();
    assert_eq!(v["valid"], true, "{v} {:?}", l.host.log());
    l
}

fn snaps(l: &Lab) -> Vec<String> {
    l.fake.state.lock().unwrap().vstors["acme"]
        .snaps
        .keys()
        .cloned()
        .collect()
}

/// The snapshot must describe the vStor exactly: tree (kinds, modes, contents,
/// targets, xattrs + ACL), the LUN and the definition.
fn assert_backup(l: &Lab, time: u64) {
    let s = l.host.snapshot(SRC, time).unwrap();
    let g = l.fake.state.lock().unwrap();
    let vs = &g.vstors["acme"];
    let paths: Vec<&str> = s.files.iter().map(|e| std::str::from_utf8(&e.path).unwrap()).collect();
    assert_eq!(paths, vs.live.keys().map(String::as_str).collect::<Vec<_>>());
    for e in &s.files {
        let n = &vs.live[std::str::from_utf8(&e.path).unwrap()];
        assert_eq!(e.mode, n.mode, "{n:?}");
        match e.kind {
            TreeKind::File => {
                let mut d = Vec::new();
                l.host.store().chunk_reader(&e.chunks).read_to_end(&mut d).unwrap();
                assert_eq!(d, n.data);
            }
            TreeKind::Dir => assert_eq!(n.kind, "dir"),
            TreeKind::Symlink => assert_eq!(e.link_target.as_deref(), n.target.as_deref().map(str::as_bytes)),
            ref k => panic!("unexpected kind {k:?}"),
        }
        let mut want: Vec<(Vec<u8>, Vec<u8>)> = n
            .xattrs
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.clone()))
            .collect();
        if let Some(a) = &n.acl {
            want.push((b"system.nfs4_acl".to_vec(), a.clone()));
        }
        want.sort();
        assert_eq!(e.xattrs, want, "{}", String::from_utf8_lossy(&e.path));
    }
    let names: Vec<&str> = s.streams.iter().map(|x| x.path.as_str()).collect();
    assert_eq!(names, ["luns/vm1", "vstor.json"]);
    let mut d = Vec::new();
    l.host
        .store()
        .chunk_reader(&s.streams[0].chunks)
        .read_to_end(&mut d)
        .unwrap();
    assert!(d == vs.luns["vm1"], "LUN content");
    let mut d = Vec::new();
    l.host
        .store()
        .chunk_reader(&s.streams[1].chunks)
        .read_to_end(&mut d)
        .unwrap();
    let def: Value = serde_json::from_slice(&d).unwrap();
    assert_eq!(def["network"]["vlan"], 10);
}

#[test]
fn pairing_validate_and_guests() {
    let l = lab();
    // not paired yet: inventory is 403, then pair with the token's code
    let v = l.host.validate(&l.cfg).unwrap();
    assert_eq!(v["valid"], true, "{v} {:?}", l.host.log());
    assert!(
        l.host
            .log()
            .iter()
            .any(|x| x.contains("paired with NexusStor \"nas1\"")),
        "{:?}",
        l.host.log()
    );
    let client_der = pem::parse(l.cfg["client_cert"].as_str().unwrap()).unwrap();
    {
        let g = l.fake.state.lock().unwrap();
        assert_eq!(g.paired.as_deref(), Some(sha256(client_der.contents()).as_str()));
        assert_eq!(g.pair_calls, 1);
    }
    // paired: no second pairing (the code is spent)
    assert_eq!(l.host.validate(&l.cfg).unwrap()["valid"], true);
    assert_eq!(l.fake.state.lock().unwrap().pair_calls, 1);
    let g = l.host.guests(&l.cfg).unwrap();
    let ids: Vec<&str> = g["guests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["acme", "beta"], "{g}");
    assert_eq!(g["guests"][0]["title"], "acme (1 NFS, 1 SMB, S3, 1 LUN)");

    // another client certificate (another NexusBackup): not paired, token expired
    let late = config(&l.fake, now() - 1);
    let v = l.host.validate(&late).unwrap();
    assert_eq!(
        (v["valid"].clone(), v["field"].clone()),
        (json!(false), json!("token")),
        "{v}"
    );
    assert_eq!(
        l.fake.state.lock().unwrap().pair_calls,
        1,
        "an expired token is not sent"
    );
    // without a token
    let mut none = config(&l.fake, now() + 900);
    none.as_object_mut().unwrap().remove("token");
    assert_eq!(l.host.validate(&none).unwrap()["field"], "token");
    // a backup without pairing names the reason
    let e = l.host.backup(&none, Some("acme")).unwrap_err();
    assert!(format!("{e:#}").contains("not paired"), "{e:#}");
}

/// #137: NexusStor's change-rate finding is passed on in the snapshot meta (known fields only, bounded), where
/// the scheduler flags the snapshot and raises `anomaly`; without one the meta has none.
#[test]
fn nexusstor_anomaly_reaches_the_snapshot_meta() {
    let l = paired();
    let b = l.host.backup(&l.cfg, Some("acme")).unwrap();
    assert!(b.meta.as_ref().unwrap()["anomaly"].is_null(), "{:?}", b.meta);
    l.fake.state.lock().unwrap().anomaly = Some(json!({"snapshot": "auto-daily-20261101-0000", "at": 1793500000,
        "last_good": "auto-daily-20261031-0000", "last_good_created": 1793413600, "extra": "x".repeat(5000)}));
    std::thread::sleep(std::time::Duration::from_secs(1)); // a later snapshot time
    let b = l.host.backup(&l.cfg, Some("acme")).unwrap();
    let a = &b.meta.as_ref().unwrap()["anomaly"];
    assert_eq!(a["system"], "NexusStor nas1");
    assert_eq!(
        (a["snapshot"].as_str(), a["last_good_created"].as_i64()),
        (Some("auto-daily-20261101-0000"), Some(1793413600))
    );
    assert!(a.get("extra").is_none(), "unknown fields are not passed on: {a}");
    assert!(
        l.host.log().iter().any(|x| x.contains("change-rate anomaly")),
        "{:?}",
        l.host.log()
    );
}

/// #137 contract step 3: the host's report after a backup reaches NexusStor as `POST /vstors/<v>/report`.
#[test]
fn backup_report_reaches_nexusstor() {
    let l = paired();
    let b = l.host.backup(&l.cfg, Some("acme")).unwrap();
    let snap = format!("{}/{}", b.source, b.time);
    l.host
        .report(
            &l.cfg,
            json!({"guest": "acme", "state": "ok", "time": b.time, "snapshot": snap, "message": "x".repeat(900)}),
        )
        .unwrap();
    let got = l.fake.state.lock().unwrap().reports.clone();
    assert_eq!(got.len(), 1);
    let (v, body) = &got[0];
    assert_eq!((v.as_str(), body["state"].as_str()), ("acme", Some("ok")));
    assert_eq!(body["snapshot"].as_str(), Some(snap.as_str()));
    assert_eq!(
        body["message"].as_str().unwrap().len(),
        500,
        "cut to the contract's limit"
    );
    // a vStor NexusStor refuses: the report op fails (the host logs it, the backup stays as it was)
    let e = l.host.report(
        &l.cfg,
        json!({"guest": "gone", "state": "failed", "time": 1, "snapshot": null}),
    );
    assert!(e.is_err());
}

#[test]
fn unpinned_server_certificate_is_refused() {
    let l = lab();
    let mut bad = l.cfg.clone();
    let (_, _, der) = cert("impostor");
    bad["fingerprint"] = json!(sha256(&der));
    let v = l.host.validate(&bad).unwrap();
    assert_eq!(
        (v["valid"].clone(), v["field"].clone()),
        (json!(false), json!("fingerprint")),
        "{v}"
    );
    assert!(l.host.backup(&bad, Some("acme")).is_err());
    assert!(l.host.guests(&bad).is_err());
    // nothing was sent: the handshake stopped before any request (no pairing code leaked)
    let g = l.fake.state.lock().unwrap();
    assert!(g.requests.is_empty(), "{:?}", g.requests);
    assert!(g.paired.is_none());
}

#[test]
fn full_and_incremental_backups() {
    let l = paired();
    let b1 = l.host.backup(&l.cfg, Some("acme")).unwrap();
    assert_eq!(b1.source, SRC);
    assert!(b1.base.is_none() && b1.consistent && b1.unchanged == 0, "{b1:?}");
    assert_backup(&l, b1.time);
    let s1 = snaps(&l);
    assert_eq!(s1.len(), 1);
    let t1 = l.host.snapshot(SRC, b1.time).unwrap();
    let chunks =
        |t: &[chunkstore::TreeEntry], p: &str| t.iter().find(|e| e.path == p.as_bytes()).unwrap().chunks.clone();

    // round 2: edit, delete, add, xattr-only change, directory rename, new dataset
    {
        let mut g = l.fake.state.lock().unwrap();
        let vs = g.vstors.get_mut("acme").unwrap();
        let a = vs.live.get_mut("data/a.txt").unwrap();
        a.data = b"hello nexusstor, changed\n".to_vec();
        a.mtime += 60;
        vs.live.remove("data/docs/r2.txt");
        vs.live.insert("data/new.txt".into(), file(b"brand new\n"));
        vs.live
            .get_mut("data/sp ace.txt")
            .unwrap()
            .xattrs
            .insert("user.tag".into(), b"x".to_vec());
        let moved: Vec<String> = vs.live.keys().filter(|k| k.starts_with("data/docs")).cloned().collect();
        for k in moved {
            let n = vs.live.remove(&k).unwrap();
            vs.live.insert(k.replacen("data/docs", "data/papers", 1), n);
        }
        vs.renames = vec![("data/docs".into(), "data/papers".into())];
        vs.dirs.push("data/vault".into());
        vs.live.insert("data/vault".into(), dir());
        vs.live.insert("data/vault/v.txt".into(), file(b"vault\n"));
    }
    let b2 = l.host.backup(&l.cfg, Some("acme")).unwrap();
    assert_eq!(b2.base, Some(b1.time), "{b2:?}");
    assert_backup(&l, b2.time);
    // big.bin, projects/p.txt, s3/bucket1/obj are Unchanged (chunk ids of the base)
    assert_eq!(b2.unchanged, 3, "{b2:?} {:?}", l.host.log());
    let t2 = l.host.snapshot(SRC, b2.time).unwrap();
    assert_eq!(chunks(&t1.files, "data/big.bin"), chunks(&t2.files, "data/big.bin"));
    // the base is kept until this run is known to be committed
    let s2 = snaps(&l);
    assert_eq!(s2.len(), 2, "{s2:?}");
    assert!(s2.contains(&s1[0]));

    // round 3: no changes; the previous base is released
    l.fake
        .state
        .lock()
        .unwrap()
        .vstors
        .get_mut("acme")
        .unwrap()
        .renames
        .clear();
    let b3 = l.host.backup(&l.cfg, Some("acme")).unwrap();
    assert_backup(&l, b3.time);
    let files = l.fake.state.lock().unwrap().vstors["acme"]
        .live
        .values()
        .filter(|n| n.kind == "file")
        .count();
    assert_eq!(b3.unchanged as usize, files, "{b3:?}");
    let s3 = snaps(&l);
    assert!(!s3.contains(&s1[0]) && s3.len() == 2, "{s3:?}");
    assert!(l
        .fake
        .state
        .lock()
        .unwrap()
        .requests
        .contains(&format!("DELETE /nexusbackup/v1/vstors/acme/snapshots/{}", s1[0])));

    // the base's NexusStor snapshot vanished: a full read, still correct
    l.fake
        .state
        .lock()
        .unwrap()
        .vstors
        .get_mut("acme")
        .unwrap()
        .snaps
        .clear();
    let b4 = l.host.backup(&l.cfg, Some("acme")).unwrap();
    assert_eq!(b4.unchanged, 0);
    assert_backup(&l, b4.time);
}

fn hostile(evil: Evil, after_full: bool, want: &str) {
    let l = paired();
    if after_full {
        l.host.backup(&l.cfg, Some("acme")).unwrap();
    }
    let before = snaps(&l);
    l.fake.state.lock().unwrap().evil = evil;
    let e = l.host.backup(&l.cfg, Some("acme")).unwrap_err();
    assert!(format!("{e:#}").contains(want), "{evil:?}: {e:#}");
    // the snapshot of the failed run is released
    assert_eq!(snaps(&l), before, "{evil:?}");
}

#[test]
fn hostile_list_entry_is_refused() {
    hostile(Evil::ListDotDot, false, "invalid name");
}

#[test]
fn hostile_record_path_is_refused() {
    hostile(Evil::FilesAbsolute, false, "invalid path \"/etc/shadow\"");
}

#[test]
fn oversized_record_is_refused() {
    hostile(Evil::FilesOversized, false, "line longer than");
}

#[test]
fn hostile_diff_path_is_refused() {
    hostile(Evil::DiffOutside, true, "outside the dataset");
}

/// The base was destroyed after the inventory listed it (a NexusStor rollback): diff
/// answers 409 and the run reads the vStor in full instead of failing.
#[test]
fn diff_409_falls_back_to_a_full_read() {
    let l = paired();
    l.host.backup(&l.cfg, Some("acme")).unwrap();
    l.fake.state.lock().unwrap().evil = Evil::Diff409;
    let b = l.host.backup(&l.cfg, Some("acme")).unwrap();
    assert_eq!(b.unchanged, 0, "{b:?}");
    assert!(b.summary.contains("full read"), "{}", b.summary);
    assert_backup(&l, b.time);
}

#[test]
fn unknown_vstor_is_refused() {
    let l = paired();
    let e = l.host.backup(&l.cfg, Some("nope")).unwrap_err();
    assert!(format!("{e:#}").contains("not in this pairing's scope"), "{e:#}");
}

/// The plugin binary in the real sandbox (Landlock, seccomp, endpoint ports)
/// against the fake: pairing, a full and an incremental backup.
#[test]
fn sandboxed_binary() {
    let l = lab();
    let mut h = Host::binary(
        MANIFEST.as_ref(),
        env!("CARGO_BIN_EXE_nexusstor-plugin").as_ref(),
        "nexusstor",
    )
    .unwrap();
    h.source_id = 7;
    let v = h.validate(&l.cfg).unwrap();
    assert_eq!(v["valid"], true, "{v} {:#?}", h.log());
    let b1 = h.backup(&l.cfg, Some("acme")).unwrap();
    l.fake
        .state
        .lock()
        .unwrap()
        .vstors
        .get_mut("acme")
        .unwrap()
        .live
        .insert("data/late.txt".into(), file(b"late\n"));
    let b2 = h.backup(&l.cfg, Some("acme")).unwrap();
    assert_eq!(b2.base, Some(b1.time));
    assert_eq!(b2.unchanged, 11, "{b2:?}"); // every file but the new one
    assert!(h.log().iter().any(|x| x.contains("landlock")), "{:?}", h.log());
}
