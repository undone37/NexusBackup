//! Standalone mode (Phase 38b/38c): the Linux platform backs up into a local repository without an
//! appliance, incrementally, restores from it, and another machine opens it with the 24 words.

use agent_core::config::{Paths, Settings};
use agent_core::server::Ctx;
use agent_core::standalone;
use agent_proto::{Filters, Overwrite};
use std::fs;
use std::path::Path;

fn paths(dir: &Path) -> Paths {
    Paths {
        config: dir.join("etc"),
        state: dir.join("state"),
        run: dir.join("run"),
    }
}

fn read(p: &Path) -> Vec<u8> {
    fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn backup_incremental_restore_and_recovery_words() {
    // not on tmpfs: the platform backs up data file systems only
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let (p, repo_dir) = (paths(&d.path().join("a")), d.path().join("repo"));
    let settings = Settings {
        hook_owner: nexus_agent::sys::geteuid(),
        ..Default::default()
    };
    // standalone keeps its own state (cache, key) apart from managed mode
    let sp = standalone::state_paths(&p);
    let ctx = Ctx {
        paths: &sp,
        settings: &settings,
    };
    let platform = nexus_agent::server::Linux::default();
    let data = d.path().join("data");
    fs::create_dir_all(data.join("docs")).unwrap();
    fs::write(data.join("docs/report.txt"), b"quarterly numbers").unwrap();
    let big: Vec<u8> = (0..3_000_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    fs::write(data.join("big.bin"), &big).unwrap();

    let words = standalone::init(&p, &repo_dir, "laptop 1").unwrap();
    assert_eq!(words.split_whitespace().count(), 24);
    assert!(standalone::init(&p, &repo_dir, "x").is_err(), "not twice");
    let repo = standalone::open(&p, &repo_dir, None).unwrap();
    assert_eq!(repo.source, "host-laptop-1");
    let roots = [data.to_string_lossy().into_owned()];
    let run = |job| standalone::backup(&platform, ctx, &repo, job, &roots, &[], &Filters::default(), false).unwrap();
    let s1 = run(1);
    assert!(
        s1.files >= 2 && s1.bytes >= big.len() as u64 && s1.new_chunks >= 2,
        "{s1:?}"
    );

    // a change and a new file: the big file is unchanged and costs nothing
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(data.join("docs/report.txt"), b"quarterly numbers, revised").unwrap();
    fs::write(data.join("docs/new.txt"), b"fresh").unwrap();
    let s2 = run(2);
    assert!(s2.time >= s1.time && s2.files == s1.files + 1, "{s2:?}");
    assert!(s2.new_chunks <= 2, "only the changed and the new file: {s2:?}");
    let snaps = standalone::list(&repo).unwrap();
    assert_eq!(snaps.len(), 2);

    // restore the first snapshot: the old report, the big file intact
    let target = d.path().join("restore");
    fs::create_dir_all(&target).unwrap();
    let st = standalone::restore(
        &platform,
        ctx,
        &repo,
        snaps[0].time,
        "",
        target.to_str().unwrap(),
        Overwrite::Never,
    )
    .unwrap();
    assert!(st.errors.is_empty(), "{st:?}");
    let rel = data.strip_prefix("/").unwrap();
    assert_eq!(read(&target.join(rel).join("docs/report.txt")), b"quarterly numbers");
    assert!(read(&target.join(rel).join("big.bin")) == big);
    assert!(!target.join(rel).join("docs/new.txt").exists());

    // one writer at a time; prune keeps the newest snapshot only (the restore above used the older one)
    {
        let _held = repo.lock().unwrap();
        assert!(
            repo.lock().is_err(),
            "a second backup or prune waits for none: it fails"
        );
    }
    // the last snapshot of today: both are from today
    let keep_one = standalone::Gfs {
        recent: 0,
        daily: 1,
        weekly: 0,
        monthly: 0,
        yearly: 0,
    };
    let line = standalone::prune(&repo, &keep_one).unwrap();
    assert!(line.starts_with("1 snapshot(s) kept, 1 deleted"), "{line}");
    assert_eq!(standalone::list(&repo).unwrap().len(), 1);

    // another machine: no key until the 24 words open it; wrong words do not
    let other = paths(&d.path().join("b"));
    assert!(standalone::open(&other, &repo_dir, None).is_err());
    let mut wrong: Vec<&str> = words.split_whitespace().collect();
    wrong.swap(0, 1);
    assert!(standalone::open(&other, &repo_dir, Some(&wrong.join(" "))).is_err());
    let r = standalone::open(&other, &repo_dir, Some(&words)).unwrap();
    assert_eq!(standalone::list(&r).unwrap().len(), 1);
    assert!(
        standalone::open(&other, &repo_dir, None).is_ok(),
        "the key is kept from then on"
    );
}

/// Phase 38e: the service's pass over `standalone.json`: a due job runs once per slot, a missing
/// repository makes it wait (and says why), a broken jobs file is reported.
#[test]
fn scheduled_jobs_run_once_per_slot_and_wait_for_the_repository() {
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let p = paths(&d.path().join("a"));
    fs::create_dir_all(&p.config).unwrap();
    let settings = Settings {
        hook_owner: nexus_agent::sys::geteuid(),
        ..Default::default()
    };
    let platform = nexus_agent::server::Linux::default();
    let data = d.path().join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("a.txt"), b"one").unwrap();
    let (repo, usb) = (d.path().join("repo"), d.path().join("usb/nexus"));
    standalone::init(&p, &repo, "host").unwrap();
    let jobs = serde_json::json!({"jobs": [
        {"name": "home", "repo": repo, "paths": [data], "schedule": "every 4h", "tz": "Europe/Berlin", "keep": "0,1,0,0,0"},
        {"name": "usb", "repo": usb, "paths": [data], "schedule": "daily 03:00"},
    ]});
    fs::write(p.config.join(standalone::JOBS_FILE), jobs.to_string()).unwrap();
    let now = 2_000_000_000i64; // a Wednesday
    let log = standalone::tick(&platform, &p, &settings, now);
    assert!(
        log.iter()
            .any(|l| l.starts_with("job home: snapshot ") && l.contains("prune: 1 snapshot(s) kept")),
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|l| l.contains("job usb: due, waiting: repository") && l.contains("not reachable")),
        "{log:?}"
    );
    let st = standalone::job_states(&p);
    assert_eq!(st["home"].last_ok, Some(now));
    assert!(st["usb"].waiting.is_some() && st["usb"].last_run == 0);
    // the same slot again: nothing runs, the wait is not logged twice
    let log = standalone::tick(&platform, &p, &settings, now + 60);
    assert!(log.is_empty(), "{log:?}");
    // the disk comes back: the waiting job runs at the next pass
    standalone::init(&p, &usb, "host").unwrap();
    let log = standalone::tick(&platform, &p, &settings, now + 120);
    assert!(log.iter().any(|l| l.starts_with("job usb: snapshot ")), "{log:?}");
    // a broken jobs file: reported, nothing runs
    fs::write(
        p.config.join(standalone::JOBS_FILE),
        r#"{"jobs": [{"name": "x", "repo": "r", "paths": ["/"], "schedule": "sometimes"}]}"#,
    )
    .unwrap();
    let log = standalone::tick(&platform, &p, &settings, now + 10 * 3600);
    assert!(log.len() == 1 && log[0].contains("bad schedule"), "{log:?}");
}

/// Phase 38c: a copy to another place (the directory backend; SFTP and S3 share the `Remote` contract),
/// incremental, with deletions after a prune; another machine fetches it and opens it with the words.
#[test]
fn copy_fetch_and_open_elsewhere() {
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let p = paths(&d.path().join("a"));
    let settings = Settings {
        hook_owner: nexus_agent::sys::geteuid(),
        ..Default::default()
    };
    let sp = standalone::state_paths(&p);
    let ctx = Ctx {
        paths: &sp,
        settings: &settings,
    };
    let platform = nexus_agent::server::Linux::default();
    let data = d.path().join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("a.txt"), b"first").unwrap();
    let (repo_dir, copy) = (d.path().join("repo"), d.path().join("offsite"));
    let words = standalone::init(&p, &repo_dir, "host").unwrap();
    let repo = standalone::open(&p, &repo_dir, None).unwrap();
    let roots = [data.to_string_lossy().into_owned()];
    let run = |job| standalone::backup(&platform, ctx, &repo, job, &roots, &[], &Filters::default(), false).unwrap();
    run(1);
    let target = d.path().join("target.json");
    fs::write(&target, serde_json::json!({"kind": "dir", "path": copy}).to_string()).unwrap();
    let (r, lock) = standalone::Target::load(&target).unwrap().open().unwrap();
    let c1 = standalone::copy_to(&repo_dir, r.as_ref(), lock).unwrap();
    assert!(c1.uploaded >= 4 && c1.deleted == 0, "{c1:?}");
    let c2 = standalone::copy_to(&repo_dir, r.as_ref(), lock).unwrap();
    assert_eq!((c2.uploaded, c2.deleted), (0, 0), "nothing new: {c2:?}");
    assert!(c2.replaced >= 1, "manifests and the clock again: {c2:?}");
    // a second snapshot, then keep only today's last one: the copy follows
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(data.join("a.txt"), b"second").unwrap();
    run(2);
    let today = standalone::Gfs {
        recent: 0,
        daily: 1,
        weekly: 0,
        monthly: 0,
        yearly: 0,
    };
    standalone::prune(&repo, &today).unwrap();
    let c3 = standalone::copy_to(&repo_dir, r.as_ref(), lock).unwrap();
    assert!(
        c3.uploaded >= 2 && c3.deleted >= 2,
        "new snapshot up, old one gone: {c3:?}"
    );
    // another machine: fetch, open with the words, restore the file
    let elsewhere = d.path().join("b-repo");
    assert!(standalone::fetch_from(r.as_ref(), &elsewhere).unwrap() > 0);
    let other = paths(&d.path().join("b"));
    let r2 = standalone::open(&other, &elsewhere, Some(&words)).unwrap();
    let snaps = standalone::list(&r2).unwrap();
    assert_eq!(snaps.len(), 1);
    let osp = standalone::state_paths(&other);
    let octx = Ctx {
        paths: &osp,
        settings: &settings,
    };
    let out = d.path().join("restored");
    fs::create_dir_all(&out).unwrap();
    standalone::restore(
        &platform,
        octx,
        &r2,
        snaps[0].time,
        "",
        out.to_str().unwrap(),
        Overwrite::Never,
    )
    .unwrap();
    assert_eq!(
        read(&out.join(data.strip_prefix("/").unwrap()).join("a.txt")),
        b"second"
    );
    assert!(
        standalone::fetch_from(r.as_ref(), &elsewhere).is_err(),
        "only into an empty directory"
    );
}
