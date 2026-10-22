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
