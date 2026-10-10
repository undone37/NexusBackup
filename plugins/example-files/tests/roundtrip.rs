//! The example plugin binary in the real sandbox against the real host code:
//! backup → incremental (Unchanged) → restore, byte-exact incl. metadata.

use plugin_sdk::testing::Host;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");

fn set_mtime(p: &Path, secs: i64, nsec: i64) {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let t = libc_timespec(secs, nsec);
    unsafe { utimensat(-100, c.as_ptr(), [t, t].as_ptr(), 0x100) };
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    s: i64,
    ns: i64,
}
fn libc_timespec(s: i64, ns: i64) -> Timespec {
    Timespec { s, ns }
}
extern "C" {
    fn utimensat(dirfd: i32, path: *const std::ffi::c_char, times: *const Timespec, flags: i32) -> i32;
    fn setxattr(path: *const std::ffi::c_char, name: *const std::ffi::c_char, v: *const u8, n: usize, f: i32) -> i32;
    fn lgetxattr(path: *const std::ffi::c_char, name: *const std::ffi::c_char, v: *mut u8, n: usize) -> isize;
}

fn xattr(p: &Path) -> Option<Vec<u8>> {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let mut buf = [0u8; 64];
    let n = unsafe { lgetxattr(c.as_ptr(), c"user.nexus".as_ptr(), buf.as_mut_ptr(), buf.len()) };
    (n >= 0).then(|| buf[..n as usize].to_vec())
}

fn make_data(d: &Path) -> bool {
    fs::create_dir_all(d.join("sub/deeper")).unwrap();
    fs::write(d.join("hello.txt"), b"hello world\n").unwrap();
    fs::write(d.join("empty"), b"").unwrap();
    let big: Vec<u8> = (0..6_000_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    fs::write(d.join("sub/big.bin"), &big).unwrap();
    fs::write(d.join("sub/deeper/x.conf"), b"a=1\n").unwrap();
    fs::write(d.join("skip.tmp"), b"excluded").unwrap();
    fs::set_permissions(d.join("sub/deeper/x.conf"), fs::Permissions::from_mode(0o640)).unwrap();
    std::os::unix::fs::symlink("hello.txt", d.join("link")).unwrap();
    fs::hard_link(d.join("hello.txt"), d.join("sub/hard")).unwrap();
    set_mtime(&d.join("hello.txt"), 1_600_000_000, 123_456_789);
    set_mtime(&d.join("sub/deeper"), 1_500_000_000, 0);
    let c = std::ffi::CString::new(d.join("empty").as_os_str().as_encoded_bytes()).unwrap();
    unsafe { setxattr(c.as_ptr(), c"user.nexus".as_ptr(), b"meta".as_ptr(), 4, 0) == 0 }
}

/// path -> (kind, mode, mtime_ns, size, content digest / link target)
fn tree(root: &Path) -> BTreeMap<String, (String, u32, i64, u64, Vec<u8>)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for e in fs::read_dir(root.join(&rel)).unwrap() {
            let e = e.unwrap();
            let r = rel.join(e.file_name());
            let p = root.join(&r);
            let m = fs::symlink_metadata(&p).unwrap();
            let (kind, data) = if m.is_dir() {
                stack.push(r.clone());
                ("dir", Vec::new())
            } else if m.file_type().is_symlink() {
                ("link", fs::read_link(&p).unwrap().into_os_string().into_encoded_bytes())
            } else {
                ("file", fs::read(&p).unwrap())
            };
            let mtime = if kind == "dir" {
                0
            } else {
                m.mtime() * 1_000_000_000 + m.mtime_nsec()
            };
            out.insert(
                r.to_string_lossy().into_owned(),
                (
                    kind.into(),
                    m.mode() & 0o7777,
                    mtime,
                    if kind == "file" { m.size() } else { 0 },
                    data,
                ),
            );
        }
    }
    out
}

#[test]
fn backup_incremental_restore_in_sandbox() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    let target = d.path().join("target");
    fs::create_dir_all(&target).unwrap();
    let has_xattr = make_data(&data);
    let mut h = Host::binary(MANIFEST.as_ref(), env!("CARGO_BIN_EXE_example-files").as_ref(), "files").unwrap();
    h.read_paths.push(data.clone());
    h.write_paths.push(target.clone());
    let cfg = json!({"path": data, "excludes": ["*.tmp"]});

    assert_eq!(h.validate(&cfg).unwrap()["valid"], true);
    let bad = h.validate(&json!({"path": d.path().join("nope")})).unwrap();
    assert_eq!(
        (bad["valid"].as_bool(), bad["field"].as_str()),
        (Some(false), Some("path"))
    );
    // outside its sandbox the plugin cannot even see the directory
    let hidden = h.validate(&json!({"path": "/etc/ssh"})).unwrap();
    assert_eq!(hidden["valid"], false, "{hidden}");

    let b1 = h.backup(&cfg, None).unwrap();
    assert_eq!(b1.source, "plugin-example-files-1");
    assert_eq!((b1.files, b1.unchanged, b1.consistent), (4, 0, false), "{:?}", h.log());
    assert!(h.log().iter().any(|l| l.starts_with("sandbox: landlock ABI")));

    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(data.join("sub/deeper/x.conf"), b"a=2\n").unwrap();
    let b2 = h.backup(&cfg, None).unwrap();
    assert_eq!(
        (b2.files, b2.unchanged, b2.base),
        (4, 3, Some(b1.time)),
        "{:?}",
        h.log()
    );
    assert_eq!(b2.transferred, 4, "only the changed file is read");
    let snap = h.snapshot(&b2.source, b2.time).unwrap();
    assert_eq!(snap.state.as_deref(), Some(&b"runs=2"[..]));

    let r = h
        .restore(&cfg, &b2.source, b2.time, "to_dir", json!({"target": target}))
        .unwrap();
    assert!(r.summary.contains("restored to"), "{}", r.summary);
    let mut want = tree(&data);
    want.remove("skip.tmp");
    assert_eq!(tree(&target), want);
    let ino = |p: &str| fs::metadata(target.join(p)).unwrap().ino();
    assert_eq!(ino("hello.txt"), ino("sub/hard"), "hard link restored");
    if has_xattr {
        assert_eq!(xattr(&target.join("empty")).as_deref(), Some(&b"meta"[..]));
    }
    // restoring again without overwrite: existing files are reported, nothing is replaced
    let again = h.restore(&cfg, &b2.source, b2.time, "to_dir", json!({"target": target}));
    assert!(format!("{:#}", again.unwrap_err()).contains("could not be restored"));
}

#[test]
fn in_process_variant() {
    // the same harness with the plugin on a thread (no sandbox): quick logic tests
    struct P;
    impl plugin_sdk::Plugin for P {
        fn validate(&mut self, _: &plugin_sdk::Ctx) -> plugin_sdk::Result<plugin_sdk::Validation> {
            Ok(plugin_sdk::Validation::Valid)
        }
        fn backup(
            &mut self,
            ctx: &plugin_sdk::Ctx,
            sink: &mut plugin_sdk::Sink,
        ) -> plugin_sdk::Result<plugin_sdk::BackupResult> {
            let mut s = sink.stream(&format!("db/{}.sql", ctx.guest().unwrap_or("all")))?;
            std::io::Write::write_all(&mut s, &vec![b'x'; 3 << 20])?;
            s.finish()?;
            Ok(plugin_sdk::BackupResult::consistent("ok"))
        }
        fn restore(&mut self, _: &plugin_sdk::Ctx, src: &mut plugin_sdk::Source) -> plugin_sdk::Result<String> {
            let mut n = 0;
            src.streams(&["db/g1.sql".into()], |_, r| {
                n = std::io::copy(r, &mut std::io::sink())?;
                Ok(())
            })?;
            Ok(n.to_string())
        }
    }
    let h = Host::in_process(MANIFEST.as_ref(), "files", || P).unwrap();
    let b = h.backup(&json!({}), Some("g1")).unwrap();
    assert_eq!(
        (b.source.as_str(), b.streams, b.bytes),
        ("plugin-example-files-1-g1", 1, 3 << 20)
    );
    let r = h.restore(&json!({}), &b.source, b.time, "x", json!({})).unwrap();
    assert_eq!(r.summary, (3u64 << 20).to_string());
}
