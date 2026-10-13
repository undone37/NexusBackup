//! Against a real qemu-nbd with a persistent dirty bitmap (needs qemu-utils).
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::Duration;

fn run(cmd: &str, args: &[&str]) {
    let st = Command::new(cmd).args(args).output().unwrap();
    assert!(
        st.status.success(),
        "{cmd} {args:?}: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[test]
fn reads_data_holes_and_dirty_bitmap() {
    if Command::new("qemu-nbd").arg("--version").output().is_err() {
        eprintln!("qemu-nbd missing, skipping");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("t.qcow2");
    let img = img.to_str().unwrap();
    run("qemu-img", &["create", "-q", "-f", "qcow2", img, "64M"]);
    run("qemu-io", &["-f", "qcow2", "-c", "write -q -P 0xab 0 4M", img]);
    run("qemu-img", &["bitmap", "--add", "-f", "qcow2", img, "b0"]);
    // recorded by b0: 64 KiB at 8 MiB (chunk 2) and 4 KiB at 40 MiB (chunk 10)
    run(
        "qemu-io",
        &[
            "-f",
            "qcow2",
            "-c",
            "write -q -P 0xcd 8M 64k",
            "-c",
            "write -q -P 0xee 40M 4k",
            img,
        ],
    );
    let sock = d.path().join("nbd.sock");
    let _srv = Kill(
        Command::new("qemu-nbd")
            .args(["-r", "-f", "qcow2", "-B", "b0", "-k", sock.to_str().unwrap(), img])
            .spawn()
            .unwrap(),
    );
    let s = (0..100)
        .find_map(|_| {
            UnixStream::connect(&sock).ok().or_else(|| {
                std::thread::sleep(Duration::from_millis(50));
                None
            })
        })
        .expect("qemu-nbd socket");
    let ctx = "qemu:dirty-bitmap:b0";
    let mut c = nbd::Client::connect(s.try_clone().unwrap(), s, "", &[ctx]).unwrap();
    assert_eq!(c.size(), 64 << 20);

    let mut buf = vec![0u8; 4 << 20];
    c.read_exact(&mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0xab));
    c.seek(SeekFrom::Start(8 << 20)).unwrap();
    let mut b2 = vec![1u8; 128 << 10];
    c.read_exact(&mut b2).unwrap();
    assert!(
        b2[..64 << 10].iter().all(|&b| b == 0xcd) && b2[64 << 10..].iter().all(|&b| b == 0),
        "data + hole"
    );

    let ext = c.block_status(ctx).unwrap();
    assert_eq!(ext.iter().map(|e| e.1).sum::<u64>(), 64 << 20, "extents cover the disk");
    // qcow2 bitmap granularity is 64 KiB: the 4 KiB write marks a whole 64 KiB block
    assert_eq!(nbd::flagged(&ext, 1), vec![(8 << 20, 64 << 10), (40 << 20, 64 << 10)]);
    c.disconnect().unwrap();
}

fn pattern(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 7 + i / 4096) as u8).collect()
}

#[test]
fn server_roundtrip_with_own_client() {
    let data = pattern(5 << 20 | 123);
    let (a, b) = UnixStream::pair().unwrap();
    let d2 = data.clone();
    let srv = std::thread::spawn(move || {
        nbd::server::serve(b.try_clone().unwrap(), b, "drive-scsi0", d2.len() as u64, |off, buf| {
            buf.copy_from_slice(&d2[off as usize..off as usize + buf.len()]);
            Ok(())
        })
    });
    let mut c = nbd::Client::connect(a.try_clone().unwrap(), a, "drive-scsi0", &[]).unwrap();
    assert_eq!(c.size(), data.len() as u64);
    let mut out = Vec::new();
    c.read_to_end(&mut out).unwrap();
    assert_eq!(out, data);
    c.disconnect().unwrap();
    srv.join().unwrap().unwrap();
}

#[test]
fn server_interops_with_qemu_img() {
    if Command::new("qemu-img").arg("--version").output().is_err() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let sock = d.path().join("srv.sock");
    let data = pattern(3 << 20 | 512);
    let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let d2 = data.clone();
    let srv = std::thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        nbd::server::serve(s.try_clone().unwrap(), s, "disk", d2.len() as u64, |off, buf| {
            buf.copy_from_slice(&d2[off as usize..off as usize + buf.len()]);
            Ok(())
        })
    });
    let out = d.path().join("out.raw");
    let uri = format!("nbd+unix:///disk?socket={}", sock.display());
    run(
        "qemu-img",
        &["convert", "-f", "raw", "-O", "raw", &uri, out.to_str().unwrap()],
    );
    assert_eq!(std::fs::read(&out).unwrap(), data);
    srv.join().unwrap().unwrap();
}

/// `base:allocation` as an optional context: unwritten areas read as zero (NBD_STATE_ZERO,
/// flag 2), written ones do not; a missing optional context is not an error.
#[test]
fn allocation_reports_zero_regions() {
    if Command::new("qemu-nbd").arg("--version").output().is_err() {
        eprintln!("qemu-nbd missing, skipping");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("a.qcow2");
    let img = img.to_str().unwrap();
    run("qemu-img", &["create", "-q", "-f", "qcow2", img, "64M"]);
    run("qemu-io", &["-f", "qcow2", "-c", "write -q -P 0xab 16M 1M", img]);
    let sock = d.path().join("nbd.sock");
    let _srv = Kill(
        Command::new("qemu-nbd")
            .args(["-r", "-f", "qcow2", "-k", sock.to_str().unwrap(), img])
            .spawn()
            .unwrap(),
    );
    let s = (0..100)
        .find_map(|_| {
            UnixStream::connect(&sock).ok().or_else(|| {
                std::thread::sleep(Duration::from_millis(50));
                None
            })
        })
        .expect("qemu-nbd socket");
    let mut c = nbd::Client::connect_opt(
        s.try_clone().unwrap(),
        s,
        "",
        &[],
        &["base:allocation", "qemu:no-such-context"],
    )
    .unwrap();
    assert!(c.context_id("base:allocation").is_some() && c.context_id("qemu:no-such-context").is_none());
    let zero = nbd::flagged(&c.block_status("base:allocation").unwrap(), 2);
    assert_eq!(
        zero,
        vec![(0, 16 << 20), (17 << 20, 47 << 20)],
        "everything but the written MiB"
    );
}

/// Pipelined reads against a real qemu-nbd: the same bytes as one read at a time, any depth.
#[test]
fn read_many_matches_read_at() {
    if Command::new("qemu-nbd").arg("--version").output().is_err() {
        eprintln!("qemu-nbd missing, skipping");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("p.qcow2");
    let img = img.to_str().unwrap();
    run("qemu-img", &["create", "-q", "-f", "qcow2", img, "32M"]);
    run(
        "qemu-io",
        &[
            "-f",
            "qcow2",
            "-c",
            "write -q -P 0x5a 1M 3M",
            "-c",
            "write -q -P 0xa5 20M 512k",
            img,
        ],
    );
    let sock = d.path().join("nbd.sock");
    let _srv = Kill(
        Command::new("qemu-nbd")
            .args(["-r", "-f", "qcow2", "-k", sock.to_str().unwrap(), img])
            .spawn()
            .unwrap(),
    );
    let s = (0..100)
        .find_map(|_| {
            UnixStream::connect(&sock).ok().or_else(|| {
                std::thread::sleep(Duration::from_millis(50));
                None
            })
        })
        .expect("qemu-nbd socket");
    let mut c = nbd::Client::connect(s.try_clone().unwrap(), s, "", &[]).unwrap();
    let ranges: Vec<(u64, u64)> = (0..32u64)
        .map(|i| (i << 20, if i % 3 == 0 { 1 << 20 } else { 700_000 }))
        .collect();
    let mut want = Vec::new();
    for &(o, l) in &ranges {
        let mut b = vec![0u8; l as usize];
        c.read_at(o, &mut b).unwrap();
        want.push(b);
    }
    for depth in [1, 4, 16] {
        let mut got = Vec::new();
        c.read_many(&ranges, depth, |i, b| {
            assert_eq!(i, got.len());
            got.push(b);
            Ok(())
        })
        .unwrap();
        assert!(got == want, "depth {depth}");
    }
}
