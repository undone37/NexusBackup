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
