//! Power-loss test guest, driven by tests/powerloss/run.sh. Built static and
//! booted as /init of a QEMU guest:
//! - `pl.mode=write`: writer children commit snapshots in a loop and print
//!   `COMMITTED <t>`, keep the last KEEP (deleting older ones) and GC every
//!   100 snapshots; each child is kill -9'd after a random time and
//!   restarted, until the host SIGKILLs QEMU (= power cut).
//! - `pl.mode=check`: after journal replay, the snapshots must be a contiguous
//!   range ending at or after the last `pl.committed`, all restore bit-exact,
//!   GC + verify leave a consistent store. Prints PASS/FAIL, powers off.
use chunkstore::{Keyring, Manifest, Options, Store};
use std::ffi::CString;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use std::{fs, io, thread};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn open(dir: &Path) -> io::Result<Store> {
    let keys = Keyring::new("tenant1", &[(1, [9; 32])]);
    Store::open(
        dir,
        keys,
        Options {
            min_lock_secs: 0,
            gc_grace_secs: 0,
            clock_slew: 1e9,
            ..Default::default()
        },
    )
}

const BLOCK: usize = 4096;
const KEEP: u64 = 50;

/// Like tests/store.rs: block `t % 6` differs, and is unique per snapshot.
fn image(t: u64) -> Vec<u8> {
    let mut x = 0x9e3779b97f4a7c15u64;
    let mut v: Vec<u8> = (0..6 * BLOCK)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if i / BLOCK == (t % 6) as usize {
                (x as u8) ^ (t as u8)
            } else {
                x as u8
            }
        })
        .collect();
    let o = (t % 6) as usize * BLOCK;
    v[o..o + 8].copy_from_slice(&t.to_le_bytes());
    v
}

fn restore(s: &Store, m: &Manifest) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    s.write_chunks(s.load_index(m, "disk")?.chunk_ids(), &mut out)?;
    Ok(out)
}

fn write(dir: &Path) -> Res<()> {
    let s = open(dir)?;
    let snaps = s.list_snapshots()?;
    let mut t = snaps.last().map_or(0, |m| m.time);
    // a killed predecessor may not have deleted its oldest snapshot yet
    for m in snaps.iter().filter(|m| m.time + KEEP <= t) {
        s.delete_snapshot("vm", m.time)?;
    }
    loop {
        t += 1;
        let idx = s.store_image(&image(t)[..], BLOCK)?;
        s.commit_snapshot("vm", t, &[("disk", idx)])?;
        println!("COMMITTED {t}");
        if t > KEEP {
            s.delete_snapshot("vm", t - KEEP)?;
        }
        if t % 100 == 0 {
            s.gc(true)?;
        }
    }
}

fn check(dir: &Path, committed: u64) -> Res<String> {
    let s = open(dir)?;
    let snaps = s.list_snapshots()?;
    let (first, n) = (snaps.first().map_or(1, |m| m.time), snaps.last().map_or(0, |m| m.time));
    if !snaps.iter().map(|m| m.time).eq(first..=n) {
        return Err("snapshot times not contiguous".into());
    }
    if n < committed {
        return Err(format!("lost committed snapshots: newest {n} on disk, {committed} reported").into());
    }
    let check_all = |s: &Store| -> Res<()> {
        for m in &snaps {
            if restore(s, m)? != image(m.time) {
                return Err(format!("snapshot {} restores wrong data", m.time).into());
            }
        }
        Ok(())
    };
    check_all(&s)?;
    let gc = s.gc(true)?;
    let r = s.verify(|_| true)?;
    if !r.corrupt.is_empty() || !r.missing.is_empty() {
        return Err(format!("verify: {r:?}").into());
    }
    check_all(&s)?;
    Ok(format!(
        "snapshots={first}..={n} reported={committed} gc_deleted={} gc_kept_grace={} chunks={}",
        gc.deleted, gc.kept_grace, r.checked
    ))
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn sys(r: libc::c_long, what: &str) -> Res<()> {
    if r < 0 {
        return Err(format!("{what}: {}", io::Error::last_os_error()).into());
    }
    Ok(())
}

fn mount(src: &str, dst: &str, fs: &str, opts: &str) -> Res<()> {
    // SAFETY: every pointer comes from a CString temporary that lives until the end of the statement, i.e.
    // across the call; mount does not keep the pointers.
    let r = unsafe {
        libc::mount(
            c(src).as_ptr(),
            c(dst).as_ptr(),
            c(fs).as_ptr(),
            0,
            c(opts).as_ptr().cast(),
        )
    };
    sys(r as _, &format!("mount {dst}"))
}

fn init() -> Res<()> {
    mount("devtmpfs", "/dev", "devtmpfs", "")?;
    mount("proc", "/proc", "proc", "")?;
    // SAFETY: the path is a NUL-terminated CString temporary alive across the call.
    let fd = unsafe { libc::open(c("/dev/console").as_ptr(), libc::O_RDWR) };
    for i in 0..3 {
        // SAFETY: dup2 only touches the fd table; an invalid `fd` (-1 on open failure) just yields EBADF.
        unsafe { libc::dup2(fd, i) };
    }
    for m in fs::read_to_string("/modules")?.lines() {
        let f = fs::File::open(format!("/lib/{m}.ko.xz"))?;
        use std::os::fd::AsRawFd;
        // MODULE_INIT_COMPRESSED_FILE = 4
        // SAFETY: `f` stays open across the call and the empty param string is a CString temporary alive across it;
        // finit_module does not keep either.
        let r = unsafe { libc::syscall(libc::SYS_finit_module, f.as_raw_fd(), c("").as_ptr(), 4) };
        if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            sys(r, &format!("finit_module {m}"))?;
        }
    }
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let arg = |k: &str| {
        cmdline
            .split_whitespace()
            .find_map(|w| w.strip_prefix(k))
            .unwrap_or("")
            .to_owned()
    };
    for _ in 0..100 {
        if Path::new("/dev/vda").exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    mount("/dev/vda", "/mnt", &arg("pl.fs="), &arg("pl.opts="))?;
    let store = Path::new("/mnt/store");
    match arg("pl.mode=").as_str() {
        "write" => loop {
            let mut child = Command::new("/init").arg("write").arg(store).spawn()?;
            thread::sleep(Duration::from_millis(rand::random::<u64>() % 1500 + 200));
            child.kill()?;
            child.wait()?;
        },
        "check" => {
            let res = check(store, arg("pl.committed=").parse()?);
            // SAFETY: sync has no arguments and no preconditions.
            unsafe { libc::sync() };
            // SAFETY: the path is a NUL-terminated CString temporary alive across the call.
            unsafe { libc::umount(c("/mnt").as_ptr()) };
            match res {
                Ok(s) => println!("PASS {s}"),
                Err(e) => println!("FAIL {e}"),
            }
            Ok(())
        }
        m => Err(format!("unknown pl.mode={m:?}").into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let res = match args.get(1).map(String::as_str) {
        Some("write") => write(Path::new(&args[2])),
        Some("check") => check(Path::new(&args[2]), 0).map(|s| println!("PASS {s}")),
        _ if std::process::id() == 1 => {
            let r = init();
            if let Err(e) = &r {
                println!("FAIL init: {e}");
            }
            // SAFETY: reboot with RB_POWER_OFF takes no pointers; as PID 1 of the test VM we may power it off.
            unsafe { libc::reboot(libc::RB_POWER_OFF) };
            r
        }
        _ => Err("usage: powerloss write|check <dir> (or run as /init)".into()),
    };
    if let Err(e) = res {
        eprintln!("FAIL {e}");
        std::process::exit(1);
    }
}
