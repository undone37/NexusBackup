//! `nexus-fsindex --helper [--mem-mb N] [--cpu-secs N]`: the sandboxed lister,
//! driven over stdin/stdout by the parent (crate docs, `proto.rs`).
//!
//! `nexus-fsindex --local <image>…`: lists raw disk images (development and
//! lab comparisons with the micro-VM listing; not sandboxed): one JSON line
//! per volume, then `<browse>/<path>\t<kind>\t<size>\t<mtime>` per entry.

use fsindex::walk::Driver;
use fsindex::{Limits, Volume};
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;

struct Print<W: Write> {
    w: W,
    browse: String,
}

impl<W: Write> Driver for Print<W> {
    fn begin(&mut self, v: &Volume) -> io::Result<bool> {
        self.browse = v.browse.clone();
        Ok(true)
    }
    fn entry(&mut self, path: &str, size: u64, mtime: i64, kind: u8) -> io::Result<()> {
        writeln!(self.w, "{}/{path}\t{kind}\t{size}\t{mtime}", self.browse)
    }
    fn end(&mut self, v: &Volume) -> io::Result<()> {
        writeln!(self.w, "{}", serde_json::to_string(v)?)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("--helper") => helper(&args[1..]),
        Some("--local") if args.len() > 1 => local(&args[1..]),
        Some("--sandbox-check") => sandbox_check(),
        _ => {
            eprintln!("usage: nexus-fsindex --helper [--mem-mb N] [--cpu-secs N] | --local <image>...");
            std::process::exit(2);
        }
    };
    if let Err(e) = res {
        eprintln!("nexus-fsindex: {e}");
        std::process::exit(1);
    }
}

fn helper(args: &[String]) -> io::Result<()> {
    let (mut mem, mut cpu) = (2048u64, 3720u64);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next().and_then(|v| v.parse().ok());
        match (a.as_str(), v) {
            ("--mem-mb", Some(v)) => mem = v,
            ("--cpu-secs", Some(v)) => cpu = v,
            _ => return Err(io::Error::other(format!("bad argument {a}"))),
        }
    }
    // the lock-free raw handles: buffered here, nothing else is open
    let stdin = io::BufReader::with_capacity(1 << 20, io::stdin().lock());
    let stdout = io::BufWriter::with_capacity(1 << 20, io::stdout().lock());
    fsindex::sandbox::confine(mem, cpu)?;
    fsindex::proto::serve(stdin, stdout)
}

/// Confines itself and tries what the sandbox forbids (tests/images.rs).
fn sandbox_check() -> io::Result<()> {
    fsindex::sandbox::confine(256, 10)?;
    let open = std::fs::File::open("/etc/passwd").is_err();
    // SAFETY: plain system calls; the results are only compared
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) } < 0;
    let exec = std::process::Command::new("/bin/true").status().is_err();
    let w = |b: bool| if b { "denied" } else { "ALLOWED" };
    println!("open: {}, socket: {}, exec: {}", w(open), w(sock), w(exec));
    Ok(())
}

fn local(paths: &[String]) -> io::Result<()> {
    let disks = paths.iter().map(std::fs::File::open).collect::<io::Result<Vec<_>>>()?;
    let io: fsindex::disk::Io = Rc::new(RefCell::new(fsindex::disk::Local { disks }));
    let names: Vec<String> = (0..paths.len()).map(|i| format!("drive-scsi{i}")).collect();
    let mut p = Print {
        w: io::BufWriter::new(io::stdout().lock()),
        browse: String::new(),
    };
    fsindex::walk::run(io, &names, Limits::default(), &mut p)?;
    p.w.flush()
}
