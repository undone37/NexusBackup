use std::io::{self, Read};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage:
  keyd init <dir>                       create KEK, print recovery key once
  keyd check-recovery <dir>             recovery key on stdin
  keyd recover <dir>                    recovery key on stdin, re-seal KEK
  keyd tenant-create <dir> <tenant>
  keyd tenant-rotate <dir> <tenant>
  keyd serve <dir> <socket> <allow-uid>";

fn stdin_line() -> io::Result<String> {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

fn run(args: &[String]) -> io::Result<()> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["init", dir] => println!(
            "RECOVERY KEY (record it now, it is shown only once):\n{}",
            keyd::init(Path::new(dir))?
        ),
        ["check-recovery", dir] => keyd::check_recovery_key(Path::new(dir), &stdin_line()?)?,
        ["recover", dir] => keyd::recover(Path::new(dir), &stdin_line()?)?,
        ["tenant-create", dir, t] => println!("{t}: DEK v{}", keyd::create_tenant(Path::new(dir), t)?),
        ["tenant-rotate", dir, t] => println!("{t}: DEK v{}", keyd::rotate_tenant(Path::new(dir), t)?),
        ["serve", dir, socket, uid] => {
            let uid = uid
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad uid"))?;
            let _ = std::fs::remove_file(socket);
            keyd::serve(UnixListener::bind(socket)?, Path::new(dir), uid)?
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE)),
    }
    Ok(())
}

fn main() -> ExitCode {
    keyd::harden_process();
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keyd: {e}");
            ExitCode::FAILURE
        }
    }
}
