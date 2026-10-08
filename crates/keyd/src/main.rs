use std::ffi::CString;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage:
  keyd init <dir>                       create KEK, print recovery key once
  keyd check-recovery <dir>             recovery key on stdin
  keyd recover <dir>                    recovery key on stdin, re-seal KEK
  keyd tenant-create <dir> <tenant>
  keyd tenant-rotate <dir> <tenant>
  keyd serve <dir> <socket> <allow-user>   allow-user: name or uid of chunkstore";

fn stdin_line() -> io::Result<String> {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

fn resolve_uid(user: &str) -> io::Result<u32> {
    if let Ok(uid) = user.parse() {
        return Ok(uid);
    }
    let name = CString::new(user).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad user"))?;
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("unknown user {user}")));
    }
    Ok(unsafe { (*pw).pw_uid })
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
        ["serve", dir, socket, user] => {
            let uid = resolve_uid(user)?;
            let _ = std::fs::remove_file(socket);
            let listener = UnixListener::bind(socket)?;
            // umask 077 made it 0600; the chunkstore user connects via group nexus-keyd
            std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
            keyd::serve(listener, Path::new(dir), uid)?
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
