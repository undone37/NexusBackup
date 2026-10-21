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
  keyd serve <dir> <socket> <allow-user> [read-only-group]
                                        allow-user: name or uid of chunkstore; that user's processes
                                        with primary group read-only-group only fetch keyrings
  keyd export-escrow <dir> <tenant> <out-dir>   wrapped KEK + tenant DEKs for the offsite copy
  keyd replica-pubkey <dir>             X25519 key a replication primary seals DEK exports to (hex)";

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
    // SAFETY: `name` is a NUL-terminated CString alive across the call; the CLI resolves the user before
    // it starts any thread, so getpwnam's static buffer is not shared.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("unknown user {user}")));
    }
    // SAFETY: `pw` is non-null and points to getpwnam's static entry, not overwritten since the call above.
    Ok(unsafe { (*pw).pw_uid })
}

fn resolve_gid(group: &str) -> io::Result<u32> {
    if let Ok(gid) = group.parse() {
        return Ok(gid);
    }
    let name = CString::new(group).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad group"))?;
    // SAFETY: as in resolve_uid: NUL-terminated name, resolved before any thread starts.
    let gr = unsafe { libc::getgrnam(name.as_ptr()) };
    if gr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("unknown group {group}"),
        ));
    }
    // SAFETY: `gr` is non-null and points to getgrnam's static entry, not overwritten since the call above.
    Ok(unsafe { (*gr).gr_gid })
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
        ["serve", dir, socket, user, rest @ ..] if rest.len() <= 1 => {
            let peers = keyd::Peers {
                uid: resolve_uid(user)?,
                read_only_gid: rest.first().map(|g| resolve_gid(g)).transpose()?,
            };
            let _ = std::fs::remove_file(socket);
            let listener = UnixListener::bind(socket)?;
            // umask 077 made it 0600; the chunkstore user connects via group nexus-keyd
            std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
            // public material for the configuration backup helper (nexus-config-backup)
            if let Some(run) = Path::new(socket).parent() {
                if let Err(e) = keyd::config_bundle::publish(Path::new(dir), run) {
                    eprintln!("keyd: warning: cannot publish the configuration backup key: {e}");
                }
            }
            keyd::serve(listener, Path::new(dir), peers)?;
        }
        ["export-escrow", dir, tenant, out] => {
            for (name, bytes) in keyd::export_escrow(Path::new(dir), tenant)? {
                let p = Path::new(out).join(&name);
                std::fs::create_dir_all(p.parent().unwrap())?;
                std::fs::write(&p, bytes)?;
                // wrapped blobs only, readable by the offsite uploader's group
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640))?;
            }
        }
        ["replica-pubkey", dir] => println!("{}", chunkstore::crypto::hex(&keyd::replica_pubkey(Path::new(dir))?)),
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
