//! SSH to the database host (pure Rust, russh): one command per channel, stdin
//! written to it and its stdout read back as a stream; the server's host key is
//! pinned (no TOFU). Runs mysqldump / mariadb-dump / mariadb-backup / xtrabackup
//! on the database host and the physical restore there (plugins/postgresql/src/ssh.rs
//! plus stdout).

use anyhow::{anyhow, bail, Context, Result};
use russh::client;
use russh::keys::{self, Algorithm, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::ChannelMsg;
use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

struct Pinned(PublicKey);

impl client::Handler for Pinned {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(matches!(key, PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.0.key_data()))
    }
}

pub struct Ssh {
    // field order = drop order: the session goes before the runtime
    h: client::Handle<Pinned>,
    rt: tokio::runtime::Runtime,
}

/// The last bytes of stderr kept for the error message and for parsing tool output.
const STDERR_TAIL: usize = 64 << 10;

/// A running remote command: `Write` feeds its stdin, `Read` returns its stdout,
/// [`Exec::finish`] waits for its exit status.
pub struct Exec<'a> {
    ssh: &'a Ssh,
    ch: russh::Channel<client::Msg>,
    buf: Vec<u8>,
    at: usize,
    eof: bool,
    code: Option<u32>,
    pub stderr: Vec<u8>,
}

impl Ssh {
    /// `host_key`: a known_hosts line or an OpenSSH public key line; `key`: an
    /// unencrypted OpenSSH private key (line breaks may be lost by a web form).
    pub fn connect(host: &str, port: u16, user: &str, key: &str, host_key: &str) -> Result<Ssh> {
        let pinned = host_key
            .split_whitespace()
            .find_map(|t| keys::parse_public_key_base64(t).ok())
            .context("ssh_host_key: no SSH public key")?;
        let key =
            Arc::new(keys::decode_secret_key(&crate::rewrap_pem(key), None).map_err(|e| anyhow!("ssh_key: {e}"))?);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        // negotiate only the pinned key's algorithm
        let algs = match pinned.algorithm() {
            Algorithm::Rsa { .. } => vec![
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
            ],
            a => vec![a],
        };
        let config = Arc::new(client::Config {
            preferred: russh::Preferred {
                key: Cow::Owned(algs),
                ..Default::default()
            },
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 4,
            nodelay: true,
            ..Default::default()
        });
        let h = rt.block_on(async {
            let mut h = tokio::time::timeout(
                Duration::from_secs(30),
                client::connect(config, (host, port), Pinned(pinned)),
            )
            .await
            .map_err(|_| anyhow!("ssh {host}:{port}: connect timeout"))?
            .map_err(|e| match e {
                russh::Error::UnknownKey => anyhow!("ssh {host}:{port}: host key does not match ssh_host_key"),
                e => anyhow!("ssh {host}:{port}: {e}"),
            })?;
            let hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();
            let auth = h
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key, hash))
                .await?;
            if !auth.success() {
                bail!("ssh {host}:{port}: public key authentication as {user} refused");
            }
            Ok::<_, anyhow::Error>(h)
        })?;
        Ok(Ssh { h, rt })
    }

    /// Starts `cmd` (run by the user's login shell).
    pub fn exec(&self, cmd: &str) -> Result<Exec<'_>> {
        let ch = self.rt.block_on(async {
            let ch = self.h.channel_open_session().await?;
            ch.exec(true, cmd).await?;
            Ok::<_, russh::Error>(ch)
        })?;
        Ok(Exec {
            ssh: self,
            ch,
            buf: Vec::new(),
            at: 0,
            eof: false,
            code: None,
            stderr: Vec::new(),
        })
    }

    /// Runs `cmd` without input; its stdout, Err with its stderr unless it exits 0.
    pub fn run(&self, cmd: &str) -> Result<String> {
        let mut e = self.exec(cmd)?;
        e.close_stdin()?;
        let mut out = String::new();
        e.read_to_string(&mut out)?;
        e.finish()?;
        Ok(out)
    }
}

impl Exec<'_> {
    pub fn close_stdin(&mut self) -> Result<()> {
        self.ssh.rt.block_on(self.ch.eof())?;
        Ok(())
    }

    /// Next channel message into the buffers; false at the end of the channel.
    fn pump(&mut self) -> bool {
        let Some(m) = self.ssh.rt.block_on(self.ch.wait()) else {
            self.eof = true;
            return false;
        };
        match m {
            ChannelMsg::Data { data } => {
                self.buf.clear();
                self.buf.extend_from_slice(&data);
                self.at = 0;
            }
            ChannelMsg::ExtendedData { data, .. } => {
                self.stderr.extend_from_slice(&data);
                if self.stderr.len() > STDERR_TAIL {
                    self.stderr.drain(..self.stderr.len() - STDERR_TAIL);
                }
            }
            ChannelMsg::ExitStatus { exit_status } => self.code = Some(exit_status),
            ChannelMsg::Failure => self.code = Some(255),
            _ => {}
        }
        true
    }

    /// The end of stderr, trimmed (for error messages).
    pub fn err_tail(&self) -> String {
        let s = String::from_utf8_lossy(&self.stderr);
        let s = s.trim();
        let start = s.len().saturating_sub(2000);
        let start = (start..=s.len()).find(|i| s.is_char_boundary(*i)).unwrap_or(0);
        s[start..].to_owned()
    }

    /// Closes stdin, discards the rest of stdout and waits for the exit status; its stderr.
    pub fn finish(mut self) -> Result<String> {
        let _ = self.ssh.rt.block_on(self.ch.eof());
        while !self.eof {
            self.pump();
        }
        match self.code {
            Some(0) => Ok(String::from_utf8_lossy(&self.stderr).into_owned()),
            c => bail!(
                "remote command failed (exit {}): {}",
                c.map_or("?".into(), |c| c.to_string()),
                self.err_tail()
            ),
        }
    }
}

impl Read for Exec<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.at >= self.buf.len() {
            if self.eof || !self.pump() {
                return Ok(0);
            }
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

impl Write for Exec<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // a remote command that exited never opens the window again: give up after 10 minutes
        let r = self
            .ssh
            .rt
            .block_on(async { tokio::time::timeout(Duration::from_secs(600), self.ch.data_bytes(buf.to_vec())).await });
        match r {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, format!("ssh: {e}"))),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("ssh: the remote command takes no input ({})", self.err_tail()),
                ))
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A shell single-quoted word.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// An option file (`[client]` user + password) for `--defaults-extra-file`.
pub fn defaults_file(user: &str, password: &str) -> String {
    let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("[client]\nuser=\"{}\"\npassword=\"{}\"\n", q(user), q(password))
}

/// Shell prologue: reads `n` bytes of stdin (an option file with the credentials,
/// never on a command line) into a private temp file `$f`, removed on exit, plus
/// a private temp dir `$d`.
pub fn with_defaults(n: usize, cmd: &str) -> String {
    format!(
        "umask 077; f=$(mktemp) && d=$(mktemp -d) || exit 1; trap 'rm -rf \"$f\" \"$d\"' EXIT; \
         head -c {n} >\"$f\" || exit 1; {cmd}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        assert_eq!(
            defaults_file("nexus", "p\"w\\x"),
            "[client]\nuser=\"nexus\"\npassword=\"p\\\"w\\\\x\"\n"
        );
        assert!(with_defaults(12, "true").contains("head -c 12 >\"$f\""));
    }
}
