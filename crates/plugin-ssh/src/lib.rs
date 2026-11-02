//! SSH for plugins that run commands on a host (Oracle, SQL Server): pure Rust (russh), the server's host key
//! pinned (no TOFU), one command per channel with stdin streamed to it and its stdout back.

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

/// A running remote command; `Write` feeds its stdin, [`Exec::finish`] waits for it.
/// `Read` gives its stdout until EOF.
pub struct Exec<'a> {
    ssh: &'a Ssh,
    ch: russh::Channel<client::Msg>,
    out: Vec<u8>,
    pos: usize,
    eof: bool,
    err: Vec<u8>,
    code: Option<u32>,
}

impl Ssh {
    /// `host_key`: a known_hosts line or an OpenSSH public key line; `key`: an
    /// unencrypted OpenSSH private key (line breaks may be lost by a web form).
    pub fn connect(host: &str, port: u16, user: &str, key: &str, host_key: &str) -> Result<Ssh> {
        let pinned = host_key
            .split_whitespace()
            .find_map(|t| keys::parse_public_key_base64(t).ok())
            .context("ssh_host_key: no SSH public key")?;
        let key = Arc::new(keys::decode_secret_key(&rewrap_pem(key), None).map_err(|e| anyhow!("ssh_key: {e}"))?);
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
            out: Vec::new(),
            pos: 0,
            eof: false,
            err: Vec::new(),
            code: None,
        })
    }

    /// Runs `cmd` without input; Err with its stderr unless it exits 0.
    pub fn run(&self, cmd: &str) -> Result<()> {
        self.exec(cmd)?.finish()
    }

    /// Writes `data` into the file `path` over the SFTP subsystem (created or truncated; the directory must exist);
    /// the bytes written. For hosts whose shell cannot take a binary stdin stream (Windows PowerShell 5.1 over
    /// OpenSSH stalls after 128 KiB). Windows paths as `/C:/dir/file`.
    pub fn upload(&self, path: &str, data: &mut dyn Read) -> Result<u64> {
        use tokio::io::AsyncWriteExt;
        self.rt.block_on(async {
            let ch = self.h.channel_open_session().await?;
            ch.request_subsystem(true, "sftp").await?;
            let sftp = russh_sftp::client::SftpSession::new(ch.into_stream())
                .await
                .map_err(|e| anyhow!("sftp: {e}"))?;
            let mut f = sftp
                .create(path)
                .await
                .map_err(|e| anyhow!("sftp create {path}: {e}"))?;
            let mut buf = vec![0u8; 256 << 10];
            let mut total = 0u64;
            loop {
                let n = data.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                f.write_all(&buf[..n])
                    .await
                    .with_context(|| format!("sftp write {path}"))?;
                total += n as u64;
            }
            f.shutdown().await.with_context(|| format!("sftp close {path}"))?;
            let _ = sftp.close().await;
            Ok(total)
        })
    }

    /// Runs `cmd` with `input` on stdin; its stdout, or Err with stdout and stderr unless it exits 0.
    pub fn output(&self, cmd: &str, input: &[u8]) -> Result<String> {
        let mut e = self.exec(cmd)?;
        e.write_all(input)?;
        e.close_stdin();
        let mut out = Vec::new();
        e.read_to_end(&mut out)?;
        let out = String::from_utf8_lossy(&out).into_owned();
        e.finish().map_err(|err| anyhow!("{err:#}\n{}", tail(&out, 40)))?;
        Ok(out)
    }
}

/// The last `n` lines of `s`.
pub fn tail(s: &str, n: usize) -> String {
    let l: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    l[l.len().saturating_sub(n)..].join("\n")
}

impl Exec<'_> {
    /// Sends EOF on stdin.
    pub fn close_stdin(&mut self) {
        let _ = self.ssh.rt.block_on(self.ch.eof());
    }

    /// The next channel message; stdout data lands in `out`. False at the end of the channel.
    fn pump(&mut self) -> Result<bool> {
        let Some(m) = self.ssh.rt.block_on(self.ch.wait()) else {
            self.eof = true;
            return Ok(false);
        };
        match m {
            ChannelMsg::Data { data } => self.out.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } if self.err.len() < 4096 => self.err.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => self.code = Some(exit_status),
            ChannelMsg::Eof => self.eof = true,
            ChannelMsg::Failure => bail!("the server refused to run the command"),
            _ => {}
        }
        Ok(true)
    }

    /// Closes stdin, skips the rest of stdout and waits for the exit status.
    pub fn finish(mut self) -> Result<()> {
        self.close_stdin();
        while self.pump()? {
            self.out.clear();
        }
        let (code, err) = (self.code, std::mem::take(&mut self.err));
        match code {
            Some(0) => Ok(()),
            c => bail!(
                "remote command failed (exit {}): {}",
                c.map_or("?".into(), |c| c.to_string()),
                String::from_utf8_lossy(&err).trim()
            ),
        }
    }
}

impl Read for Exec<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.out.len() {
            self.out.clear();
            self.pos = 0;
            if self.eof || !self.pump().map_err(io::Error::other)? {
                return Ok(0);
            }
        }
        let n = buf.len().min(self.out.len() - self.pos);
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for Exec<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ssh
            .rt
            .block_on(self.ch.data_bytes(buf.to_vec()))
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("ssh: {e}")))?;
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

/// A PEM block pasted into a single-line (password) field loses its line breaks: rebuild them.
pub fn rewrap_pem(s: &str) -> String {
    if s.contains('\n') {
        return s.to_owned();
    }
    let mut out = String::new();
    let mut rest = s.trim();
    while let Some(b) = rest.find("-----BEGIN ") {
        let after = &rest[b + 11..];
        let Some(l) = after.find("-----") else { break };
        let label = &after[..l];
        let footer = format!("-----END {label}-----");
        let Some(e) = after.find(&footer) else { break };
        let body: String = after[l + 5..e].split_whitespace().collect();
        out += &format!("-----BEGIN {label}-----\n");
        for c in body.as_bytes().chunks(64) {
            out += std::str::from_utf8(c).unwrap_or_default();
            out.push('\n');
        }
        out += &footer;
        out.push('\n');
        rest = &after[e + footer.len()..];
    }
    if out.is_empty() {
        s.to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_without_line_breaks() {
        let one = "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW QyNTUxOQ== -----END OPENSSH PRIVATE KEY-----";
        assert_eq!(
            rewrap_pem(one),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\nc2gtZWQyNTUxOQ==\n-----END OPENSSH PRIVATE KEY-----\n"
        );
        assert_eq!(rewrap_pem("a\nb"), "a\nb");
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        assert_eq!(tail("a\n\nb\nc\n", 2), "b\nc");
    }
}
