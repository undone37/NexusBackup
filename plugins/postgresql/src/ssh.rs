//! SSH to the restore host (pure Rust, russh): runs one command per channel and
//! streams stdin to it. The server's host key is pinned (no TOFU). Used by the
//! point-in-time restore to unpack a data directory (`tar -x`) on the target host.

use anyhow::{anyhow, bail, Context, Result};
use russh::client;
use russh::keys::{self, Algorithm, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::ChannelMsg;
use std::borrow::Cow;
use std::io::{self, Write};
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
pub struct Exec<'a> {
    ssh: &'a Ssh,
    ch: russh::Channel<client::Msg>,
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
        Ok(Exec { ssh: self, ch })
    }

    /// Runs `cmd` without input; Err with its stderr unless it exits 0.
    pub fn run(&self, cmd: &str) -> Result<()> {
        self.exec(cmd)?.finish()
    }
}

impl Exec<'_> {
    /// Closes stdin and waits for the exit status.
    pub fn finish(mut self) -> Result<()> {
        let (code, err) = self.ssh.rt.block_on(async {
            let _ = self.ch.eof().await;
            let mut err = Vec::new();
            let mut code = None;
            while let Some(m) = self.ch.wait().await {
                match m {
                    ChannelMsg::ExtendedData { data, .. } if err.len() < 4096 => err.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    ChannelMsg::Failure => bail!("the server refused to run the command"),
                    _ => {}
                }
            }
            Ok((code, err))
        })?;
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
