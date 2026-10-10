# offsite

Offsite tier (plan §9): encrypted pack files on a dumb remote, one Hetzner
Storage Box or S3 bucket per tenant. `remote::Remote` is the storage contract;
`remote::conformance()` is the shared test every backend must pass. Remotes
with retention locks (`supports_locks`, `put_locked`, `extend_lock`,
`lock_of`) make `Target` lock every object until its snapshot may go.

## S3 backend

`s3::S3Remote`: own SigV4 client (reqwest blocking + rustls, no AWS SDK), Object
Lock in compliance mode, multipart above 64 MiB, `If-None-Match: *` against
overwrites. Setup, lock semantics, policies and the threat model delta:
[docs/s3-offsite.md](../../docs/s3-offsite.md). Test server:
`testbox-s3/run.sh start` (MinIO with an Object Lock bucket and a restricted
user), then `eval "$(crates/offsite/testbox-s3/run.sh env)"` and
`cargo test -p offsite --test s3`.

## SFTP backend

`sftp::SftpRemote` (pure Rust: russh + russh-sftp) implements `Remote` for a Storage Box.

| Setting | Default | Notes |
|---|---|---|
| `port` | 23 | Hetzner's extended SSH service. It takes OpenSSH-format public keys. Port 22 also serves SFTP but needs RFC4716 keys. |
| `key_file` | – | Unencrypted ed25519 private key (OpenSSH format). |
| `host_key` | – | Pinned server key, given as a known_hosts line or `ssh-ed25519 AAAA…`. Any other key fails the connect. There is no trust-on-first-use. |
| `base_dir` | `""` | All paths are relative to this. Empty means the login directory. |
| `max_connections` | 4 | Pool size. Values above 10 are rejected because the box allows 10 simultaneous connections per account. Each connection carries one SFTP channel. |
| `connect_timeout` | 20 s | Covers TCP, key exchange, auth and SFTP init. |
| `request_timeout` | 60 s | Applies to each SFTP request. A stalled connection is detected after this and replaced. |
| `retries` / `backoff` | 4 / 500 ms | Retries after transport errors. The delay doubles each time, up to 30 s. Protocol answers (not found, exists, permission) are never retried. |

Behaviour:

- **Connections** open lazily. A caller waits when all of them are busy. Dead
  connections are dropped and reopened on the next operation.
- **put** first checks that the target doesn't exist. It then streams the data
  into `<path>.tmp-<unique>` with up to 16 pipelined writes, fsyncs the file
  (`fsync@openssh.com`) and renames it with plain `SSH_FXP_RENAME`. That rename
  never replaces an existing file, so a second put to the same path fails with
  `AlreadyExists`. Missing parent directories are created as with `mkdir -p`,
  and concurrent creation is tolerated.
  - If a put is retried and finds the target present with the expected size, it
    counts as success, because the earlier attempt's rename landed.
  - A connection that dies mid-upload can leave a `*.tmp-*` file behind.
    `Target::check_inventory` reports it as unknown.
- **get** does range reads with up to 16 pipelined requests. Request size is
  taken from `limits@openssh.com` (255 KiB on OpenSSH), otherwise 32 KiB. A
  range past the end of the file is an error.
- **list** is non-recursive and returns sizes plus a directory flag. A missing
  directory gives an empty list.
- **delete** removes one file. **remove_dir** is a plain rmdir: it fails on a
  non-empty directory and never removes recursively.
- **usage()** returns `(total, available)` bytes via `statvfs@openssh.com`, when
  the server supports it.
- The trait is synchronous, so the remote runs a private 2-thread tokio
  runtime. Don't call it from inside another tokio runtime.

Test server: `testbox/run.sh start` starts an OpenSSH SFTP-only server in
rootless podman that behaves like a Storage Box: chroot, key-only auth, no
shell or forwarding, and at most 10 authenticated connections. The extra ones
are refused at auth. Then run:

```
eval "$(crates/offsite/testbox/run.sh env)"
cargo test -p offsite --test sftp -- --nocapture
```

Without that environment the SFTP tests print `SKIP` and pass.
