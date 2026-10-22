//! Standalone mode (Phase 38b/38c, docs/agent-standalone.md): the agent backs up into a repository of its
//! own (the appliance's chunk store format: deduplicated, compressed, encrypted) in a local or mounted
//! directory, without an appliance. The same platform code walks and chunks as in managed mode; this module
//! replaces the appliance's half: chunk ids, the tree, the commit, listing and feeding restores.
//!
//! Keys: a random data key per repository, wrapped under a random recovery key in `key.recovery` inside the
//! repository; the recovery key is shown once as 24 words (crate recovery-key). The agent keeps the data key
//! in its standalone state directory (root/SYSTEM only), so scheduled backups need no input; on another
//! machine the 24 words open the repository.
//!
//! Its own state directory (`<state>/standalone`) keeps the metadata cache apart from managed mode: a file
//! "unchanged" there means unchanged since the last standalone snapshot, whose chunk ids it takes over.

use crate::cache::Cache;
use crate::config::Paths;
use crate::server::{Ctx, Platform, RestoreJob, ScanError};
use agent_proto::{Entry, Filters, Hash, Kind, Overwrite, ScanStats};
use chunkstore::crypto::{generate_key, unwrap_key, wrap_key};
pub use chunkstore::retention::Gfs;
use chunkstore::{ChunkId, Index, Keyring, Options, Store, TreeEntry, TreeKind};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The repository's description (not secret).
const INFO: &str = "standalone.json";
/// The data key wrapped under the recovery key.
const KEY_RECOVERY: &str = "key.recovery";
const LABEL: &str = "nexus-standalone-dek:v1";
const TREE: &str = "tree";
/// Snapshots stay deletable at once: retention is the owner's choice on their own disk (no appliance-side
/// immutability here; S3 Object Lock comes with the S3 target).
const MIN_LOCK_SECS: u64 = 0;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// The standalone state paths: `<state>/standalone` (cache, spool, key).
pub fn state_paths(paths: &Paths) -> Paths {
    Paths {
        state: paths.state.join("standalone"),
        ..paths.clone()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Info {
    version: u32,
    /// repository id: names the local key file
    id: String,
    /// the snapshot source of this machine (`host-<hostname>`)
    source: String,
}

/// An open repository.
pub struct Repo {
    pub store: Store,
    pub source: String,
    dir: PathBuf,
}

/// Held while a backup or a prune writes the repository (`<repo>/lock`, an OS file lock: released when the
/// process ends, also on a crash).
pub struct Lock(#[allow(dead_code)] fs::File);

impl Repo {
    /// The writer lock; fails at once when another backup or prune holds it.
    pub fn lock(&self) -> Result<Lock, String> {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("lock"))
            .map_err(|e| format!("{}: {e}", self.dir.display()))?;
        match f.try_lock() {
            Ok(()) => Ok(Lock(f)),
            Err(fs::TryLockError::WouldBlock) => {
                Err(format!("{}: another backup or prune is running", self.dir.display()))
            }
            Err(fs::TryLockError::Error(e)) => Err(format!("{}: lock: {e}", self.dir.display())),
        }
    }
}

fn key_file(paths: &Paths, id: &str) -> PathBuf {
    state_paths(paths).state.join(format!("repo-{id}.key"))
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        io::Write::write_all(&mut f, data)?;
        f.sync_all()
    }
    // ponytail: on Windows the state directory's ACL (SYSTEM and Administrators) protects the key; DPAPI
    // sealing would also bind it to the machine
    #[cfg(not(unix))]
    fs::write(path, data)
}

fn open_store(dir: &Path, dek: &[u8; 32]) -> Result<Store, String> {
    let opts = Options {
        min_lock_secs: MIN_LOCK_SECS,
        ..Options::default()
    };
    Store::open(dir, Keyring::new("standalone", &[(1, *dek)]), opts).map_err(|e| format!("{}: {e}", dir.display()))
}

/// Creates a repository in the empty (or new) directory `dir` for this machine; returns the recovery key's
/// 24 words, shown once.
pub fn init(paths: &Paths, dir: &Path, hostname: &str) -> Result<String, String> {
    if dir.join(INFO).exists() {
        return Err(format!("{}: already a repository", dir.display()));
    }
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if fs::read_dir(dir).map_err(err)?.next().is_some() {
        return Err(format!("{}: not empty", dir.display()));
    }
    let dek = Zeroizing::new(generate_key());
    let rk = Zeroizing::new(generate_key());
    let id = hex::encode(&generate_key()[..8]);
    let info = Info {
        version: 1,
        id: id.clone(),
        source: format!("host-{}", source_name(hostname)),
    };
    fs::write(dir.join(KEY_RECOVERY), wrap_key(&rk, &dek, LABEL)).map_err(err)?;
    fs::write(
        dir.join(INFO),
        serde_json::to_vec_pretty(&serde_json::json!(info)).map_err(err)?,
    )
    .map_err(err)?;
    write_private(&key_file(paths, &id), hex::encode(*dek).as_bytes()).map_err(err)?;
    open_store(dir, &dek)?;
    Ok(recovery_key::format(&rk))
}

/// A hostname as a snapshot source name part: letters, digits, `.`, `-`, `_` only.
fn source_name(h: &str) -> String {
    let s: String = h
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if s.is_empty() {
        "local".into()
    } else {
        s
    }
}

fn info(dir: &Path) -> Result<Info, String> {
    let b = fs::read(dir.join(INFO)).map_err(|e| format!("{}: not a repository ({e})", dir.display()))?;
    serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", dir.join(INFO).display()))
}

/// Opens a repository with the key this machine keeps; `recovery` (the 24 words) instead opens one this
/// machine has no key for and keeps that key from then on.
pub fn open(paths: &Paths, dir: &Path, recovery: Option<&str>) -> Result<Repo, String> {
    let i = info(dir)?;
    let dek: Zeroizing<[u8; 32]> = match recovery {
        Some(words) => {
            let rk = recovery_key::parse(words)?;
            let wrapped = fs::read(dir.join(KEY_RECOVERY)).map_err(err)?;
            let dek = Zeroizing::new(
                unwrap_key(&rk, &wrapped, LABEL).map_err(|_| "the recovery key does not open this repository")?,
            );
            write_private(&key_file(paths, &i.id), hex::encode(*dek).as_bytes()).map_err(err)?;
            dek
        }
        None => {
            let t = fs::read_to_string(key_file(paths, &i.id))
                .map_err(|_| "this machine has no key for the repository: open it with the recovery key")?;
            let mut k = Zeroizing::new([0u8; 32]);
            hex::decode_to_slice(t.trim(), &mut k[..]).map_err(|_| "local repository key damaged")?;
            k
        }
    };
    Ok(Repo {
        store: open_store(dir, &dek)?,
        source: i.source,
        dir: dir.to_owned(),
    })
}

/// What a standalone backup did.
#[derive(Debug, Default)]
pub struct Summary {
    pub time: u64,
    pub entries: u64,
    pub files: u64,
    pub bytes: u64,
    /// chunks the repository did not have yet
    pub new_chunks: u64,
    pub consistent: bool,
    /// hook and snapshot log text
    pub log: String,
}

fn tree_kind(k: Kind) -> TreeKind {
    match k {
        Kind::File => TreeKind::File,
        Kind::Dir => TreeKind::Dir,
        Kind::Symlink => TreeKind::Symlink,
        Kind::Hardlink => TreeKind::Hardlink,
        Kind::Device => TreeKind::Device,
        Kind::Fifo => TreeKind::Fifo,
        Kind::Socket => TreeKind::Socket,
    }
}

fn proto_kind(k: &TreeKind) -> Kind {
    match k {
        TreeKind::File => Kind::File,
        TreeKind::Dir => Kind::Dir,
        TreeKind::Symlink => Kind::Symlink,
        TreeKind::Hardlink => Kind::Hardlink,
        TreeKind::Device => Kind::Device,
        TreeKind::Fifo => Kind::Fifo,
        TreeKind::Socket => Kind::Socket,
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The newest snapshot of `source` and its tree, by path.
fn previous(store: &Store, source: &str) -> io::Result<HashMap<Vec<u8>, TreeEntry>> {
    let Some(m) = store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == source)
        .max_by_key(|m| m.time)
    else {
        return Ok(HashMap::new());
    };
    Ok(match store.load_index(&m, TREE)? {
        Index::Tree { entries } => entries.into_iter().map(|e| (e.path.clone(), e)).collect(),
        _ => HashMap::new(),
    })
}

/// Backs up `paths` (absolute host paths) into the repository: snapshot, walk, new chunks into the store,
/// commit. Files the metadata cache calls unchanged take their chunk ids from the previous snapshot; if
/// that does not match (the snapshot was deleted, the cache is older), the backup reads everything again.
#[allow(clippy::too_many_arguments)]
pub fn backup<P: Platform>(
    platform: &P,
    ctx: Ctx,
    repo: &Repo,
    job: u64,
    roots: &[String],
    excludes: &[String],
    filters: &Filters,
    hooks: bool,
) -> Result<Summary, String> {
    let _lock = repo.lock()?;
    match backup_once(platform, ctx, repo, job, roots, excludes, filters, hooks, true) {
        Err(Retry) => backup_once(platform, ctx, repo, job, roots, excludes, filters, hooks, false)
            .map_err(|_| "unchanged files without chunks in the previous snapshot twice".to_owned())?,
        Ok(r) => r,
    }
}

/// The cache claimed an unchanged file the previous snapshot cannot back.
struct Retry;

#[allow(clippy::too_many_arguments)]
fn backup_once<P: Platform>(
    platform: &P,
    ctx: Ctx,
    repo: &Repo,
    job: u64,
    roots: &[String],
    excludes: &[String],
    filters: &Filters,
    hooks: bool,
    use_cache: bool,
) -> Result<Result<Summary, String>, Retry> {
    let mut prepared = match platform.prepare(ctx, job, roots, excludes, filters, hooks) {
        Ok(p) => p,
        Err(r) => return Ok(Err(format!("prepare: {}", r.1))),
    };
    let mut sum = Summary {
        consistent: prepared.consistent,
        log: prepared.hook_log.clone(),
        ..Summary::default()
    };
    let cache = if use_cache { Cache::load(ctx.paths) } else { None };
    let mut entries: Vec<Entry> = Vec::new();
    let scanned = platform.scan(
        ctx,
        &mut prepared.job,
        job,
        cache.as_ref().map(|_| 0),
        cache.as_ref(),
        &mut |e| {
            entries.push(e);
            Ok(())
        },
    );
    let result = (|| -> Result<Result<(Cache, Vec<TreeEntry>), ()>, String> {
        let mut out = match scanned {
            Ok(o) => o,
            Err(ScanError::Conn(e)) => return Err(format!("scan: {e}")),
            Err(ScanError::Refused(r)) => return Err(format!("scan: {}", r.1)),
        };
        let prev = previous(&repo.store, &repo.source).map_err(err)?;
        let mut keyed: HashMap<Hash, ChunkId> = HashMap::new();
        let mut tree = Vec::with_capacity(entries.len());
        for e in entries.drain(..) {
            let chunks: Vec<ChunkId> = if e.unchanged {
                match prev.get(&e.path) {
                    Some(p) if p.kind == TreeKind::File && p.size == e.size && p.chunks.len() == e.chunks.len() => {
                        p.chunks.clone()
                    }
                    _ => return Ok(Err(())),
                }
            } else {
                let mut ids = Vec::with_capacity(e.chunks.len());
                for (h, _) in &e.chunks {
                    let id = match keyed.get(h) {
                        Some(id) => *id,
                        None => {
                            let data = out.locator.get(h).ok_or_else(|| {
                                format!("{}: changed while it was read", String::from_utf8_lossy(&e.path))
                            })?;
                            let (id, new) = repo.store.insert_chunk(&data).map_err(err)?;
                            sum.new_chunks += u64::from(new);
                            keyed.insert(*h, id);
                            id
                        }
                    };
                    ids.push(id);
                }
                ids
            };
            if e.kind == Kind::File {
                sum.files += 1;
                sum.bytes += e.size;
            }
            tree.push(TreeEntry {
                chunks,
                path: e.path,
                kind: tree_kind(e.kind),
                mode: e.mode,
                uid: e.uid,
                gid: e.gid,
                size: e.size,
                mtime_ns: e.mtime_ns,
                ctime_ns: e.ctime_ns,
                inode: e.inode,
                rdev: e.rdev,
                link_target: e.link_target,
                xattrs: e.xattrs,
                inconsistent: e.inconsistent,
            });
        }
        // the locator keeps the last read file open: close it before the snapshots go
        drop(out.locator);
        Ok(Ok((out.cache, tree)))
    })();
    let success = matches!(result, Ok(Ok(_)));
    sum.log
        .push_str(&platform.release_snapshots(ctx, &mut prepared.job, job, success));
    let committed = match result {
        Ok(Ok((cache, tree))) => {
            sum.entries = tree.len() as u64;
            sum.time = now();
            let r = repo
                .store
                .commit_snapshot(&repo.source, sum.time, &[(TREE, Index::Tree { entries: tree })])
                .map_err(err)
                .and_then(|_| cache.commit(ctx.paths).map_err(|e| format!("metadata cache: {e}")));
            Some(r)
        }
        Ok(Err(())) => None,
        Err(e) => Some(Err(e)),
    };
    sum.log
        .push_str(&platform.finish_job(ctx, prepared.job, job, matches!(committed, Some(Ok(())))));
    match committed {
        None => Err(Retry),
        Some(Err(e)) => Ok(Err(e)),
        Some(Ok(())) => Ok(Ok(sum)),
    }
}

/// Applies GFS retention to this machine's snapshots, then removes the chunks no snapshot uses any more.
/// Returns a summary line.
pub fn prune(repo: &Repo, gfs: &Gfs) -> Result<String, String> {
    let _lock = repo.lock()?;
    let (kept, deleted, locked) = repo.store.apply_retention(&repo.source, gfs).map_err(err)?;
    // the owner runs it on their own repository: no second approval for large deletions
    let gc = repo.store.gc(true).map_err(err)?;
    Ok(format!(
        "{kept} snapshot(s) kept, {deleted} deleted, {locked} still locked; {} unused chunk(s) removed, {} kept (younger than a day)",
        gc.deleted, gc.kept_grace
    ))
}

/// One snapshot of the repository.
#[derive(Debug, serde::Serialize)]
pub struct Snap {
    pub source: String,
    pub time: u64,
}

/// The repository's snapshots, oldest first.
pub fn list(repo: &Repo) -> Result<Vec<Snap>, String> {
    let mut v: Vec<Snap> = repo
        .store
        .list_snapshots()
        .map_err(err)?
        .into_iter()
        .map(|m| Snap {
            source: m.source,
            time: m.time,
        })
        .collect();
    v.sort_by_key(|s| (s.time, s.source.clone()));
    Ok(v)
}

/// Restores the entries of snapshot `time` below `prefix` (`""` = everything) to `target` through the
/// platform's restore engine (the same one appliance restores use).
pub fn restore<P: Platform>(
    platform: &P,
    ctx: Ctx,
    repo: &Repo,
    time: u64,
    prefix: &str,
    target: &str,
    overwrite: Overwrite,
) -> Result<ScanStats, String> {
    let m = repo
        .store
        .list_snapshots()
        .map_err(err)?
        .into_iter()
        .find(|m| m.source == repo.source && m.time == time)
        .ok_or_else(|| format!("no snapshot {time}"))?;
    let Index::Tree { entries } = repo.store.load_index(&m, TREE).map_err(err)? else {
        return Err("not a file snapshot".into());
    };
    let p = prefix.trim_matches('/').as_bytes();
    let wanted = |path: &[u8]| p.is_empty() || path == p || (path.starts_with(p) && path.get(p.len()) == Some(&b'/'));
    let mut job = platform
        // the local administrator started it (managed restores carry the UI's confirmation token here)
        .restore_begin(ctx, 0, target, overwrite, "standalone")
        .map_err(|e| format!("{target}: {e}"))?;
    // ponytail: one entry per batch and every chunk read once to hash it, again to send it; batch like
    // agent-conn when large restores need it
    for e in entries.iter().filter(|e| wanted(&e.path)) {
        let mut hashes = Vec::with_capacity(e.chunks.len());
        for id in &e.chunks {
            let d = repo.store.read_chunk(id).map_err(err)?;
            hashes.push((*blake3::hash(&d).as_bytes(), d.len() as u32));
        }
        job.entries(vec![Entry {
            path: e.path.clone(),
            kind: proto_kind(&e.kind),
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            size: e.size,
            mtime_ns: e.mtime_ns,
            ctime_ns: e.ctime_ns,
            inode: e.inode,
            rdev: e.rdev,
            link_target: e.link_target.clone(),
            xattrs: e.xattrs.clone(),
            chunks: hashes.clone(),
            unchanged: false,
            inconsistent: e.inconsistent,
        }]);
        if e.kind == TreeKind::File {
            for (id, (h, _)) in e.chunks.iter().zip(&hashes) {
                job.chunk(*h, &repo.store.read_chunk(id).map_err(err)?);
            }
        }
    }
    Ok(job.end())
}

/// Options of the `repo` commands (both agents' command lines).
#[derive(Clone, Debug)]
pub struct CliOpts {
    pub json: bool,
    /// `--path`: restore only this path (and below)
    pub only: String,
    /// `--overwrite never|if-older|always`
    pub overwrite: Overwrite,
    /// `--keep H,D,W,M,Y`
    pub keep: String,
}

impl Default for CliOpts {
    fn default() -> Self {
        CliOpts {
            json: false,
            only: String::new(),
            overwrite: Overwrite::Never,
            keep: "24,7,4,12,0".into(),
        }
    }
}

impl CliOpts {
    /// Takes `--path`, `--overwrite` or `--keep` with its value.
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), String> {
        match name {
            "--path" => self.only = value.to_owned(),
            "--keep" => self.keep = value.to_owned(),
            "--overwrite" => {
                self.overwrite = match value {
                    "never" => Overwrite::Never,
                    "if-older" => Overwrite::IfOlder,
                    "always" => Overwrite::Always,
                    o => return Err(format!("--overwrite: never, if-older or always, not {o}")),
                }
            }
            _ => return Err(format!("unknown option {name}")),
        }
        Ok(())
    }

    fn gfs(&self) -> Result<Gfs, String> {
        let bad = || format!("--keep: five numbers H,D,W,M,Y, not {}", self.keep);
        let n: Vec<u32> = self
            .keep
            .split(',')
            .map(|x| x.trim().parse::<u32>())
            .collect::<Result<_, _>>()
            .map_err(|_| bad())?;
        let [recent, daily, weekly, monthly, yearly] = n[..] else {
            return Err(bad());
        };
        if recent + daily + weekly + monthly + yearly == 0 {
            return Err("--keep: keeping nothing would delete every snapshot".into());
        }
        Ok(Gfs {
            recent,
            daily,
            weekly,
            monthly,
            yearly,
        })
    }
}

/// The usage lines of the `repo` commands (`agent` = the command name).
pub fn usage(agent: &str) -> String {
    format!(
        "standalone mode (administrator; a repository of its own, no appliance; docs/agent-standalone.md):
  {agent} repo init <dir>            new repository; prints the 24-word recovery key once
  {agent} repo open <dir>            on another machine: the 24 words on stdin open it
  {agent} repo backup <dir> <path>…  back up these paths (snapshot where possible)
  {agent} repo list <dir> [--json]
  {agent} repo prune <dir> [--keep H,D,W,M,Y]   keep all of the last H hours plus the last snapshot of
                                         D days, W weeks, M months, Y years (default 24,7,4,12,0);
                                         then unused chunks are removed
  {agent} repo restore <dir> <time> <target> [--path P] [--overwrite never|if-older|always]"
    )
}

/// Runs one `repo` command (`args` after `repo`). `Ok(false)`: done with errors (restore); `Err("")`: the
/// arguments do not form a command (print the usage).
pub fn cli<P: Platform>(
    platform: &P,
    paths: &Paths,
    settings: &crate::config::Settings,
    hostname: &str,
    args: &[&str],
    o: &CliOpts,
) -> Result<bool, String> {
    let sp = state_paths(paths);
    let ctx = Ctx { paths: &sp, settings };
    match args {
        ["init", dir] => {
            let words = init(paths, Path::new(dir), hostname)?;
            println!("Repository {dir} created.\nRECOVERY KEY (record it now, it is shown only once):\n{words}");
        }
        ["open", dir] => {
            let mut words = String::new();
            io::stdin().read_line(&mut words).map_err(|e| format!("stdin: {e}"))?;
            let r = open(paths, Path::new(dir), Some(words.trim()))?;
            println!(
                "{dir}: opened, {} snapshot(s); this machine keeps its key",
                list(&r)?.len()
            );
        }
        ["backup", dir, roots @ ..] if !roots.is_empty() => {
            let r = open(paths, Path::new(dir), None)?;
            fs::create_dir_all(&sp.state).map_err(|e| format!("{}: {e}", sp.state.display()))?;
            let roots: Vec<String> = roots.iter().map(|s| (*s).to_owned()).collect();
            let s = backup(platform, ctx, &r, now(), &roots, &[], &Filters::default(), true)?;
            print!("{}", s.log);
            println!(
                "snapshot {} of {}: {} entries, {} files, {} bytes, {} new chunks{}",
                s.time,
                r.source,
                s.entries,
                s.files,
                s.bytes,
                s.new_chunks,
                if s.consistent {
                    ""
                } else {
                    " (not consistent: no snapshot)"
                }
            );
        }
        ["prune", dir] => {
            let gfs = o.gfs()?;
            let r = open(paths, Path::new(dir), None)?;
            println!("{}", prune(&r, &gfs)?);
        }
        ["list", dir] => {
            let r = open(paths, Path::new(dir), None)?;
            let snaps = list(&r)?;
            if o.json {
                println!("{}", serde_json::to_string(&snaps).map_err(err)?);
            } else {
                for s in snaps {
                    println!("{}  {}", s.time, s.source);
                }
            }
        }
        ["restore", dir, time, target] => {
            let r = open(paths, Path::new(dir), None)?;
            let time = time
                .parse::<u64>()
                .map_err(|_| format!("invalid snapshot time {time}"))?;
            let st = restore(platform, ctx, &r, time, &o.only, target, o.overwrite)?;
            for e in &st.errors {
                eprintln!("{e}");
            }
            println!("restored {} files, {} bytes to {target}", st.files, st.bytes);
            return Ok(st.errors.is_empty());
        }
        _ => return Err(String::new()),
    }
    Ok(true)
}
