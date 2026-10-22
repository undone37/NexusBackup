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
    /// The writer lock; fails at once when another backup, prune or copy holds it.
    pub fn lock(&self) -> Result<Lock, String> {
        Repo::lock_dir(&self.dir)
    }

    fn lock_dir(dir: &Path) -> Result<Lock, String> {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        match f.try_lock() {
            Ok(()) => Ok(Lock(f)),
            Err(fs::TryLockError::WouldBlock) => {
                Err(format!("{}: another backup, prune or copy is running", dir.display()))
            }
            Err(fs::TryLockError::Error(e)) => Err(format!("{}: lock: {e}", dir.display())),
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
            // snapshots are named by the second: a run right after another one (a "run now" after the
            // scheduled run) takes the next free second
            let last = repo
                .store
                .list_snapshots()
                .unwrap_or_default()
                .iter()
                .filter(|m| m.source == repo.source)
                .map(|m| m.time)
                .max()
                .unwrap_or(0);
            sum.time = now().max(last + 1);
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
  {agent} repo restore <dir> <time> <target> [--path P] [--overwrite never|if-older|always]
  {agent} repo copy <dir> <target.json>   mirror the repository to SFTP, S3 or another directory
  {agent} repo fetch <target.json> <dir>  download a copy (then: repo open <dir> with the 24 words)
  {agent} repo jobs [--json]         scheduled jobs ({JOBS_FILE} in the config directory; the service runs them)
  {agent} repo run <job>             run a scheduled job now"
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
        ["copy", dir, target] => {
            let (r, lock_days) = Target::load(Path::new(target))?.open()?;
            let s = copy_to(Path::new(dir), r.as_ref(), lock_days)?;
            println!(
                "{} file(s) uploaded, {} replaced ({} bytes), {} deleted{}",
                s.uploaded,
                s.replaced,
                s.bytes,
                s.deleted,
                if s.kept > 0 {
                    format!(", {} still locked", s.kept)
                } else {
                    String::new()
                }
            );
        }
        ["fetch", target, dir] => {
            let (r, _) = Target::load(Path::new(target))?.open()?;
            let n = fetch_from(r.as_ref(), Path::new(dir))?;
            println!("{n} file(s) fetched into {dir}; open it with: repo open {dir} (24 words on stdin)");
        }
        ["jobs"] => {
            let jobs = load_jobs(paths)?;
            let states = job_states(paths);
            if o.json {
                let v: Vec<_> = jobs
                    .iter()
                    .map(|j| serde_json::json!({"job": j, "state": states.get(&j.name)}))
                    .collect();
                println!("{}", serde_json::to_string(&v).map_err(err)?);
            } else {
                for j in &jobs {
                    let s = states.get(&j.name).cloned().unwrap_or_default();
                    let next = j.schedule().ok().and_then(|x| x.next_slot(now() as i64));
                    println!(
                        "{}: {} -> {} ({}){}{}",
                        j.name,
                        j.paths.join(" "),
                        j.repo,
                        j.schedule,
                        next.map_or(String::new(), |n| format!(", next slot {n}")),
                        match (&s.waiting, &s.last_error, s.last_ok) {
                            (Some(w), _, _) => format!(", waiting: {w}"),
                            (None, Some(e), _) => format!(", last run failed: {e}"),
                            (None, None, Some(t)) => format!(", last ok {t}: {}", s.last_summary),
                            _ => ", never run".into(),
                        }
                    );
                }
            }
        }
        ["run", name] => {
            let jobs = load_jobs(paths)?;
            let job = jobs
                .iter()
                .find(|j| j.name == *name)
                .ok_or_else(|| format!("no job {name} in {JOBS_FILE}"))?;
            println!("{}", run_job(platform, paths, settings, job)?);
        }
        _ => return Err(String::new()),
    }
    Ok(true)
}

// ---- scheduled jobs (Phase 38e) ------------------------------------------------------------------------

/// The jobs file in the agent's configuration directory.
pub const JOBS_FILE: &str = "standalone.json";
const JOB_STATE: &str = "jobs.json";

/// A scheduled standalone backup (`<config>/standalone.json`, `{"jobs": [...]}`).
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Job {
    /// unique, shown in logs and `repo jobs`
    pub name: String,
    /// the repository directory (`repo init` first)
    pub repo: String,
    /// absolute host paths to back up
    pub paths: Vec<String>,
    /// the appliance's schedule grammar (`daily 21:00`, `Mon-Fri 12:30`, `every 4h`, ...)
    pub schedule: String,
    /// IANA time zone of the schedule (default UTC)
    #[serde(default)]
    pub tz: Option<String>,
    /// `--keep H,D,W,M,Y` after each backup; `""` = no pruning
    #[serde(default = "default_keep")]
    pub keep: String,
    /// on battery: wait while the charge is below this (0 = do not wait)
    #[serde(default)]
    pub min_battery: u8,
    /// wait while the network connection is metered
    #[serde(default)]
    pub skip_metered: bool,
    /// after the backup and prune: mirror the repository to this target file (SFTP, S3, directory)
    #[serde(default)]
    pub copy: Option<String>,
}

fn default_keep() -> String {
    CliOpts::default().keep
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct JobsFile {
    jobs: Vec<Job>,
}

/// What happened to a job (`<state>/standalone/jobs.json`).
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
pub struct JobState {
    /// last attempt (unix seconds); a slot counts as done once attempted
    pub last_run: i64,
    pub last_ok: Option<i64>,
    pub last_error: Option<String>,
    /// summary line of the last successful run
    pub last_summary: String,
    /// why a due run waits right now (repository missing, battery, metered network)
    pub waiting: Option<String>,
}

impl Job {
    /// Next slot after `now` (unix seconds), `None` for a broken schedule.
    pub fn next_slot(&self, now: i64) -> Option<i64> {
        self.schedule().ok()?.next_slot(now)
    }

    fn schedule(&self) -> Result<schedule::Schedule, String> {
        let s = schedule::Schedule::parse(&self.schedule).map_err(|e| format!("job {}: {e:#}", self.name))?;
        match &self.tz {
            Some(tz) => s.in_tz(tz).map_err(|e| format!("job {}: {e:#}", self.name)),
            None => Ok(s),
        }
    }
}

/// The configured jobs, checked (an empty list when there is no jobs file).
pub fn load_jobs(paths: &Paths) -> Result<Vec<Job>, String> {
    let p = paths.config.join(JOBS_FILE);
    let b = match fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", p.display())),
    };
    let f: JobsFile = serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut names = std::collections::HashSet::new();
    for j in &f.jobs {
        if j.name.is_empty() || j.name.len() > 64 || !names.insert(j.name.clone()) {
            return Err(format!("{}: job names must be unique, 1..=64 characters", p.display()));
        }
        if j.paths.is_empty() || j.repo.is_empty() {
            return Err(format!("job {}: repo and paths are needed", j.name));
        }
        j.schedule()?;
        if !j.keep.is_empty() {
            CliOpts {
                keep: j.keep.clone(),
                ..CliOpts::default()
            }
            .gfs()
            .map_err(|e| format!("job {}: {e}", j.name))?;
        }
        if j.min_battery > 100 {
            return Err(format!("job {}: min_battery 0..=100", j.name));
        }
    }
    Ok(f.jobs)
}

fn state_file(paths: &Paths) -> PathBuf {
    state_paths(paths).state.join(JOB_STATE)
}

/// The jobs' states by name.
pub fn job_states(paths: &Paths) -> HashMap<String, JobState> {
    fs::read(state_file(paths))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_states(paths: &Paths, s: &HashMap<String, JobState>) -> io::Result<()> {
    let p = state_file(paths);
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
    fs::rename(tmp, p)
}

/// Why a due job waits, if it does: the repository is not there (a disconnected USB disk, an unmounted
/// share), the battery is low, the network is metered.
fn hold(job: &Job, power: &agent_proto::PowerState) -> Option<String> {
    if !Path::new(&job.repo).join(INFO).exists() {
        return Some(format!("repository {} not reachable (disconnected?)", job.repo));
    }
    if job.min_battery > 0 && power.on_battery == Some(true) {
        if let Some(p) = power.battery_percent.filter(|p| *p < job.min_battery) {
            return Some(format!("on battery at {p} % (below {} %)", job.min_battery));
        }
    }
    if job.skip_metered && power.metered == Some(true) {
        return Some("metered network".into());
    }
    None
}

/// Runs one job now: backup, then prune. Returns the summary line.
pub fn run_job<P: Platform>(
    platform: &P,
    paths: &Paths,
    settings: &crate::config::Settings,
    job: &Job,
) -> Result<String, String> {
    let sp = state_paths(paths);
    fs::create_dir_all(&sp.state).map_err(|e| format!("{}: {e}", sp.state.display()))?;
    let ctx = Ctx { paths: &sp, settings };
    let r = open(paths, Path::new(&job.repo), None)?;
    let s = backup(platform, ctx, &r, now(), &job.paths, &[], &Filters::default(), true)?;
    let mut line = format!(
        "snapshot {}: {} files, {} bytes, {} new chunks{}",
        s.time,
        s.files,
        s.bytes,
        s.new_chunks,
        if s.consistent {
            ""
        } else {
            " (no snapshot: not consistent)"
        }
    );
    if !job.keep.is_empty() {
        let gfs = CliOpts {
            keep: job.keep.clone(),
            ..CliOpts::default()
        }
        .gfs()?;
        line.push_str(&format!("; prune: {}", prune(&r, &gfs)?));
    }
    if let Some(t) = &job.copy {
        let (remote, lock_days) = Target::load(Path::new(t))?.open()?;
        let c = copy_to(Path::new(&job.repo), remote.as_ref(), lock_days).map_err(|e| format!("copy: {e}"))?;
        line.push_str(&format!(
            "; copy: {} uploaded, {} replaced, {} deleted",
            c.uploaded, c.replaced, c.deleted
        ));
    }
    Ok(line)
}

/// One pass over the jobs at `now`: runs every due job that does not have to wait. Returns log lines.
pub fn tick<P: Platform>(platform: &P, paths: &Paths, settings: &crate::config::Settings, now: i64) -> Vec<String> {
    // one pass at a time: jobs.json is read, changed and written back
    let _pass = PASS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let jobs = match load_jobs(paths) {
        Ok(j) => j,
        Err(e) => return vec![format!("standalone jobs: {e}")],
    };
    if jobs.is_empty() {
        return Vec::new();
    }
    let mut states = job_states(paths);
    let power = platform.power_state();
    let mut log = Vec::new();
    // the queue stays until a job starts: a waiting job keeps its request
    let requested = queued();
    for job in &jobs {
        let st = states.entry(job.name.clone()).or_default();
        let Ok(sched) = job.schedule() else { continue };
        // "run now" from the local UI: due at once, the waits apply as for a slot
        let asked = requested.contains(&job.name);
        if !asked && !sched.due(st.last_run, now) {
            st.waiting = None;
            continue;
        }
        if let Some(why) = hold(job, &power) {
            if st.waiting.as_deref() != Some(why.as_str()) {
                log.push(format!("job {}: due, waiting: {why}", job.name));
            }
            st.waiting = Some(why);
            continue;
        }
        st.waiting = None;
        st.last_run = now;
        unqueue(&job.name);
        match run_job(platform, paths, settings, job) {
            Ok(line) => {
                log.push(format!("job {}: {line}", job.name));
                st.last_ok = Some(now);
                st.last_error = None;
                st.last_summary = line;
            }
            Err(e) => {
                log.push(format!("job {}: failed: {e}", job.name));
                st.last_error = Some(e);
            }
        }
    }
    states.retain(|n, _| jobs.iter().any(|j| &j.name == n));
    if let Err(e) = save_states(paths, &states) {
        log.push(format!("standalone jobs: state not saved: {e}"));
    }
    log
}

/// The agent service's job loop: a pass every minute, forever (a thread of `run`).
pub fn run_jobs<P: Platform>(platform: &P, paths: &Paths, settings: &crate::config::Settings) {
    loop {
        for l in tick(platform, paths, settings, now() as i64) {
            eprintln!("nexus-agent: {l}");
        }
        // a minute, or until the local UI asks for a run
        let (q, wake) = &*RUN_NOW;
        let g = q.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.is_empty() {
            let _ = wake.wait_timeout(g, std::time::Duration::from_secs(60));
        }
    }
}

/// One job pass at a time (the service's loop, a run asked for by the local UI).
static PASS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Jobs the local UI asked to run now, and the wake-up of the job loop.
static RUN_NOW: std::sync::LazyLock<(std::sync::Mutex<std::collections::BTreeSet<String>>, std::sync::Condvar)> =
    std::sync::LazyLock::new(Default::default);

/// Queues a configured job for the next pass and wakes the job loop (local UI "run now"). The pass applies
/// the usual waits (repository missing, battery, metered network) and records the result.
pub fn request_run(paths: &Paths, name: &str) -> Result<(), String> {
    if !load_jobs(paths)?.iter().any(|j| j.name == name) {
        return Err(format!("no standalone job {name:?}"));
    }
    let (q, wake) = &*RUN_NOW;
    q.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(name.to_owned());
    wake.notify_all();
    Ok(())
}

/// The jobs queued by the local UI and not started yet.
pub fn queued() -> std::collections::BTreeSet<String> {
    RUN_NOW
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn unqueue(name: &str) {
    RUN_NOW
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(name);
}

// ---- copies to SFTP / S3 (Phase 38c) -------------------------------------------------------------------

/// Where a repository is copied to (a JSON file next to the jobs file: it holds credentials, keep it
/// root/Administrators only). `{"kind": "s3", "endpoint": "https://…", "region": "…", "bucket": "…",
/// "prefix": "…", "access_key": "…", "secret_key": "…", "lock_days": 30}`, `{"kind": "sftp", "host": "…",
/// "port": 23, "user": "…", "key_file": "…", "host_key": "ssh-ed25519 AAAA…", "base_dir": "…"}` or
/// `{"kind": "dir", "path": "…"}`.
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Target {
    Dir {
        path: PathBuf,
    },
    Sftp {
        host: String,
        #[serde(default = "sftp_port")]
        port: u16,
        user: String,
        key_file: PathBuf,
        host_key: String,
        #[serde(default)]
        base_dir: String,
    },
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        #[serde(default)]
        prefix: String,
        access_key: String,
        secret_key: String,
        #[serde(default)]
        path_style: bool,
        /// the bucket has Object Lock: chunks stay undeletable this many days after their upload
        #[serde(default)]
        lock_days: u32,
    },
}

fn sftp_port() -> u16 {
    22
}

impl Target {
    /// Reads a target file.
    pub fn load(path: &Path) -> Result<Target, String> {
        let b = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The client and the lock period (days, 0 = none).
    pub fn open(&self) -> Result<(Box<dyn remote::Remote>, u32), String> {
        Ok(match self {
            Target::Dir { path } => (Box::new(remote::LocalDir(path.clone())), 0),
            Target::Sftp {
                host,
                port,
                user,
                key_file,
                host_key,
                base_dir,
            } => {
                let mut c = remote::sftp::SftpConfig::new(host, user, key_file.clone(), host_key);
                c.port = *port;
                c.base_dir = base_dir.clone();
                (Box::new(remote::sftp::SftpRemote::new(c).map_err(err)?), 0)
            }
            Target::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                access_key,
                secret_key,
                path_style,
                lock_days,
            } => {
                let mut c = remote::s3::S3Config::new(endpoint, region, bucket, access_key, secret_key);
                c.prefix = prefix.trim_matches('/').to_owned();
                c.path_style = *path_style;
                c.lock = *lock_days > 0;
                (Box::new(remote::s3::S3Remote::new(c).map_err(err)?), *lock_days)
            }
        })
    }
}

/// What a copy did.
#[derive(Debug, Default)]
pub struct CopyStats {
    pub uploaded: u64,
    pub bytes: u64,
    /// small files that change (manifests, clock) uploaded again
    pub replaced: u64,
    pub deleted: u64,
    /// deletions the remote refused (still locked): tried again next time
    pub kept: u64,
}

/// Files of a repository, relative `/`-separated paths with sizes; the lock file, temporary and corrupt
/// chunk files are not part of a copy.
fn local_files(root: &Path, rel: &str, out: &mut Vec<(String, u64)>) -> io::Result<()> {
    for e in fs::read_dir(if rel.is_empty() {
        root.to_owned()
    } else {
        root.join(rel)
    })? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let path = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let ft = e.file_type()?;
        if ft.is_dir() {
            local_files(root, &path, out)?;
        } else if ft.is_file() && path != "lock" && !name.ends_with(".bad") && !name.contains(".tmp") {
            out.push((path, e.metadata()?.len()));
        }
    }
    Ok(())
}

fn remote_files(r: &dyn remote::Remote, dir: &str, out: &mut HashMap<String, u64>) -> io::Result<()> {
    for (name, size, is_dir) in r.list(dir)? {
        let path = if dir.is_empty() { name } else { format!("{dir}/{name}") };
        if is_dir {
            remote_files(r, &path, out)?;
        } else {
            out.insert(path, size);
        }
    }
    Ok(())
}

/// Order of uploads and deletions: a snapshot's manifest is its commit point, so chunks go up before the
/// snapshot files, those before the manifest, the top-level files last; deletions run the other way round.
fn rank(path: &str) -> u8 {
    if path.starts_with("chunks/") {
        0
    } else if path.starts_with("snapshots/") && !path.ends_with("/manifest") {
        1
    } else if path.starts_with("snapshots/") {
        2
    } else {
        3
    }
}

/// Files that change after they were written: manifests (lock extensions) and the top level (clock).
fn mutable(path: &str) -> bool {
    rank(path) >= 2
}

/// Mirrors the repository directory `dir` to `r`: uploads what the remote lacks (chunks locked for
/// `lock_days` where the remote supports it), replaces manifests and the top-level files, deletes what the
/// repository no longer has. Everything it sends is already encrypted.
pub fn copy_to(dir: &Path, r: &dyn remote::Remote, lock_days: u32) -> Result<CopyStats, String> {
    info(dir)?;
    let _lock = Repo::lock_dir(dir)?;
    let mut local = Vec::new();
    local_files(dir, "", &mut local).map_err(|e| format!("{}: {e}", dir.display()))?;
    local.sort_by(|a, b| (rank(&a.0), &a.0).cmp(&(rank(&b.0), &b.0)));
    let mut have = HashMap::new();
    remote_files(r, "", &mut have).map_err(|e| format!("remote listing: {e}"))?;
    let mut st = CopyStats::default();
    let until = now() + u64::from(lock_days) * 86400;
    for (path, size) in &local {
        let present = have.remove(path);
        if present.is_some() && !mutable(path) {
            continue;
        }
        let data = fs::read(dir.join(path)).map_err(|e| format!("{path}: {e}"))?;
        if present.is_some() {
            r.delete(path).map_err(|e| format!("remote {path}: {e}"))?;
            st.replaced += 1;
        } else {
            st.uploaded += 1;
        }
        st.bytes += size;
        let put = if lock_days > 0 && r.supports_locks() && rank(path) == 0 {
            r.put_locked(path, &data, until)
        } else {
            r.put(path, &data)
        };
        put.map_err(|e| format!("remote {path}: {e}"))?;
    }
    let mut gone: Vec<String> = have.into_keys().collect();
    gone.sort_by(|a, b| (std::cmp::Reverse(rank(a)), a).cmp(&(std::cmp::Reverse(rank(b)), b)));
    for path in gone {
        match r.delete(&path) {
            Ok(()) => st.deleted += 1,
            Err(_) => st.kept += 1,
        }
    }
    Ok(st)
}

/// Downloads a copy into the new or empty directory `dir` (then `open` it with the recovery words).
pub fn fetch_from(r: &dyn remote::Remote, dir: &Path) -> Result<u64, String> {
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if fs::read_dir(dir).map_err(err)?.next().is_some() {
        return Err(format!("{}: not empty", dir.display()));
    }
    let mut files = HashMap::new();
    remote_files(r, "", &mut files).map_err(|e| format!("remote listing: {e}"))?;
    if !files.contains_key(INFO) {
        return Err("the target holds no repository".into());
    }
    let mut n = 0;
    for path in files.keys() {
        remote::check(path).map_err(err)?;
        let data = r.get(path, 0, None).map_err(|e| format!("remote {path}: {e}"))?;
        let p = dir.join(path);
        if let Some(d) = p.parent() {
            fs::create_dir_all(d).map_err(err)?;
        }
        fs::write(&p, data).map_err(|e| format!("{}: {e}", p.display()))?;
        n += 1;
    }
    Ok(n)
}
