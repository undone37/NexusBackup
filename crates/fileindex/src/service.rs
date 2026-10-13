//! The nexus-index service: one sealed Tantivy index per tenant under
//! `<index_base>/<tenant>/`, kept in line with the tenant's store (sync after
//! nudges from the scheduler and periodically), searched by the web-api.
//! Memory: decrypted index blocks live in one cache bounded in bytes; the
//! readers of tenants nobody searched for a while are closed.

use crate::model::{State, TenantIndex};
use crate::sealdir::{BlockCache, SealedDir};
use anyhow::{anyhow, bail, Context, Result};
use chunkstore::snapfile::MetaReader;
use chunkstore::Keyring;
use index_proto::{Request, SearchReq, SearchResp, SourceRules, SourceSnaps, Status, TenantStatus};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub store_base: PathBuf,
    pub index_base: PathBuf,
    pub keyd_socket: PathBuf,
    pub socket: PathBuf,
    /// decrypted index blocks kept in memory
    pub cache_mb: u64,
    /// ingestion pauses while the index file system has less free space
    pub floor_mb: u64,
    /// full comparison of every tenant with its store
    pub sync_secs: u64,
    /// readers of tenants idle this long are closed
    pub idle_secs: u64,
    /// users allowed on the socket besides the service's own (the scheduler runs
    /// as the same user); resolved at start
    pub allowed_users: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            store_base: "/var/lib/nexus/chunkstore".into(),
            index_base: "/var/lib/nexus/index".into(),
            keyd_socket: "/run/nexus-keyd/keyd.sock".into(),
            socket: index_proto::DEFAULT_SOCKET.into(),
            cache_mb: 256,
            floor_mb: 2048,
            sync_secs: 600,
            idle_secs: 900,
            allowed_users: vec!["nexus-webapi".into()],
        }
    }
}

pub type Keys = Arc<dyn Fn(&str) -> io::Result<Keyring> + Send + Sync>;

pub struct Tenant {
    pub name: String,
    pub idx: TenantIndex,
    reader: MetaReader,
    /// one writer at a time (sync, config, rebuild)
    write: Mutex<()>,
    /// per source: (time, has a name index) from the last sync
    snaps: RwLock<BTreeMap<String, Vec<(u64, bool)>>>,
    status: Mutex<TenantStatus>,
    used: Mutex<Instant>,
}

pub struct Service {
    pub cfg: Config,
    keys: Keys,
    cache: Arc<Mutex<BlockCache>>,
    tenants: Mutex<HashMap<String, Arc<Tenant>>>,
    /// tenants to sync soon (nudges); `None` in the set = all
    queue: Mutex<BTreeSet<String>>,
    wake: Condvar,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn valid_tenant(t: &str) -> bool {
    !t.is_empty() && t.len() <= 64 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Free bytes of the file system holding `p`.
fn free_bytes(p: &Path) -> u64 {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) else {
        return 0;
    };
    // SAFETY: statvfs with a valid path and an out struct
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return 0;
    }
    st.f_bavail * st.f_frsize
}

impl Service {
    pub fn new(cfg: Config, keys: Keys) -> Arc<Service> {
        let cache = BlockCache::new((cfg.cache_mb << 20) as usize);
        Arc::new(Service {
            cfg,
            keys,
            cache,
            tenants: Mutex::new(HashMap::new()),
            queue: Mutex::new(BTreeSet::new()),
            wake: Condvar::new(),
        })
    }

    /// Tenants with a store (directories with a key check).
    pub fn tenants_on_disk(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.cfg.store_base)
            .map(|d| {
                d.flatten()
                    .filter(|e| e.path().join("keycheck").is_file())
                    .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                    .filter(|t| valid_tenant(t))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    pub fn tenant(&self, name: &str) -> Result<Arc<Tenant>> {
        if !valid_tenant(name) {
            bail!("tenant: invalid name");
        }
        if let Some(t) = self.tenants.lock().unwrap().get(name) {
            *t.used.lock().unwrap() = Instant::now();
            return Ok(t.clone());
        }
        let root = self.cfg.store_base.join(name);
        if !root.join("keycheck").is_file() {
            bail!("tenant {name}: no store");
        }
        let keys = (self.keys)(name).with_context(|| format!("tenant {name}: keys"))?;
        let reader = MetaReader::new(&root, (self.keys)(name)?);
        reader.check_keys()?;
        let dir = SealedDir::open(&self.cfg.index_base.join(name), Arc::new(keys), self.cache.clone())?;
        let t = Arc::new(Tenant {
            name: name.to_owned(),
            idx: TenantIndex::open(dir)?,
            reader,
            write: Mutex::new(()),
            snaps: RwLock::new(BTreeMap::new()),
            status: Mutex::new(TenantStatus {
                tenant: name.to_owned(),
                ..Default::default()
            }),
            used: Mutex::new(Instant::now()),
        });
        let mut all = self.tenants.lock().unwrap();
        Ok(all.entry(name.to_owned()).or_insert(t).clone())
    }

    pub fn paused(&self) -> bool {
        free_bytes(&self.cfg.index_base) < self.cfg.floor_mb << 20
    }

    /// Compares the tenant's index with its store and ingests the difference.
    pub fn sync(&self, name: &str) -> Result<()> {
        let t = self.tenant(name)?;
        let _w = t.write.lock().unwrap();
        let keys = t.reader.snapshot_keys()?;
        let mut snaps: BTreeMap<String, Vec<(u64, bool)>> = BTreeMap::new();
        for (s, time) in keys {
            let has = t.reader.has_names(&s, time);
            snaps.entry(s).or_default().push((time, has));
        }
        let mut st = t.idx.state();
        let mut changed = false;
        let mut err = None;
        if !self.paused() {
            let mut w = t.idx.writer()?;
            let sources: BTreeSet<String> = snaps.keys().chain(st.sources.keys()).cloned().collect();
            for s in sources {
                let times: Vec<u64> = snaps
                    .get(&s)
                    .map(|v| v.iter().filter(|x| x.1).map(|x| x.0).collect())
                    .unwrap_or_default();
                let rules = st.config.get(&s).cloned().unwrap_or_default();
                match t.idx.sync_source(&mut w, &mut st, &t.reader, &s, &times, &rules) {
                    Ok(c) => changed |= c,
                    Err(e) => {
                        eprintln!("nexus-index: {name}/{s}: {e:#}");
                        err.get_or_insert(format!("{s}: {e:#}"));
                    }
                }
            }
            if changed {
                t.idx.commit(&mut w, &st)?;
            }
            w.wait_merging_threads()?;
        }
        *t.snaps.write().unwrap() = snaps;
        self.update_status(&t, &st, err);
        Ok(())
    }

    fn update_status(&self, t: &Tenant, st: &State, error: Option<String>) {
        let snaps = t.snaps.read().unwrap();
        let mut s = TenantStatus {
            tenant: t.name.clone(),
            docs: t.idx.docs(),
            bytes: t.idx.dir.disk_bytes(),
            sources: snaps.len() as u64,
            last_sync: Some(now()),
            error,
            ..Default::default()
        };
        for (src, v) in snaps.iter() {
            let ing = st.sources.get(src).map(|x| x.ingested.as_slice()).unwrap_or_default();
            let off = st.config.get(src).is_some_and(|r| !r.enabled);
            for (time, has) in v {
                if !has || off {
                    s.snapshots_unindexed += 1;
                } else if ing.binary_search(time).is_ok() {
                    s.snapshots_indexed += 1;
                } else {
                    s.snapshots_pending += 1;
                    s.oldest_pending = Some(s.oldest_pending.map_or(*time, |o| o.min(*time)));
                }
            }
        }
        *t.status.lock().unwrap() = s;
    }

    pub fn search(&self, r: &SearchReq) -> Result<SearchResp> {
        r.validate().map_err(|e| anyhow!(e))?;
        let t0 = Instant::now();
        let t = self.tenant(&r.tenant)?;
        if t.snaps.read().unwrap().is_empty() && t.status.lock().unwrap().last_sync.is_none() {
            // first use since the start: the index may be behind; sync now
            if let Err(e) = self.sync(&r.tenant) {
                eprintln!("nexus-index: {}: {e:#}", r.tenant);
            }
        }
        let (hits, next) = crate::query::run(&t.idx, r).map_err(|e| anyhow!(e))?;
        let st = t.idx.state();
        let snaps = t.snaps.read().unwrap();
        let mut sources = BTreeMap::new();
        for s in crate::query::hit_sources(&hits) {
            let ing = st.sources.get(&s).map(|x| x.ingested.clone()).unwrap_or_default();
            let unindexed = snaps
                .get(&s)
                .map(|v| {
                    v.iter()
                        .map(|x| x.0)
                        .filter(|x| ing.binary_search(x).is_err())
                        .collect()
                })
                .unwrap_or_default();
            sources.insert(
                s,
                SourceSnaps {
                    indexed: ing,
                    unindexed,
                },
            );
        }
        let pending = t.status.lock().unwrap().snapshots_pending;
        Ok(SearchResp {
            hits,
            next,
            elapsed_ms: t0.elapsed().as_millis() as u64,
            sources,
            pending,
        })
    }

    /// New per-source rules: kept in the index payload; changed sources are re-ingested.
    pub fn configure(&self, tenant: &str, sources: BTreeMap<String, SourceRules>) -> Result<bool> {
        for r in sources.values() {
            if !r.include.iter().chain(&r.exclude).all(|x| index_proto::valid_rule(x)) {
                bail!("rules: absolute paths with / separators");
            }
        }
        let t = self.tenant(tenant)?;
        {
            let _w = t.write.lock().unwrap();
            let mut st = t.idx.state();
            if st.config == sources {
                return Ok(false);
            }
            st.config = sources;
            let mut w = t.idx.writer()?;
            t.idx.commit(&mut w, &st)?;
            w.wait_merging_threads()?;
        }
        self.nudge(tenant);
        Ok(true)
    }

    pub fn rebuild(&self, tenant: &str) -> Result<()> {
        let t = self.tenant(tenant)?;
        {
            let _w = t.write.lock().unwrap();
            let mut st = t.idx.state();
            st.sources.clear();
            let mut w = t.idx.writer()?;
            w.delete_all_documents()?;
            t.idx.commit(&mut w, &st)?;
            w.wait_merging_threads()?;
        }
        self.sync(tenant)
    }

    pub fn status(&self, tenant: Option<&str>) -> Result<Status> {
        let mut out = Status {
            free_bytes: free_bytes(&self.cfg.index_base),
            floor_bytes: self.cfg.floor_mb << 20,
            paused: self.paused(),
            cache_limit: self.cfg.cache_mb << 20,
            cache_bytes: self.cache.lock().unwrap().bytes() as u64,
            ..Default::default()
        };
        let names = match tenant {
            Some(t) => vec![t.to_owned()],
            None => self.tenants_on_disk(),
        };
        for n in names {
            let open = self.tenants.lock().unwrap().get(&n).cloned();
            match open {
                Some(t) => out.tenants.push(t.status.lock().unwrap().clone()),
                None => out.tenants.push(TenantStatus {
                    tenant: n.clone(),
                    bytes: SealedDir::bytes_of(&self.cfg.index_base.join(&n)),
                    ..Default::default()
                }),
            }
        }
        Ok(out)
    }

    pub fn nudge(&self, tenant: &str) {
        self.queue.lock().unwrap().insert(tenant.to_owned());
        self.wake.notify_all();
    }

    pub fn handle(&self, req: Request) -> Result<serde_json::Value> {
        Ok(match req {
            Request::Search(r) => serde_json::to_value(self.search(&r)?)?,
            Request::Sync { tenant } => {
                if !valid_tenant(&tenant) {
                    bail!("tenant: invalid name");
                }
                self.nudge(&tenant);
                serde_json::json!({"queued": tenant})
            }
            Request::Config { tenant, sources } => serde_json::json!({"changed": self.configure(&tenant, sources)?}),
            Request::Status { tenant } => serde_json::to_value(self.status(tenant.as_deref())?)?,
            Request::Rebuild { tenant } => {
                self.rebuild(&tenant)?;
                serde_json::json!({"rebuilt": tenant})
            }
        })
    }

    /// Closes the readers of tenants unused for `idle_secs` (memory).
    fn evict(&self) {
        let idle = Duration::from_secs(self.cfg.idle_secs);
        self.tenants
            .lock()
            .unwrap()
            .retain(|_, t| t.used.lock().unwrap().elapsed() < idle);
    }

    /// The sync loop: nudged tenants soon, every tenant each `sync_secs`.
    pub fn run_sync(self: &Arc<Self>) {
        let mut last_full = Instant::now() - Duration::from_secs(self.cfg.sync_secs + 1);
        loop {
            let due: Vec<String> = {
                let mut q = self.queue.lock().unwrap();
                if q.is_empty() && last_full.elapsed() < Duration::from_secs(self.cfg.sync_secs) {
                    q = self.wake.wait_timeout(q, Duration::from_secs(5)).unwrap().0;
                }
                if last_full.elapsed() >= Duration::from_secs(self.cfg.sync_secs) {
                    last_full = Instant::now();
                    q.clear();
                    drop(q);
                    self.tenants_on_disk()
                } else {
                    std::mem::take(&mut *q).into_iter().collect()
                }
            };
            for t in due {
                if let Err(e) = self.sync(&t) {
                    eprintln!("nexus-index: sync {t}: {e:#}");
                    if let Some(x) = self.tenants.lock().unwrap().get(&t) {
                        x.status.lock().unwrap().error = Some(format!("{e:#}"));
                    }
                }
            }
            self.evict();
        }
    }
}
