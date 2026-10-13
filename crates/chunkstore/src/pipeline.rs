//! Parallel chunk insertion (docs/adr.md ADR-001, docs/pve-connector.md "VM backup flow").
//!
//! The producer (the caller's thread) reads chunk data in order and hands each
//! chunk to a bounded queue; worker threads do the CPU and disk work of
//! `Store::insert_chunk_stored` (keyed BLAKE3 id, dedup check, zstd, AEAD seal,
//! write + fsync) and, for partly dirty image chunks, the merge with the
//! previous snapshot's chunk (decrypt + verify of the base). Results come back
//! tagged with the chunk's position and are returned in input order.
//!
//! Memory: the queue holds `workers` chunks, each worker one, the producer the
//! one it is filling: at most `2 * workers + 1` chunk buffers (plus each
//! worker's sealed copy) are alive. Workers are spawned on demand (one per fed
//! chunk until `workers`), so a one-chunk input costs one thread, not N.
//!
//! Failure: the first error (producer or worker) is kept, a flag stops the
//! producer before its next chunk and makes the workers discard what is still
//! queued. Workers exit only when the queue closes (the producer side is
//! dropped), so a producer blocked on a full queue is always drained.

use crate::crypto::ChunkId;
use crate::store::Store;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, Scope};

/// Upper bound of the default worker count (`Options::chunk_workers` = 0).
pub const MAX_DEFAULT_WORKERS: usize = 8;

/// Worker count for `Options::chunk_workers`: an explicit value, else
/// `NEXUS_CHUNK_WORKERS`, else `min(available cores, 8)`; at least 1.
pub(crate) fn resolve_workers(configured: usize) -> usize {
    if configured > 0 {
        return configured;
    }
    if let Some(n) = std::env::var("NEXUS_CHUNK_WORKERS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
    {
        return n;
    }
    thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, MAX_DEFAULT_WORKERS)
}

pub(crate) struct Job {
    /// the chunk's plain bytes (its exact length)
    pub buf: Vec<u8>,
    /// ranges of `buf` the producer did not fill: copied from `base` (zero
    /// beyond its end), or zeroed without a base
    pub holes: Vec<(usize, usize)>,
    pub base: Option<ChunkId>,
}

struct Shared<E> {
    failed: AtomicBool,
    err: Mutex<Option<E>>,
}

impl<E> Shared<E> {
    /// Keeps the first error, then raises the stop flag.
    fn fail(&self, e: E) {
        let mut g = self.err.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            *g = Some(e);
        }
        self.failed.store(true, Ordering::SeqCst);
    }
}

type Done = (usize, ChunkId, u64);
type Queue = Arc<Mutex<Receiver<(usize, Job)>>>;

/// The producer's handle: `push` chunks in order, `buffer` for a recycled buffer.
pub struct ChunkSink<'scope, 'env, E> {
    scope: &'scope Scope<'scope, 'env>,
    store: &'env Store,
    shared: &'env Shared<E>,
    workers: usize,
    spawned: usize,
    next: usize,
    tx: SyncSender<(usize, Job)>,
    /// kept to hand to workers spawned later; dropped once all are spawned so
    /// that `tx.send` fails instead of blocking when every worker is gone
    rx: Option<Queue>,
    done: Sender<Done>,
    free: Receiver<Vec<u8>>,
    free_tx: SyncSender<Vec<u8>>,
}

fn aborted() -> io::Error {
    io::Error::other("chunk pipeline stopped after an error")
}

impl<'scope, 'env, E: From<io::Error> + Send + 'env> ChunkSink<'scope, 'env, E> {
    /// A buffer of `len` bytes (contents unspecified), reusing one a worker finished with.
    pub fn buffer(&mut self, len: usize) -> Vec<u8> {
        let mut b = self.free.try_recv().unwrap_or_default();
        b.resize(len, 0);
        b
    }

    /// Queues one chunk; returns its position in the result. Blocks while the
    /// queue is full; fails once any worker failed.
    pub fn push(&mut self, data: Vec<u8>) -> io::Result<usize> {
        self.feed(Job {
            buf: data,
            holes: Vec::new(),
            base: None,
        })
    }

    pub(crate) fn feed(&mut self, job: Job) -> io::Result<usize> {
        if self.shared.failed.load(Ordering::SeqCst) {
            return Err(aborted());
        }
        if self.spawned < self.workers {
            let rx = if self.spawned + 1 == self.workers {
                self.rx.take()
            } else {
                self.rx.clone()
            }
            .expect("receiver kept until the last worker is spawned");
            let (store, shared, done, free) = (self.store, self.shared, self.done.clone(), self.free_tx.clone());
            self.scope.spawn(move || worker(store, shared, rx, done, free));
            self.spawned += 1;
        }
        let slot = self.next;
        self.tx.send((slot, job)).map_err(|_| aborted())?;
        self.next += 1;
        Ok(slot)
    }
}

/// Sets the stop flag if the worker panics (the scope re-raises the panic).
struct PanicGuard<'a>(&'a AtomicBool);

impl Drop for PanicGuard<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}

fn worker<E: From<io::Error>>(
    store: &Store,
    shared: &Shared<E>,
    rx: Queue,
    done: Sender<Done>,
    free: SyncSender<Vec<u8>>,
) {
    let _guard = PanicGuard(&shared.failed);
    loop {
        let msg = rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
        let Ok((slot, mut job)) = msg else { return };
        if shared.failed.load(Ordering::SeqCst) {
            continue; // drain: the producer may be blocked on a full queue
        }
        match process(store, &mut job) {
            Ok((id, stored)) => {
                let _ = done.send((slot, id, stored));
                let _ = free.try_send(job.buf);
            }
            Err(e) => shared.fail(e.into()),
        }
    }
}

fn process(store: &Store, job: &mut Job) -> io::Result<(ChunkId, u64)> {
    if !job.holes.is_empty() {
        let old = match &job.base {
            Some(id) => store.read_chunk(id)?,
            None => Vec::new(),
        };
        for &(a, b) in &job.holes {
            let k = old.len().clamp(a, b);
            job.buf[a..k].copy_from_slice(&old[a..k]);
            job.buf[k..b].fill(0);
        }
    }
    store.insert_chunk_stored(&job.buf)
}

/// Runs `produce` on the calling thread with `workers` insert threads; returns
/// (id, sealed bytes written or 0 if deduplicated) per pushed chunk, in push order.
pub(crate) fn run<E: From<io::Error> + Send>(
    store: &Store,
    workers: usize,
    produce: impl FnOnce(&mut ChunkSink<'_, '_, E>) -> Result<(), E>,
) -> Result<Vec<(ChunkId, u64)>, E> {
    let workers = workers.max(1);
    let shared = Shared {
        failed: AtomicBool::new(false),
        err: Mutex::new(None),
    };
    let (done, results) = mpsc::channel();
    let pushed = thread::scope(|scope| {
        let (tx, rx) = mpsc::sync_channel(workers);
        let (free_tx, free) = mpsc::sync_channel(workers + 1);
        let mut sink = ChunkSink {
            scope,
            store,
            shared: &shared,
            workers,
            spawned: 0,
            next: 0,
            tx,
            rx: Some(Arc::new(Mutex::new(rx))),
            done,
            free,
            free_tx,
        };
        if let Err(e) = produce(&mut sink) {
            shared.fail(e);
        }
        // dropping the sink closes the queue: the workers finish (or, after a
        // failure, discard) what is queued and exit; the scope joins them
        sink.next
    });
    if let Some(e) = shared.err.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(e);
    }
    let mut out = vec![None; pushed];
    for (slot, id, stored) in results.try_iter() {
        out[slot] = Some((id, stored));
    }
    out.into_iter()
        .map(|r| r.ok_or_else(|| E::from(io::Error::other("chunk pipeline lost a result"))))
        .collect()
}
