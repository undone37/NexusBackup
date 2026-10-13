//! Rust SDK for NexusBackup plugins (docs/plugin-sdk.md, contract docs/plugin-system.md).
//!
//! ```no_run
//! use plugin_sdk::{BackupResult, Ctx, Plugin, Result, Sink, Source, Validation};
//! struct Mine;
//! impl Plugin for Mine {
//!     fn validate(&mut self, _ctx: &Ctx) -> Result<Validation> { Ok(Validation::Valid) }
//!     fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
//!         let mut s = sink.stream("dump.sql")?;
//!         std::io::Write::write_all(&mut s, b"...")?;
//!         s.finish()?;
//!         Ok(BackupResult::consistent("1 stream"))
//!     }
//!     fn restore(&mut self, _ctx: &Ctx, src: &mut Source) -> Result<String> {
//!         src.streams(&["dump.sql".into()], |_name, data| { std::io::copy(data, &mut std::io::sink())?; Ok(()) })?;
//!         Ok("done".into())
//!     }
//! }
//! fn main() { plugin_sdk::run(Mine) }
//! ```
//!
//! The runner reads `Init`, dispatches to the trait, frames every message, and turns
//! an `Err` into the protocol's `Error` (code from [`PluginError`], else 1). Plugins
//! never see store, keys or catalog; they only name paths and send bytes.

pub mod export;
pub mod meta;
pub mod sink;
pub mod source;
#[cfg(feature = "testing")]
pub mod testing;

pub use export::{Export, Output};
pub use plugin_proto as proto;
pub use plugin_proto::{BaseEntry, Guest, Kind, Meta, Op, TaggedGuest};
pub use sink::{Sink, StreamWriter, WalkOptions, WalkStats};
pub use source::{FileItem, Mount, RestoreOptions, RestoreStats, Source};

use plugin_proto::{read_msg, write_msg, Message};
use serde_json::Value;
use std::cell::RefCell;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::rc::Rc;

pub type Result<T> = anyhow::Result<T>;

/// An error with a protocol error code (default code 1 for any other error).
#[derive(Debug)]
pub struct PluginError {
    pub code: u32,
    pub message: String,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for PluginError {}

pub fn error(code: u32, message: impl Into<String>) -> anyhow::Error {
    PluginError {
        code,
        message: message.into(),
    }
    .into()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Validation {
    Valid,
    Invalid { field: String, message: String },
}

#[derive(Debug, Clone, Default)]
pub struct BackupResult {
    /// opaque state for the next backup (≤ 1 MiB), returned in `Ctx::state`
    pub state: Option<Vec<u8>>,
    pub consistent: bool,
    pub summary: String,
}

impl BackupResult {
    pub fn consistent(summary: impl Into<String>) -> Self {
        BackupResult {
            state: None,
            consistent: true,
            summary: summary.into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

/// The framed connection to the host (shared by Ctx, Sink, Source).
pub(crate) struct Chan {
    pub r: Box<dyn Read>,
    pub w: Box<dyn Write>,
}

impl Chan {
    pub fn send(&mut self, m: &Message) -> io::Result<()> {
        write_msg(&mut self.w, m)
    }
    pub fn recv(&mut self) -> io::Result<Message> {
        read_msg(&mut self.r)
    }
}

pub(crate) type Shared = Rc<RefCell<Chan>>;

/// What the host asked for.
pub struct Ctx {
    pub job: u64,
    /// manifest kind of the source
    pub kind: String,
    pub op: Op,
    /// the source config (secrets opened; keep them in memory)
    pub config: Value,
    /// op parameters: backup `{"guest", "source_id"}`, restore `{"restore", "params", "snapshot", "streams", "top", "files", "guest"?}`,
    /// mount `{"params", "minutes", "snapshot", …}`
    pub params: Value,
    /// previous snapshot (backup) / the snapshot (restore, mount)
    pub base_time: Option<u64>,
    /// state blob of that snapshot
    pub state: Option<Vec<u8>>,
    pub(crate) chan: Shared,
}

impl Ctx {
    pub fn log(&self, level: Level, text: impl Into<String>) {
        let _ = self.chan.borrow_mut().send(&Message::Log {
            level: level as u8,
            text: text.into(),
        });
    }
    pub fn info(&self, text: impl Into<String>) {
        self.log(Level::Info, text)
    }
    pub fn warn(&self, text: impl Into<String>) {
        self.log(Level::Warn, text)
    }
    pub fn progress(&self, done: u64, total: u64, text: impl Into<String>) {
        let _ = self.chan.borrow_mut().send(&Message::Progress {
            done,
            total,
            text: text.into(),
        });
    }
    /// The guest of this backup (groups with guests), if any.
    pub fn guest(&self) -> Option<&str> {
        self.params["guest"].as_str()
    }
    /// The appliance's id of the source being backed up (backup op): stable and unique per
    /// appliance, e.g. to name objects the plugin creates on the source system.
    pub fn source_id(&self) -> Option<u64> {
        self.params["source_id"].as_u64()
    }
    /// A string config field.
    pub fn config_str(&self, key: &str) -> Result<&str> {
        self.config[key]
            .as_str()
            .ok_or_else(|| error(22, format!("config: {key} missing")))
    }
}

pub trait Plugin {
    /// Connectivity and permission check of the source config.
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation>;
    /// Guests a group can select (databases, VMs, …). Default: none.
    fn list_guests(&mut self, _ctx: &Ctx) -> Result<Vec<Guest>> {
        Ok(Vec::new())
    }
    /// Guests with tags (`type:user`, `pool:x`, …) that auto-protect groups select on
    /// (contract v1.5). Default: [`Plugin::list_guests`] without tags. Without any tag
    /// the answer stays a v1.4 `Guests` message (runs on older hosts too).
    fn list_tagged_guests(&mut self, ctx: &Ctx) -> Result<Vec<TaggedGuest>> {
        Ok(self.list_guests(ctx)?.into_iter().map(TaggedGuest::from).collect())
    }
    fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult>;
    /// A restore of the manifest's `restores[]` (`ctx.params["restore"]`); returns a summary.
    fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String>;
    /// Mount / instant access. Default: unsupported.
    fn mount(&mut self, _ctx: &Ctx, _m: &mut Mount) -> Result<String> {
        Err(error(95, "mount is not supported by this plugin"))
    }
    /// Download with conversion (contract v1.9; manifest: the `download` restore has a
    /// `params_schema`, `ctx.params["params"]` are the user's values). Default: unsupported.
    fn export(&mut self, _ctx: &Ctx, _ex: &mut Export) -> Result<String> {
        Err(error(95, "export is not supported by this plugin"))
    }
}

/// Runs the plugin on stdin/stdout and exits (status 0 = Done sent).
pub fn run<P: Plugin>(p: P) -> ! {
    let code = run_with(p, Box::new(io::stdin()), Box::new(io::stdout()));
    std::process::exit(code)
}

fn send_error(chan: &Shared, e: &anyhow::Error) {
    let (code, message) = match e.downcast_ref::<PluginError>() {
        Some(p) => (p.code, p.message.clone()),
        None => (1, format!("{e:#}")),
    };
    let mut message = message;
    message.truncate(60_000);
    let _ = chan.borrow_mut().send(&Message::Error { code, message });
}

/// Runs one operation on the given streams (the test harness uses pipes). Returns the exit status.
pub fn run_with<P: Plugin>(mut p: P, r: Box<dyn Read + Send>, w: Box<dyn Write + Send>) -> i32 {
    let chan: Shared = Rc::new(RefCell::new(Chan {
        r: Box::new(BufReader::with_capacity(1 << 16, r)),
        w: Box::new(BufWriter::with_capacity(1 << 16, w)),
    }));
    let init = chan.borrow_mut().recv();
    let Ok(Message::Init {
        api,
        job,
        kind,
        op,
        config,
        params,
        base,
        state,
    }) = init
    else {
        eprintln!("plugin: expected Init from the host");
        return 2;
    };
    if api != plugin_proto::API {
        send_error(
            &chan,
            &error(2, format!("plugin speaks api {}, host {api}", plugin_proto::API)),
        );
        return 2;
    }
    let ctx = Ctx {
        job,
        kind,
        op,
        config: serde_json::from_str(&config).unwrap_or(Value::Null),
        params: serde_json::from_str(&params).unwrap_or(Value::Null),
        base_time: base.map(|b| b.time),
        state,
        chan: chan.clone(),
    };
    let r: Result<Message> = match op {
        Op::Validate => p.validate(&ctx).map(|v| match v {
            Validation::Valid => Message::Valid,
            Validation::Invalid { field, message } => Message::Invalid { field, message },
        }),
        Op::ListGuests => p.list_tagged_guests(&ctx).map(|list| {
            if list.iter().all(|g| g.tags.is_empty()) {
                Message::Guests {
                    list: list.into_iter().map(Guest::from).collect(),
                }
            } else {
                Message::TaggedGuests { list }
            }
        }),
        Op::Backup => {
            let mut sink = Sink::new(chan.clone(), ctx.base_time.is_some());
            p.backup(&ctx, &mut sink).and_then(|mut b| {
                if sink.inconsistent > 0 {
                    b.consistent = false;
                }
                if sink.failed > 0 {
                    // v1.7: only sent when needed, so other plugins still run on a v1.6 host
                    chan.borrow_mut()
                        .send(&Message::Warnings {
                            count: sink.failed,
                            samples: std::mem::take(&mut sink.failed_samples),
                        })
                        .map_err(|e| anyhow::anyhow!("host connection: {e}"))?;
                }
                Ok(Message::Done {
                    state: b.state,
                    consistent: b.consistent,
                    summary: b.summary,
                })
            })
        }
        Op::Restore => {
            let mut src = Source::new(chan.clone());
            p.restore(&ctx, &mut src).map(|summary| Message::Done {
                state: None,
                consistent: true,
                summary,
            })
        }
        Op::Export => {
            let mut ex = Export::new(chan.clone());
            p.export(&ctx, &mut ex).map(|summary| Message::Done {
                state: None,
                consistent: true,
                summary,
            })
        }
        Op::Mount => {
            let mut m = Mount::new(chan.clone());
            p.mount(&ctx, &mut m).map(|summary| Message::Done {
                state: None,
                consistent: true,
                summary,
            })
        }
    };
    match r {
        Ok(m) => {
            if chan.borrow_mut().send(&m).is_err() {
                return 1;
            }
            0
        }
        Err(e) => {
            send_error(&chan, &e);
            1
        }
    }
}
