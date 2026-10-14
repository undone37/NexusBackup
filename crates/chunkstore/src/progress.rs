//! Live job progress (docs/control-plane.md "Live progress"). Connectors print
//! machine lines `progress {json}` on **stderr** (stdout may be a captured job
//! result); the scheduler keeps the newest per item as the job's `progress`
//! and leaves them out of the stored log. One line is one [`Line`]; every field
//! is optional, a line describes the current state (not a delta):
//!
//! ```text
//! progress {"item":"vm-101","label":"dc1dev","item_index":2,"items":3,"part":"scsi0","part_index":1,"parts":2,"done":1048576,"total":4294967296}
//! progress {"item":"vm-101","item_index":2,"items":3,"end":"ok"}
//! ```
//!
//! `done`/`total` are bytes of the current `part` (a disk, the tar stream, the
//! chunk transfer), `entries` counts items of a part without a byte total (an
//! agent's scan, a file index walk) and `entries_total` estimates them.
//! [`start_item`] also prints the human line `item 2/3: vm-101 dc1dev` (it
//! stays in the log). Several items may run at once (parallel
//! guests): the item context is per thread. A [`Meter`] prints at most every
//! [`EVERY`], so the data path pays one `Instant::now()` per call.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::io::Write;
use std::time::{Duration, Instant};

pub const PREFIX: &str = "progress ";

/// Minimum time between two lines of one [`Meter`].
pub const EVERY: Duration = Duration::from_secs(2);

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Line {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// display name (guest name, agent name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// 1-based
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<String>,
    /// 1-based
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<u64>,
    /// estimated `entries` of the part (a percentage without byte totals; may be off)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries_total: Option<u64>,
    /// the item ended: `ok` | `failed`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
}

impl Line {
    /// The line of a `progress {json}` output line (None: any other line).
    pub fn parse(l: &str) -> Option<Line> {
        serde_json::from_str(l.strip_prefix(PREFIX)?.trim_end()).ok()
    }

    pub fn render(&self) -> String {
        format!("{PREFIX}{}\n", serde_json::to_string(self).unwrap_or_default())
    }

    /// One `write` on stderr: lines of parallel threads never interleave.
    pub fn print(&self) {
        let captured = CAPTURE.with(|c| c.borrow_mut().as_mut().map(|v| v.push(self.clone())).is_some());
        if !captured {
            let _ = std::io::stderr().lock().write_all(self.render().as_bytes());
        }
    }

    /// This line with the thread's item context ([`start_item`]).
    fn with_item(mut self) -> Line {
        ITEM.with(|c| {
            if let Some(i) = &*c.borrow() {
                self.item = Some(i.item.clone());
                self.label = i.label.clone();
                self.item_index = i.index;
                self.items = i.items;
            }
        });
        self
    }
}

struct Item {
    item: String,
    label: Option<String>,
    index: Option<u32>,
    items: Option<u32>,
}

thread_local! {
    static ITEM: RefCell<Option<Item>> = const { RefCell::new(None) };
    static CAPTURE: RefCell<Option<Vec<Line>>> = const { RefCell::new(None) };
}

/// Runs `f` with the lines this thread prints collected instead (tests of
/// the connectors' progress).
pub fn capture<R>(f: impl FnOnce() -> R) -> (R, Vec<Line>) {
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    let r = f();
    (r, CAPTURE.with(|c| c.borrow_mut().take().unwrap_or_default()))
}

/// The human line of an item start (`item 2/3: vm-101 dc1dev`).
pub fn item_line(item: &str, label: Option<&str>, index: u32, items: u32) -> String {
    match label.filter(|l| !l.is_empty()) {
        Some(l) => format!("item {index}/{items}: {item} {l}"),
        None => format!("item {index}/{items}: {item}"),
    }
}

/// Item `index` (1-based) of `items` starts on this thread: prints the human
/// line on stdout and a progress line; later [`Meter`]s on this thread carry it.
pub fn start_item(item: &str, label: Option<&str>, index: u32, items: u32) {
    let _ = std::io::stdout()
        .lock()
        .write_all(format!("{}\n", item_line(item, label, index, items)).as_bytes());
    set_item(item, label, Some((index, items)));
}

/// Names the item of a connector that runs one item per process and does not
/// know its position (`nexus-agentctl backup`: the scheduler counts its steps).
pub fn name_item(item: &str, label: Option<&str>) {
    set_item(item, label, None);
}

fn set_item(item: &str, label: Option<&str>, at: Option<(u32, u32)>) {
    ITEM.with(|c| {
        *c.borrow_mut() = Some(Item {
            item: item.to_owned(),
            label: label.filter(|l| !l.is_empty()).map(str::to_owned),
            index: at.map(|a| a.0),
            items: at.map(|a| a.1),
        })
    });
    Line::default().with_item().print();
}

/// [`start_item`] whose `end` line goes out when the guard drops, on every
/// exit path (`failed` unless [`ItemGuard::ok`] was called).
pub fn item(item: &str, label: Option<&str>, index: u32, items: u32) -> ItemGuard {
    start_item(item, label, index, items);
    ItemGuard { ok: false }
}

pub struct ItemGuard {
    ok: bool,
}

impl ItemGuard {
    pub fn ok(&mut self) {
        self.ok = true;
    }
}

impl Drop for ItemGuard {
    fn drop(&mut self) {
        end_item(self.ok);
    }
}

/// The thread's item ended (prints the `end` line, clears the context).
pub fn end_item(ok: bool) {
    let l = Line {
        end: Some(if ok { "ok" } else { "failed" }.into()),
        ..Default::default()
    }
    .with_item();
    ITEM.with(|c| *c.borrow_mut() = None);
    if l.item.is_some() {
        l.print();
    }
}

/// Progress of one part: [`Meter::add`] counts, a line goes out at most every
/// [`EVERY`] (and on start and [`Meter::finish`]).
pub struct Meter {
    line: Line,
    last: Instant,
    every: Duration,
}

impl Meter {
    pub fn new(part: &str, part_index: u32, parts: u32, total: Option<u64>) -> Meter {
        let m = Meter {
            line: Line {
                part: Some(part.to_owned()),
                part_index: Some(part_index),
                parts: Some(parts),
                done: Some(0),
                total,
                ..Default::default()
            }
            .with_item(),
            last: Instant::now(),
            every: EVERY,
        };
        m.line.print();
        m
    }

    /// `done` bytes more.
    pub fn add(&mut self, n: u64) {
        *self.line.done.get_or_insert(0) += n;
        self.tick();
    }

    /// `n` entries more (parts without a byte total).
    pub fn add_entries(&mut self, n: u64) {
        *self.line.entries.get_or_insert(0) += n;
        self.tick();
    }

    pub fn set_total(&mut self, total: u64) {
        self.line.total = Some(total);
    }

    fn tick(&mut self) {
        if self.last.elapsed() >= self.every {
            self.last = Instant::now();
            self.line.print();
        }
    }

    pub fn finish(&mut self) {
        self.line.print();
    }

    /// The line as printed next (tests).
    pub fn line(&self) -> &Line {
        &self.line
    }
}

/// A reader whose bytes count into a [`Meter`] (streams without a known size).
pub struct Reader<R> {
    pub inner: R,
    pub meter: Meter,
}

impl<R: std::io::Read> std::io::Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.meter.add(n as u64);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_item_context() {
        assert_eq!(Line::parse("committed vm-100/5"), None);
        assert_eq!(Line::parse("progress not json"), None);
        let l = Line::parse(r#"progress {"item":"vm-100","done":5,"total":10,"future":1}"#).unwrap();
        assert_eq!(
            (l.item.as_deref(), l.done, l.total),
            (Some("vm-100"), Some(5), Some(10))
        );
        assert_eq!(Line::default().render(), "progress {}\n", "unset fields are left out");
        assert_eq!(item_line("vm-101", Some("dc1dev"), 2, 3), "item 2/3: vm-101 dc1dev");
        assert_eq!(item_line("vm-101", Some(""), 2, 3), "item 2/3: vm-101");
        std::thread::spawn(|| {
            start_item("vm-101", Some("dc1dev"), 2, 3);
            let mut m = Meter::new("scsi0", 1, 2, Some(100));
            m.every = Duration::ZERO;
            m.add(40);
            let l = m.line().clone();
            assert_eq!(l.item.as_deref(), Some("vm-101"));
            assert_eq!(l.label.as_deref(), Some("dc1dev"));
            assert_eq!(
                (l.item_index, l.items, l.done, l.total),
                (Some(2), Some(3), Some(40), Some(100))
            );
            let back = Line::parse(l.render().trim_end()).unwrap();
            assert_eq!(back, l);
            end_item(true);
            assert_eq!(Meter::new("x", 1, 1, None).line().item, None, "context cleared");
        })
        .join()
        .unwrap();
    }
}
