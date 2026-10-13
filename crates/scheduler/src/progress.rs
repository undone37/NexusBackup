//! Live progress of a running job (docs/control-plane.md "Live progress"): the
//! connectors' `progress {json}` lines (chunkstore::progress) aggregated into
//! the `jobs.progress` JSON the web UI shows: current item and part, items
//! done / total, bytes of the current part, overall percentage, rate over a
//! sliding window and ETA.

use chunkstore::progress::Line;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

/// Rate window.
const WINDOW: Duration = Duration::from_secs(10);

#[derive(Default)]
pub struct Tracker {
    /// changes since the start (the writer compares)
    pub seq: u64,
    started: Option<Instant>,
    /// (index, count) of the CLI step running: the item of a connector that does
    /// not name its own (one `nexus-agentctl backup` step per agent)
    step: (u32, u32),
    items: Option<u32>,
    /// items in flight, by name
    active: BTreeMap<String, Cur>,
    ended: BTreeSet<String>,
    /// item of the newest line
    last: Option<String>,
    /// bytes moved over all items and parts
    bytes: u64,
    samples: VecDeque<(Instant, u64)>,
}

struct Cur {
    line: Line,
}

fn frac(l: &Line) -> Option<f64> {
    let part = match (l.done, l.total) {
        (Some(d), Some(t)) if t > 0 => (d as f64 / t as f64).min(1.0),
        (_, Some(0)) => 1.0,
        _ => return None,
    };
    Some(match (l.part_index, l.parts) {
        (Some(i), Some(n)) if n > 0 => ((f64::from(i.clamp(1, n)) - 1.0 + part) / f64::from(n)).min(1.0),
        _ => part,
    })
}

impl Tracker {
    /// A CLI step starts (1-based `index` of `count`): items of the previous one ended.
    pub fn step(&mut self, index: u32, count: u32) {
        let prev = std::mem::take(&mut self.active);
        self.ended.extend(prev.into_keys());
        self.step = (index, count);
        self.seq += 1;
    }

    pub fn line(&mut self, mut l: Line, now: Instant) {
        self.started.get_or_insert(now);
        if l.items.is_none() && self.step.1 > 0 {
            // a connector that does not count its items: one per CLI step
            l.item_index = Some(self.step.0);
            l.items = Some(self.step.1);
        }
        if l.item.is_none() {
            l.item = Some(format!("step-{}", self.step.0));
        }
        if let Some(n) = l.items {
            self.items = Some(n);
        }
        let key = l.item.clone().unwrap_or_default();
        self.seq += 1;
        if l.end.is_some() {
            self.active.remove(&key);
            self.ended.insert(key);
            return;
        }
        if let Some(prev) = self.active.get(&key) {
            // the item start line names it once; part lines may leave that out
            l.label = l.label.or_else(|| prev.line.label.clone());
            l.item_index = l.item_index.or(prev.line.item_index);
        }
        let delta = match self.active.get(&key) {
            Some(c) if c.line.part == l.part => l.done.unwrap_or(0).saturating_sub(c.line.done.unwrap_or(0)),
            _ => l.done.unwrap_or(0),
        };
        self.bytes += delta;
        self.samples.push_back((now, self.bytes));
        while self.samples.len() > 2 && now.duration_since(self.samples[1].0) >= WINDOW {
            self.samples.pop_front();
        }
        self.last = Some(key.clone());
        self.active.insert(key, Cur { line: l });
    }

    /// Bytes per second over the last [`WINDOW`] (up to `now`).
    fn rate(&self, now: Instant) -> Option<f64> {
        let (t0, b0) = *self.samples.front()?;
        let span = now.duration_since(t0).as_secs_f64();
        (span >= 1.0).then(|| (self.bytes - b0) as f64 / span)
    }

    /// The `jobs.progress` JSON (None: no progress line yet).
    pub fn snapshot(&self, now: Instant) -> Option<Value> {
        let started = self.started?;
        let cur = self
            .last
            .as_ref()
            .and_then(|k| self.active.get(k))
            .or_else(|| self.active.values().next());
        let items_done = self.ended.len() as u32;
        let items = self.items.map(|n| n.max(items_done));
        let in_flight: f64 = self.active.values().filter_map(|c| frac(&c.line)).sum();
        let overall = items
            .filter(|&n| n > 0)
            .map(|n| ((f64::from(items_done) + in_flight) / f64::from(n)).min(1.0));
        let rate = self.rate(now);
        let elapsed = now.duration_since(started).as_secs_f64();
        let eta = overall
            .filter(|&f| f > 0.01 && elapsed >= 5.0)
            .map(|f| (elapsed * (1.0 - f) / f).round() as u64);
        let item_eta = cur.and_then(|c| {
            let rem = c.line.total?.checked_sub(c.line.done?)?;
            rate.filter(|r| *r > 0.0).map(|r| (rem as f64 / r).round() as u64)
        });
        let pct = |f: f64| (f * 1000.0).round() / 10.0;
        let mut v = json!({
            "items": items, "items_done": items_done,
            "percent": overall.map(pct),
            "bytes": self.bytes,
            "rate": rate.map(|r| r.round() as u64),
            "eta": eta.or(if items.is_none_or(|n| n <= 1) { item_eta } else { None }),
            "item_eta": item_eta,
            "elapsed": elapsed.round() as u64,
            "updated": catalog::now(),
        });
        if let Some(c) = cur {
            let l = &c.line;
            v["item"] = json!(l.item.as_deref().filter(|i| !i.starts_with("step-")));
            v["label"] = json!(l.label);
            v["item_index"] = json!(l.item_index);
            v["part"] = json!(l.part);
            v["part_index"] = json!(l.part_index);
            v["parts"] = json!(l.parts);
            v["done"] = json!(l.done);
            v["total"] = json!(l.total);
            v["entries"] = json!(l.entries);
            v["item_percent"] = json!(frac(l).map(pct));
        }
        if self.active.len() > 1 {
            v["active"] = self
                .active
                .values()
                .map(|c| {
                    let l = &c.line;
                    json!({"item": l.item, "label": l.label, "item_index": l.item_index, "part": l.part,
                           "done": l.done, "total": l.total, "percent": frac(l).map(pct)})
                })
                .collect();
        }
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(s: &str) -> Line {
        Line::parse(&format!("progress {s}")).unwrap()
    }

    #[test]
    fn aggregates_items_parts_rate_and_eta() {
        let t0 = Instant::now();
        let mut t = Tracker::default();
        assert!(t.snapshot(t0).is_none());
        t.line(l(r#"{"item":"vm-100","label":"web","item_index":1,"items":2}"#), t0);
        t.line(
            l(r#"{"item":"vm-100","item_index":1,"items":2,"part":"scsi0","part_index":1,"parts":2,"done":0,"total":1000}"#),
            t0,
        );
        let s = t.line_at(
            r#"{"item":"vm-100","item_index":1,"items":2,"part":"scsi0","part_index":1,"parts":2,"done":500,"total":1000}"#,
            t0 + Duration::from_secs(5),
        );
        assert_eq!(s["item"], "vm-100");
        assert_eq!(s["label"], "web", "named once on the item start line");
        assert_eq!(s["item_percent"], 25.0, "half of the first of two disks");
        assert_eq!(s["percent"], 12.5);
        assert_eq!(s["rate"], 100);
        assert_eq!(s["bytes"], 500);
        assert_eq!(s["item_eta"], 5);
        assert_eq!(s["eta"], 35, "overall: 5 s for 12.5 %");
        // second disk: done restarts, bytes keep counting
        let s = t.line_at(
            r#"{"item":"vm-100","items":2,"part":"scsi1","part_index":2,"parts":2,"done":100,"total":100}"#,
            t0 + Duration::from_secs(6),
        );
        assert_eq!(s["bytes"], 600);
        assert_eq!(s["item_percent"], 100.0);
        let s = t.line_at(r#"{"item":"vm-100","end":"ok"}"#, t0 + Duration::from_secs(6));
        assert_eq!((s["items_done"].as_u64(), s["percent"].as_f64()), (Some(1), Some(50.0)));
        assert!(s.get("item").is_none(), "nothing in flight");
    }

    #[test]
    fn parallel_items_and_steps() {
        let t0 = Instant::now();
        let mut t = Tracker::default();
        t.line(l(r#"{"item":"vm-1","items":4,"done":50,"total":100}"#), t0);
        let s = t.line_at(r#"{"item":"vm-2","items":4,"done":0,"total":100}"#, t0);
        assert_eq!(s["active"].as_array().unwrap().len(), 2);
        assert_eq!(s["percent"], 12.5);
        assert_eq!(s["item"], "vm-2", "newest line is current");
        // connectors without items: one item per CLI step
        let mut t = Tracker::default();
        t.step(1, 3);
        t.line(l(r#"{"part":"transfer","done":10,"total":20}"#), t0);
        t.step(2, 3);
        let s = t.line_at(r#"{"part":"scan","entries":7}"#, t0);
        assert_eq!((s["items_done"].as_u64(), s["items"].as_u64()), (Some(1), Some(3)));
        assert_eq!(s["item_index"], 2);
        assert_eq!(s["item"], serde_json::Value::Null);
        assert_eq!(s["entries"], 7);
    }

    impl Tracker {
        fn line_at(&mut self, s: &str, now: Instant) -> Value {
            self.line(l(s), now);
            self.snapshot(now).unwrap()
        }
    }
}
