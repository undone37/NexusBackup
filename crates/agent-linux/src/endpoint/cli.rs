//! Scriptable end-user commands (`veeamconfig session list / info` counterparts):
//! `nexus-agent status | sessions | session <id> | request-backup [--json]`.

use super::proto::{Requested, SessionDetail, SessionKind, Status};
use super::{bytes, connect, duration, failure, rate, reach_label, result_label, secs, state_label, Clock, Failure};
use std::fmt::Write;
use std::path::Path;

pub enum Command {
    Status,
    Sessions { limit: usize },
    Session { id: u64 },
    RequestBackup,
}

/// Runs one command against the socket and returns what to print on stdout.
pub fn run(cmd: &Command, sock: &Path, json: bool, clock: Clock) -> Result<String, Failure> {
    let mut c = connect(sock)?;
    let fail = |e| failure(sock, e);
    Ok(match cmd {
        Command::Status => {
            let s = c.status().map_err(fail)?;
            if json {
                pretty(&s)
            } else {
                status_text(&s, clock)
            }
        }
        Command::Sessions { limit } => {
            let s = c.sessions(Some(*limit)).map_err(fail)?;
            if json {
                pretty(&s)
            } else {
                sessions_text(&s, clock)
            }
        }
        Command::Session { id } => {
            let s = c.session(*id).map_err(fail)?;
            if json {
                pretty(&s)
            } else {
                session_text(&s, clock)
            }
        }
        Command::RequestBackup => {
            let r = c.request_backup().map_err(fail)?;
            if json {
                pretty(&r)
            } else {
                requested_text(&r, clock)
            }
        }
    })
}

fn pretty<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default() + "\n"
}

pub fn status_text(s: &Status, clock: Clock) -> String {
    let mut o = String::new();
    let none = "-";
    let _ = writeln!(
        o,
        "Agent:          {} (version {})",
        if s.agent_id.is_empty() { none } else { &s.agent_id },
        s.version
    );
    let _ = writeln!(o, "Appliance:      {}", s.appliance.as_deref().unwrap_or(none));
    if let Some(m) = &s.managed_by {
        let _ = writeln!(o, "Managed by:     {m}");
    }
    let _ = writeln!(o, "State:          {}", state_label(s));
    if let Some(r) = &s.running {
        let pct = r.percent.map(|p| format!("{p:.0} %, ")).unwrap_or_default();
        let _ = writeln!(
            o,
            "Progress:       {pct}read {}, transferred {} (started {})",
            bytes(r.read_bytes),
            bytes(r.transferred_bytes),
            clock.fmt(r.started)
        );
    }
    let _ = writeln!(o, "Last success:   {}", clock.fmt_opt(s.last_success, "never"));
    let _ = writeln!(o, "Next run:       {}", clock.fmt_opt(s.next_run, "not scheduled"));
    let _ = writeln!(o, "Reachability:   {}", reach_label(s, clock));
    if s.reachable {
        let _ = writeln!(
            o,
            "Last contact:   {}",
            clock.fmt_opt(s.last_seen_by_appliance, "never")
        );
    }
    o
}

pub fn sessions_text(list: &[super::proto::Session], clock: Clock) -> String {
    if list.is_empty() {
        return "no backup sessions yet\n".into();
    }
    let mut o = format!(
        "{:<8} {:<13} {:<16} {:>9} {:>12} {:>8}\n",
        "ID", "RESULT", "START", "DURATION", "TRANSFERRED", "WARNINGS"
    );
    for s in list {
        let (g, l) = result_label(s.result);
        let dur = duration(secs(s.started, s.ended));
        let _ = writeln!(
            o,
            "{:<8} {:<13} {:<16} {:>9} {:>12} {:>8}",
            s.id,
            format!("{g} {l}"),
            clock.fmt(s.started),
            dur,
            bytes(s.transferred_bytes),
            s.warnings
        );
    }
    o
}

pub fn session_text(d: &SessionDetail, clock: Clock) -> String {
    let s = &d.session;
    let (g, l) = result_label(s.result);
    let t = secs(s.started, s.ended);
    let mut o = String::new();
    let _ = writeln!(o, "Session:        {} ({})", s.id, kind(s.kind));
    let _ = writeln!(o, "Result:         {g} {l}");
    let _ = writeln!(o, "Start:          {}", clock.fmt(s.started));
    let _ = writeln!(o, "End:            {}", clock.fmt(s.ended));
    let _ = writeln!(o, "Duration:       {}", duration(t));
    let _ = writeln!(o, "Rate:           {}", rate(s.read_bytes, t));
    let _ = writeln!(o, "Read:           {}", bytes(s.read_bytes));
    let _ = writeln!(o, "Transferred:    {}", bytes(s.transferred_bytes));
    let _ = writeln!(o, "New:            {}", bytes(s.new_bytes));
    let _ = writeln!(o, "Warnings:       {}", s.warnings);
    if let Some(e) = &s.first_error {
        let _ = writeln!(o, "First error:    {e}");
    }
    if let Some(t) = s.snapshot_time {
        let _ = writeln!(o, "Restore point:  {}", clock.fmt(t));
    }
    if !d.log_tail.is_empty() {
        o.push_str("Log (last lines):\n");
        for l in &d.log_tail {
            let _ = writeln!(o, "  {l}");
        }
    }
    o
}

pub fn requested_text(r: &Requested, clock: Clock) -> String {
    format!(
        "backup requested at {} (request {}); the appliance starts it at its next poll\n",
        clock.fmt(r.queued_at),
        r.request_id
    )
}

pub fn kind(k: SessionKind) -> &'static str {
    match k {
        SessionKind::Backup => "backup",
        SessionKind::Restore => "restore",
    }
}
