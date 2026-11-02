//! `nexusctl system status|reboot|poweroff|cancel` (#179; NexusStor's `storctl system`): reboot or shut down
//! the appliance as the web UI's top bar > Power does. A person's action, never an API token's
//! (crates/web-api/src/power.rs), so this signs in as an administrator like `update upload`. With approvals on
//! the request waits for a second person in the web UI (Approvals); the delay counts from the approval.

use crate::update::{connect, Login};
use anyhow::{bail, Context, Result};
use reqwest::Method;
use serde_json::{json, Value};
use std::time::Duration;

/// What to do.
#[derive(Debug, PartialEq)]
pub enum Cmd {
    Status,
    Request {
        action: String,
        reason: String,
        delay_s: u64,
        force: bool,
    },
    Cancel,
}

/// `<status|reboot|poweroff|cancel> --user NAME [--reason TEXT] [--delay S] [--force]`: the command and the user.
pub fn parse(args: &[String]) -> Result<(Cmd, String)> {
    let usage = "usage: nexusctl system status|reboot|poweroff|cancel --user NAME \
                 [--reason TEXT] [--delay SECONDS] [--force]";
    let mut it = args.iter();
    let verb = it.next().context(usage)?.clone();
    let (mut user, mut reason, mut delay, mut force) = (None, None, 0u64, false);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--user" => user = it.next().cloned(),
            "--reason" => reason = it.next().cloned(),
            "--delay" => {
                delay = it
                    .next()
                    .context("--delay: seconds")?
                    .parse()
                    .context("--delay: seconds")?;
            }
            "--force" => force = true,
            other => bail!("unexpected argument {other:?}\n{usage}"),
        }
    }
    let user = user.context("--user NAME (an administrator) is required")?;
    let cmd = match verb.as_str() {
        "status" => Cmd::Status,
        "cancel" => Cmd::Cancel,
        "reboot" | "poweroff" => {
            if delay > 300 {
                bail!("--delay: 0-300 seconds");
            }
            Cmd::Request {
                action: verb.clone(),
                reason: reason
                    .clone()
                    .context("--reason TEXT is required (it goes to the audit log)")?,
                delay_s: delay,
                force,
            }
        }
        _ => bail!("{usage}"),
    };
    if !matches!(cmd, Cmd::Request { .. }) && (reason.is_some() || delay != 0 || force) {
        bail!("--reason, --delay and --force belong to reboot and poweroff");
    }
    Ok((cmd, user))
}

/// Signs in, runs `cmd` against /system/power, signs out: the API's answer.
pub fn run(url: &str, ca_pem: Option<&str>, login: &mut Login, cmd: &Cmd) -> Result<Value> {
    let s = connect(url, ca_pem, login, Some(Duration::from_secs(60)))?;
    let res = match cmd {
        Cmd::Status => s.call(Method::GET, "/system/power", None),
        Cmd::Cancel => s.call(Method::DELETE, "/system/power", None),
        Cmd::Request {
            action,
            reason,
            delay_s,
            force,
        } => s.call(
            Method::POST,
            "/system/power",
            Some(&json!({"action": action, "reason": reason, "delay_s": delay_s, "force": force})),
        ),
    };
    s.sign_out();
    res
}

/// One line per fact for people.
pub fn render(cmd: &Cmd, v: &Value) -> String {
    let s = |k: &Value| k.as_str().unwrap_or("?").to_owned();
    match cmd {
        Cmd::Request { action, .. } => match v["quorum_id"].as_i64() {
            Some(id) if v["executed"] != true => {
                format!("{action}: approval #{id} pending (Approvals in the web UI); it starts once approved\n")
            }
            _ => format!("{action} scheduled in {} s\n", v["delay_s"].as_u64().unwrap_or(0)),
        },
        Cmd::Cancel => format!("{} cancelled\n", s(&v["action"])),
        Cmd::Status => {
            let mut out = format!("appliance: {}\n", s(&v["appliance"]));
            match v["pending"].as_object() {
                Some(p) => {
                    out += &format!(
                        "scheduled: {} at {} (unix time), requested by {}{}: {}\n",
                        s(&p["action"]),
                        p["at"],
                        s(&p["requested_by"]),
                        p["approved_by"]
                            .as_str()
                            .map(|a| format!(", approved by {a}"))
                            .unwrap_or_default(),
                        s(&p["reason"])
                    );
                }
                None => out += "scheduled: nothing\n",
            }
            if let Some(q) = v["request_pending"].as_object() {
                out += &format!(
                    "waiting for approval: #{} {} by {}\n",
                    q["id"],
                    s(&q["action"]),
                    s(&q["requested_by"])
                );
            }
            if let Some(l) = v["last"].as_object() {
                out += &format!("last: {} {}: {}\n", s(&l["action"]), s(&l["result"]), s(&l["detail"]));
            }
            out += &format!("running jobs: {}\n", v["running_jobs"].as_i64().unwrap_or(0));
            for b in v["blockers"].as_array().into_iter().flatten() {
                out += &format!("blocked: {}\n", s(b));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parsing() {
        assert_eq!(
            parse(&args("reboot --user ada --reason kernel --delay 60")).unwrap(),
            (
                Cmd::Request {
                    action: "reboot".into(),
                    reason: "kernel".into(),
                    delay_s: 60,
                    force: false
                },
                "ada".into()
            )
        );
        assert_eq!(parse(&args("status --user ada")).unwrap().0, Cmd::Status);
        assert_eq!(parse(&args("cancel --user ada")).unwrap().0, Cmd::Cancel);
        for (bad, want) in [
            ("reboot --user ada", "--reason"),
            ("poweroff --user ada --reason x --delay 301", "0-300"),
            ("reboot --reason x", "--user"),
            ("halt --user ada", "usage"),
            ("status --user ada --force", "belong to"),
            ("reboot --user ada --reason x --now", "unexpected"),
        ] {
            let e = parse(&args(bad)).unwrap_err().to_string();
            assert!(e.contains(want), "{bad}: {e}");
        }
    }

    #[test]
    fn rendering() {
        let r = Cmd::Request {
            action: "reboot".into(),
            reason: "x".into(),
            delay_s: 0,
            force: false,
        };
        assert!(render(&r, &json!({"quorum_id": 7, "delay_s": 60})).contains("approval #7 pending"));
        assert_eq!(
            render(&r, &json!({"approvals": "disabled", "executed": true, "delay_s": 60})),
            "reboot scheduled in 60 s\n"
        );
        let v = json!({"appliance": "nb1", "pending": {"action": "poweroff", "at": 100, "requested_by": "ada",
                       "approved_by": "sam", "reason": "rack"}, "running_jobs": 2,
                       "blockers": ["an update is being checked"], "last": null});
        let out = render(&Cmd::Status, &v);
        assert!(
            out.contains("scheduled: poweroff at 100 (unix time), requested by ada, approved by sam: rack"),
            "{out}"
        );
        assert!(
            out.contains("running jobs: 2\nblocked: an update is being checked\n"),
            "{out}"
        );
    }
}
