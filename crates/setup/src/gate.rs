//! Console gate (Phase 14c, `nexus-console-gate` on tty2): the only way to a
//! root shell on the appliance (root's password is locked, there is no sshd).
//!
//! It accepts a one-time code issued by the web-api after an approved
//! `console.unlock` request (catalog::console; the code's file is deleted when
//! it is used) or the recovery key (checked against keyd's escrow as in
//! [`crate::recover`]). Failures are audited and limited to [`MAX_FAILS`] per
//! [`WINDOW_SECS`], with a growing delay after each. A shell is audited
//! (`console.root_shell`, actor `console`), raises the critical alert
//! `console_root_shell`, and sets [`SHELL_SETTING`] for the web UI banner
//! until it ends (`console.root_shell_end`).
//!
//! Everything here is free of terminal I/O and process handling (main: gate_main.rs).

use crate::Paths;
use anyhow::{bail, Context, Result};
use catalog::console::{self, Unlock, MAX_HOURS, SHELL_SETTING};
use catalog::rusqlite::params;
use catalog::Catalog;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const ACTOR: &str = "console";
pub const MAX_FAILS: usize = 5;
pub const WINDOW_SECS: i64 = 15 * 60;

/// Failed attempts (unix times), kept in the gate's runtime dir so that a
/// restart of the gate does not reset them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Limiter {
    fails: Vec<i64>,
}

impl Limiter {
    pub fn load(path: &Path) -> Limiter {
        let fails = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Limiter { fails }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_vec(&self.fails)?).with_context(|| format!("writing {}", path.display()))
    }

    /// Failures within the window.
    pub fn count(&self, now: i64) -> usize {
        self.recent(now).len()
    }

    fn recent(&self, now: i64) -> Vec<i64> {
        self.fails.iter().copied().filter(|t| now - t < WINDOW_SECS).collect()
    }

    /// Seconds until the next attempt is allowed (0 = now): 2, 4, 8, 16 s after
    /// the 1st..4th failure, and after the 5th until the oldest leaves the window.
    pub fn wait(&self, now: i64) -> i64 {
        let r = self.recent(now);
        let Some(&last) = r.last() else { return 0 };
        let until = if r.len() >= MAX_FAILS {
            r[r.len() - MAX_FAILS] + WINDOW_SECS
        } else {
            last + (1 << r.len())
        };
        (until - now).max(0)
    }

    pub fn fail(&mut self, now: i64) {
        self.fails = self.recent(now);
        self.fails.push(now);
    }

    pub fn clear(&mut self) {
        self.fails.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Code(Unlock),
    RecoveryKey,
}

impl Method {
    pub fn name(&self) -> &'static str {
        match self {
            Method::Code(_) => "code",
            Method::RecoveryKey => "recovery_key",
        }
    }
}

/// A running shell, as recorded in the setting.
#[derive(Debug, Clone)]
pub struct Session {
    pub at: i64,
    pub until: i64,
    pub hours: u32,
    pub unit: String,
    pub value: Value,
}

pub struct Gate {
    pub paths: Paths,
    pub unlock_dir: PathBuf,
}

impl Gate {
    pub fn new(paths: Paths, unlock_dir: PathBuf) -> Gate {
        Gate { paths, unlock_dir }
    }

    pub fn ready(&self) -> bool {
        self.paths.setup_done.exists()
    }

    fn cat(&self) -> Result<Catalog> {
        Catalog::open(&self.paths.catalog).with_context(|| format!("opening {}", self.paths.catalog.display()))
    }

    /// Checks the input; a matching code is consumed at once (its file deleted).
    pub fn check(&self, input: &str, now: i64) -> Result<Option<Method>> {
        if !self.ready() {
            bail!("the appliance is not set up yet: the setup wizard runs on tty1");
        }
        let input = input.trim();
        if let Some((file, u)) = console::find(&self.unlock_dir, input, now) {
            std::fs::remove_file(&file).with_context(|| format!("consuming {}", file.display()))?;
            return Ok(Some(Method::Code(u)));
        }
        if keyd::parse_recovery_key(input).is_ok() && keyd::check_recovery_key(&self.paths.keyd_dir, input).is_ok() {
            return Ok(Some(Method::RecoveryKey));
        }
        Ok(None)
    }

    /// Audits a rejected input (never the input itself).
    pub fn failed(&self, fails_in_window: usize) -> Result<()> {
        self.cat()?.audit(
            ACTOR,
            "console.unlock_failed",
            "console",
            &json!({"fails_in_window": fails_in_window, "max": MAX_FAILS}),
        )?;
        Ok(())
    }

    /// Records the shell before it starts: audit, critical alert, banner setting.
    pub fn begin(&self, m: &Method, hours: u32, now: i64) -> Result<Session> {
        if !(1..=MAX_HOURS).contains(&hours) {
            bail!("hours: 1 to {MAX_HOURS}");
        }
        let until = now + i64::from(hours) * 3600;
        let (unlock, who) = match m {
            Method::Code(u) => (
                json!(u.id),
                format!(
                    "one-time code #{} (requested by {}, approved by {}; reason: {})",
                    u.id, u.requested_by, u.approved_by, u.reason
                ),
            ),
            Method::RecoveryKey => (Value::Null, "the recovery key".to_owned()),
        };
        let cat = self.cat()?;
        let alert = {
            let c = cat.conn();
            c.execute(
                "INSERT INTO alerts (ts, last_ts, severity, kind, key, message) VALUES (?1, ?1, 'critical', 'console_root_shell', ?2, ?3)",
                params![
                    now,
                    format!("console_root_shell:{now}"),
                    format!("root shell opened on the appliance console with {who}, for up to {hours} h")
                ],
            )?;
            c.last_insert_rowid()
        };
        let unit = format!("nexus-console-shell-{now}");
        let value = json!({"at": now, "until": until, "method": m.name(), "unlock": unlock, "alert": alert,
                           "unit": unit, "requested_by": match m { Method::Code(u) => json!(u.requested_by), _ => Value::Null }});
        catalog::set_setting(&cat.conn(), SHELL_SETTING, &value.to_string())?;
        let target = match m {
            Method::Code(u) => format!("console-unlock/{}", u.id),
            Method::RecoveryKey => "console".to_owned(),
        };
        let mut details = json!({"method": m.name(), "hours": hours, "until": until, "alert": alert});
        if let Method::Code(u) = m {
            details["unlock"] = json!(u.id);
            details["requested_by"] = json!(u.requested_by);
            details["approved_by"] = json!(u.approved_by);
        }
        cat.audit(ACTOR, "console.root_shell", &target, &details)?;
        Ok(Session {
            at: now,
            until,
            hours,
            unit,
            value,
        })
    }

    /// The shell ended (`how`: exit, timeout, error ...): audit, banner off.
    pub fn end(&self, s: &Session, how: &str, now: i64) -> Result<()> {
        let cat = self.cat()?;
        cat.conn().execute(
            "DELETE FROM settings WHERE key = ?1 AND value = ?2",
            params![SHELL_SETTING, s.value.to_string()],
        )?;
        cat.audit(
            ACTOR,
            "console.root_shell_end",
            "console",
            &json!({"started": s.at, "seconds": now - s.at, "how": how, "method": s.value["method"],
                    "unlock": s.value["unlock"]}),
        )?;
        Ok(())
    }

    /// At start: a banner left by a gate that died during a shell is cleared
    /// and the end audited. Returns the shell's scope unit, which the caller
    /// stops (the restarted unit's TTYVHangup= has already hung up its terminal).
    pub fn clear_stale(&self, now: i64) -> Result<Option<String>> {
        if !self.paths.catalog.exists() {
            return Ok(None);
        }
        let cat = self.cat()?;
        let Some(raw) = catalog::setting(&cat.conn(), SHELL_SETTING)? else {
            return Ok(None);
        };
        let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
        cat.conn()
            .execute("DELETE FROM settings WHERE key = ?1", [SHELL_SETTING])?;
        cat.audit(
            ACTOR,
            "console.root_shell_end",
            "console",
            &json!({"started": v["at"], "seconds": v["at"].as_i64().map(|a| now - a), "how": "gate restarted",
                    "method": v["method"], "unlock": v["unlock"]}),
        )?;
        Ok(v["unit"].as_str().map(str::to_owned))
    }

    /// Deletes the files of expired codes.
    pub fn remove_expired(&self, now: i64) {
        for p in console::expired(&self.unlock_dir, now) {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn appliance() -> (tempfile::TempDir, Gate, String) {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::under(d.path());
        std::fs::create_dir_all(&paths.keyd_dir).unwrap();
        std::fs::create_dir_all(paths.catalog.parent().unwrap()).unwrap();
        let rk = keyd::init(&paths.keyd_dir).unwrap();
        std::fs::write(&paths.setup_done, "").unwrap();
        Catalog::open(&paths.catalog).unwrap();
        let unlock = d.path().join("var/lib/nexus/console-unlock");
        std::fs::create_dir_all(&unlock).unwrap();
        (d, Gate::new(paths, unlock), rk)
    }

    fn issue(g: &Gate, id: i64, hours: u32, expires: i64) -> String {
        let code = console::new_code();
        let u = Unlock {
            id,
            hash: console::hash(&code).unwrap(),
            hours,
            requested_by: "alice".into(),
            approved_by: "sam".into(),
            reason: "driver".into(),
            issued: 1,
            expires,
        };
        std::fs::write(console::path(&g.unlock_dir, id), serde_json::to_vec(&u).unwrap()).unwrap();
        code
    }

    fn count(g: &Gate, sql: &str) -> i64 {
        g.cat().unwrap().conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn limiter_backs_off_and_caps_per_window() {
        let mut l = Limiter::default();
        assert_eq!(l.wait(1000), 0);
        l.fail(1000);
        assert_eq!((l.wait(1000), l.wait(1001), l.wait(1002)), (2, 1, 0));
        for (i, t) in [1002, 1010, 1030, 1060].into_iter().enumerate() {
            l.fail(t);
            if i < 3 {
                assert_eq!(l.wait(t), 1 << (i + 2));
            }
        }
        // 5 failures since 1000: locked until 1000 + 15 min
        assert_eq!(l.wait(1060), 1000 + WINDOW_SECS - 1060);
        assert_eq!(l.wait(1000 + WINDOW_SECS), 0);
        // old failures fall out of the window
        l.fail(1000 + WINDOW_SECS + 10);
        assert_eq!(l.recent(1000 + WINDOW_SECS + 10), vec![1030, 1060, 1910]);
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("attempts");
        l.save(&f).unwrap();
        assert_eq!(Limiter::load(&f), l);
        assert_eq!(Limiter::load(&d.path().join("missing")), Limiter::default());
        l.clear();
        assert_eq!(l.wait(2000), 0);
    }

    #[test]
    fn a_code_works_once_and_is_audited() {
        let (_d, g, _rk) = appliance();
        let now = catalog::now();
        let code = issue(&g, 3, 2, now + 3600);
        let old = issue(&g, 4, 1, now - 1);
        assert_eq!(g.check(&old, now).unwrap(), None, "expired");
        let m = g.check(&format!(" {} ", code.to_lowercase()), now).unwrap().unwrap();
        let Method::Code(u) = &m else { panic!("{m:?}") };
        assert_eq!((u.id, u.hours), (3, 2));
        assert_eq!(g.check(&code, now).unwrap(), None, "one-time");
        assert!(!console::path(&g.unlock_dir, 3).exists());
        g.remove_expired(now);
        assert!(!console::path(&g.unlock_dir, 4).exists());

        let s = g.begin(&m, u.hours, now).unwrap();
        assert_eq!(s.until, now + 7200);
        let c = g.cat().unwrap();
        let v: Value = serde_json::from_str(&catalog::setting(&c.conn(), SHELL_SETTING).unwrap().unwrap()).unwrap();
        assert_eq!((v["method"].as_str(), v["unlock"].as_i64()), (Some("code"), Some(3)));
        let kind: String = c
            .conn()
            .query_row(
                "SELECT kind FROM alerts WHERE id = ?1 AND severity = 'critical'",
                [v["alert"].as_i64()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kind, "console_root_shell");
        let target: String = c
            .conn()
            .query_row(
                "SELECT target FROM audit WHERE action = 'console.root_shell'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(target, "console-unlock/3");
        g.end(&s, "exit", now + 60).unwrap();
        assert!(catalog::setting(&c.conn(), SHELL_SETTING).unwrap().is_none());
        assert_eq!(
            count(&g, "SELECT COUNT(*) FROM audit WHERE action = 'console.root_shell_end'"),
            1
        );
        assert!(c.verify_audit().is_ok());
    }

    #[test]
    fn recovery_key_failures_and_stale_banner() {
        let (_d, g, rk) = appliance();
        let now = catalog::now();
        assert_eq!(g.check(&keyd::format_recovery_key(&[7; 32]), now).unwrap(), None);
        assert_eq!(g.check("hello", now).unwrap(), None);
        g.failed(1).unwrap();
        assert_eq!(
            count(&g, "SELECT COUNT(*) FROM audit WHERE action = 'console.unlock_failed'"),
            1
        );
        let m = g.check(&rk.to_uppercase(), now).unwrap().unwrap();
        assert_eq!(m, Method::RecoveryKey);
        assert!(g.begin(&m, 9, now).is_err());
        let s = g.begin(&m, 8, now).unwrap();
        // the gate died during the shell: the next start clears the banner
        assert_eq!(g.clear_stale(now + 5).unwrap(), Some(s.unit));
        assert!(catalog::setting(&g.cat().unwrap().conn(), SHELL_SETTING)
            .unwrap()
            .is_none());
        assert_eq!(
            count(&g, "SELECT COUNT(*) FROM audit WHERE action = 'console.root_shell_end'"),
            1
        );
        assert_eq!(g.clear_stale(now + 6).unwrap(), None);
        assert_eq!(
            count(&g, "SELECT COUNT(*) FROM audit WHERE action = 'console.root_shell_end'"),
            1
        );
        std::fs::remove_file(&g.paths.setup_done).unwrap();
        assert!(g.check(&rk, now).is_err(), "not set up");
    }
}
