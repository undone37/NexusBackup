use super::*;

const MON: i64 = 1_791_763_200; // Monday 2026-10-12 00:00 UTC
const H: i64 = 3600;

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn set_reports(s: &Scheduler, v: Value) {
    catalog::set_setting(&s.db.conn(), reports::SETTING, &v.to_string()).unwrap();
}

/// Plain-text SMTP on loopback: accepts one message and returns its DATA.
fn smtp_stub() -> (u16, std::thread::JoinHandle<String>) {
    use std::io::{BufRead, BufReader, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        let mut w = c.try_clone().unwrap();
        let mut r = BufReader::new(c);
        w.write_all(b"220 stub ESMTP\r\n").unwrap();
        let (mut data, mut in_data) = (String::new(), false);
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if in_data {
                if line == ".\r\n" {
                    in_data = false;
                    w.write_all(b"250 queued\r\n").unwrap();
                } else {
                    data.push_str(&line);
                }
                continue;
            }
            let cmd = line.to_ascii_uppercase();
            let reply: &[u8] = if cmd.starts_with("DATA") {
                in_data = true;
                b"354 go ahead\r\n"
            } else if cmd.starts_with("QUIT") {
                w.write_all(b"221 bye\r\n").unwrap();
                break;
            } else {
                b"250 ok\r\n"
            };
            w.write_all(reply).unwrap();
        }
        data
    });
    (port, h)
}

fn smtp_setting(s: &Scheduler, port: u16) {
    let v = json!({"smtp": {"host": "127.0.0.1", "port": port, "starttls": false, "from": "nexus@example.com"}});
    catalog::set_setting(&s.db.conn(), alerts::SETTING_KEY, &v.to_string()).unwrap();
}

/// A report is queued once per slot (first sight waits), covering the
/// previous slot up to this one; a running one is not queued again.
#[test]
fn scheduled_reports_are_due_once_per_slot() {
    let e = env(4);
    let mut s = sched(&e);
    set_reports(
        &s,
        json!([{"name": "weekly", "types": ["failed"], "schedule": "Mon 07:00", "recipients": ["ops@example.com"]},
               {"name": "broken", "types": ["failed"], "schedule": "hourly 05", "recipients": ["ops@example.com"]}]),
    );
    let jobs = |s: &Scheduler| count(s, "SELECT COUNT(*) FROM jobs WHERE kind = 'report_send'");
    s.now = MON + 6 * H;
    s.queue_reports(s.now).unwrap();
    assert_eq!(jobs(&s), 0, "first sight");
    // an hourly schedule is refused with an alert
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE key = 'report:broken' AND resolved_at IS NULL"
        ),
        1
    );
    s.now = MON + 7 * H + 5;
    s.queue_reports(s.now).unwrap();
    assert_eq!(jobs(&s), 1);
    let p: String =
        s.db.conn()
            .query_row("SELECT params FROM jobs WHERE kind = 'report_send'", [], |r| r.get(0))
            .unwrap();
    let p: Value = serde_json::from_str(&p).unwrap();
    assert_eq!(
        p,
        json!({"name": "weekly", "from": MON + 7 * H - 7 * 24 * H, "to": MON + 7 * H})
    );
    s.now += 60;
    s.queue_reports(s.now).unwrap();
    assert_eq!(jobs(&s), 1, "still queued");
    s.db.conn()
        .execute("UPDATE jobs SET state = 'ok' WHERE kind = 'report_send'", [])
        .unwrap();
    s.now = MON + 3 * 24 * H;
    s.queue_reports(s.now).unwrap();
    assert_eq!(jobs(&s), 1, "once per slot");
    // a manual send does not move the schedule
    let m = manual(&s, "report_send", "-", json!({"name": "weekly", "from": 0, "to": 1}));
    s.db.conn()
        .execute(
            "UPDATE jobs SET state = 'ok', created = ?2 WHERE id = ?1",
            [m, MON + 4 * 24 * H],
        )
        .unwrap();
    s.now = MON + 7 * 24 * H + 7 * H;
    s.queue_reports(s.now).unwrap();
    assert_eq!(jobs(&s), 3);
}

#[test]
fn message_has_the_attachments() {
    let m = reports::Mail {
        subject: "[NexusBackup n] report r: 2026-10-05 – 2026-10-11".into(),
        html: "<p>x</p>".into(),
        text: "x".into(),
        attachments: vec![
            ("r-failed-2026-10-11.csv".into(), "job,error\r\n1,\"a, b\"\r\n".into()),
            ("r-sla-2026-10-11.csv".into(), "type\r\n".into()),
        ],
        rows: 1,
    };
    let msg = crate::report_mail::message(
        "nexus@example.com",
        &["a@example.com".into(), "b@example.com".into()],
        &m,
    )
    .unwrap();
    let raw = String::from_utf8(msg.formatted()).unwrap();
    assert!(
        raw.contains("multipart/mixed") && raw.contains("multipart/alternative"),
        "{raw}"
    );
    assert!(raw.contains("text/html") && raw.contains("text/plain"));
    assert!(raw.contains("filename=\"r-failed-2026-10-11.csv\""), "{raw}");
    assert!(raw.contains("filename=\"r-sla-2026-10-11.csv\""));
    assert_eq!(raw.matches("text/csv; charset=utf-8").count(), 2);
    assert!(raw.contains("To: a@example.com, b@example.com"));
    assert!(crate::report_mail::message("nexus@example.com", &["not a mail".into()], &m).is_err());
}

/// Sent through the SMTP server of the setting `alerts` (audit `report.sent`);
/// a failed send raises `report:<name>` (not `job_failed`), the next good send resolves it.
#[test]
fn report_send_mails_audits_and_alerts() {
    let e = env(4);
    let mut s = sched(&e);
    s.db.conn()
        .execute_batch(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created, finished, log) VALUES
               ('backup', 't1', '{\"group_id\":1}', 'failed', 'scheduler', 10, 10, 'ERROR: <boom> & more');",
        )
        .unwrap();
    set_reports(
        &s,
        json!([{"name": "ops", "types": ["failed", "protection"], "schedule": "Mon 07:00",
                "recipients": ["ops@example.com"], "tenant": "t1"}]),
    );
    // SMTP down: the report alert, no job_failed
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    smtp_setting(&s, dead);
    let id = manual(&s, "report_send", "-", json!({"name": "ops", "from": 0, "to": 100}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(60)).unwrap();
    assert_eq!(state(&s, id), "failed");
    let (kind, msg): (String, String) =
        s.db.conn()
            .query_row(
                "SELECT kind, message FROM alerts WHERE key = 'report:ops' AND resolved_at IS NULL",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(kind, "report");
    assert!(
        msg.contains("could not be sent") && msg.contains("sending the mail failed"),
        "{msg}"
    );
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE kind = 'job_failed'"), 0);
    // SMTP up: sent, audited, alert resolved
    let (port, got) = smtp_stub();
    smtp_setting(&s, port);
    let id = manual(&s, "report_send", "-", json!({"name": "ops", "from": 0, "to": 100}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(60)).unwrap();
    assert_eq!(state(&s, id), "ok");
    let data = got.join().unwrap();
    assert!(data.contains("Subject: [NexusBackup "), "{data}");
    assert!(data.contains("ops-failed-1970-01-01.csv") && data.contains("ops-protection-1970-01-01.csv"));
    let r = result_of(&s, id);
    assert_eq!(r["recipients"], json!(["ops@example.com"]));
    assert_eq!(r["attachments"].as_array().unwrap().len(), 2);
    assert_eq!(r["rows"], 4, "one failed job, the guests of t1's groups g1, g2, g3");
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM audit WHERE action = 'report.sent' AND target = 'report/ops'"
        ),
        1
    );
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE key = 'report:ops' AND resolved_at IS NULL"
        ),
        0
    );
    // a report removed meanwhile fails cleanly
    set_reports(&s, json!([]));
    let id = manual(&s, "report_send", "-", json!({"name": "ops", "from": 0, "to": 100}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, id), "failed");
    let log: String =
        s.db.conn()
            .query_row("SELECT log FROM jobs WHERE id = ?1", [id], |r| r.get(0))
            .unwrap();
    assert!(log.contains("no scheduled report named ops"), "{log}");
}
