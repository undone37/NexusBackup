use super::*;
use catalog::Catalog;

const NOW: i64 = 1_791_763_200; // 2026-10-12T00:00:00Z
const H: i64 = 3600;

/// acme: pve guests 100 (daily, fresh backup) and 101 (daily, last backup 3 days
/// ago, a gap earlier); globex: guest 200 (never backed up). Jobs, alerts, stats.
fn seeded() -> Catalog {
    let cat = Catalog::open_memory().unwrap();
    cat.conn()
        .execute_batch(&format!(
            r#"INSERT INTO tenants (name) VALUES ('acme'), ('globex');
               INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{{}}'),
                 (2, 'globex', 'pve', 'pve-g', '{{}}');
               INSERT INTO policies (id, name, schedule, gfs, offsite, sla_minutes, tier) VALUES
                 (1, 'daily', 'daily 22:00', '{{}}', 1, 60, 'gold');
               INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                 (1, 'acme', 1, 1, 'web', '[100, 101]'), (2, 'globex', 2, 1, 'erp', '[200]');
               INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until, verified) VALUES
                 ('acme', 'vm-100', {a}, 100, 1, 1, 0, {v}),
                 ('acme', 'vm-101', {b}, 200, 1, 0, 0, NULL);
               INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored) VALUES
                 ('acme', 'vm-100', {a}, 100, 1000, 3, 500, 250);
               INSERT INTO capacity_samples (day, tenant, used, logical) VALUES ('{d8}', 'acme', 100, 1000), ('{d0}', 'acme', 300, 1000);
               INSERT INTO jobs (id, kind, tenant, params, state, requested_by, created, started, finished, log, result) VALUES
                 (1, 'backup', 'acme', '{{"group_id":1}}', 'ok', 'scheduler', {g1}, {g1}, {g1}, '', '{{"snapshots":[{{"source":"vm-101","time":{g1},"consistent":true}}]}}'),
                 (2, 'backup', 'acme', '{{"group_id":1}}', 'failed', 'scheduler', {f}, {f}, {f},
                    'starting' || char(10) || 'ERROR: vzdump: "disk, full"' || char(10) || 'more', NULL),
                 (3, 'verify', 'globex', '{{}}', 'failed', 'scheduler', {f}, {f}, {f}, 'line one' || char(10) || 'last line', NULL),
                 (4, 'backup', 'acme', '{{"group_id":1}}', 'ok', 'scheduler', {s}, {s}, {s2}, '', NULL);
               INSERT INTO alerts (ts, last_ts, severity, kind, key, message, tenant) VALUES
                 ({s3}, {s3}, 'warning', 'sla_missed', 'sla_missed:4', 'backup job 4 of group web (acme) still running', 'acme');"#,
            a = NOW - 2 * H,
            v = NOW - H,
            b = NOW - 3 * 24 * H,
            g1 = NOW - 9 * 24 * H,
            f = NOW - 2 * 24 * H,
            s = NOW - 5 * 24 * H,
            s2 = NOW - 5 * 24 * H + 3 * H,
            s3 = NOW - 5 * 24 * H + 2 * H,
            d8 = day(NOW - 8 * 86400),
            d0 = day(NOW),
        ))
        .unwrap();
    cat
}

fn col(t: &Table, row: &[Cell], name: &str) -> String {
    row[t.columns.iter().position(|c| *c == name).unwrap()].to_string()
}

#[test]
fn csv_quoting() {
    let t = Table {
        kind: Kind::Failed,
        columns: &["a", "b, c"],
        rows: vec![
            vec![Cell::text("plain"), Cell::text("with \"quotes\", comma")],
            vec![Cell::text("multi\nline"), Cell::Int(-5)],
            vec![Cell::text("=SUM(A1)"), Cell::Empty],
            vec![Cell::Time(NOW), Cell::Ratio(2.0 / 3.0)],
            vec![Cell::text("ä ü 東京"), Cell::hours(5400)],
        ],
    };
    assert_eq!(
        t.csv(),
        "a,\"b, c\"\r\nplain,\"with \"\"quotes\"\", comma\"\r\n\"multi\nline\",-5\r\n'=SUM(A1),\r\n\
         2026-10-12T00:00:00Z,0.667\r\nä ü 東京,1.5\r\n"
    );
    assert!(!t.csv().starts_with('\u{feff}'), "no BOM");
}

#[test]
fn dates() {
    assert_eq!(iso(NOW + 3661), "2026-10-12T01:01:01Z");
    assert_eq!(iso(0), "1970-01-01T00:00:00Z");
    assert_eq!(parse_day("2026-10-12"), Some(NOW / 86400));
    assert_eq!(
        parse_day("2000-02-29").map(|d| day(d * 86400)),
        Some("2000-02-29".into())
    );
    for bad in ["2026-02-30", "2026-13-01", "26-10-12", "2026-10-1x", ""] {
        assert_eq!(parse_day(bad), None, "{bad}");
    }
}

#[test]
fn error_lines() {
    assert_eq!(error_line("a\nError: disk full\nb"), "Error: disk full");
    assert_eq!(error_line("a\n  last  \n\n"), "last");
    assert_eq!(error_line(""), "");
    assert_eq!(error_line(&"x".repeat(500)).len(), 300);
}

#[test]
fn breach_intervals() {
    // backups at 0, 10, 50 with limit 15: gap 10→50 breaches from 25 to 50
    assert_eq!(breaches(&[0, 10, 50], 15, false, 0, 100, 60), vec![(25, 50, false)]);
    // open gap until now (unless paused), clipped to the range
    assert_eq!(breaches(&[0], 15, false, 0, 100, 60), vec![(15, 60, true)]);
    assert!(breaches(&[0], 15, true, 0, 100, 60).is_empty());
    assert_eq!(breaches(&[0, 10, 50], 15, false, 30, 40, 60), vec![(30, 40, false)]);
    assert!(breaches(&[], 15, false, 0, 100, 60).is_empty());
}

use protection::breaches;

#[test]
fn protection_report() {
    let cat = seeded();
    let c = cat.conn();
    let t = generate(&c, Kind::Protection, None, 0, NOW, NOW).unwrap();
    assert_eq!(t.rows.len(), 3);
    let by = |src: &str| t.rows.iter().find(|r| col(&t, r, "object").ends_with(src)).unwrap();
    let r = by("guest 100");
    assert_eq!(col(&t, r, "status"), "ok");
    assert_eq!(col(&t, r, "groups"), "web");
    assert_eq!(col(&t, r, "last_good"), iso(NOW - 2 * H));
    assert_eq!(
        (col(&t, r, "local"), col(&t, r, "offsite")),
        ("yes".into(), "yes".into())
    );
    assert_eq!(col(&t, r, "verified"), iso(NOW - H));
    assert_eq!(col(&t, r, "rpo_hours"), "24");
    let r = by("guest 101");
    assert_eq!(col(&t, r, "status"), "breach");
    assert_eq!(col(&t, r, "age_hours"), "72");
    assert_eq!(col(&t, r, "offsite"), "no");
    let r = by("guest 200");
    assert_eq!(
        (col(&t, r, "status"), col(&t, r, "last_good")),
        ("never".into(), String::new())
    );
    // tenant scope
    let t = generate(&c, Kind::Protection, Some("globex"), 0, NOW, NOW).unwrap();
    assert_eq!(t.rows.len(), 1);
    assert!(t.csv().contains("globex"));
    assert!(!t.csv().contains("acme"));
}

#[test]
fn consistency_from_the_job_result() {
    let cat = seeded();
    // the last snapshot of vm-101 was written by job 1 (consistent)
    cat.conn()
        .execute(
            "UPDATE snapshots SET time = ?1 WHERE source = 'vm-101'",
            [NOW - 9 * 24 * H],
        )
        .unwrap();
    let c = cat.conn();
    let t = generate(&c, Kind::Protection, Some("acme"), 0, NOW, NOW).unwrap();
    let r = t.rows.iter().find(|r| col(&t, r, "source") == "vm-101").unwrap();
    assert_eq!(col(&t, r, "consistency"), "crash", "legacy consistent=true");
    let r = t.rows.iter().find(|r| col(&t, r, "source") == "vm-100").unwrap();
    assert_eq!(col(&t, r, "consistency"), "unknown");
    // the level recorded since 15d wins
    c.execute("UPDATE snapshots SET consistency = 'application'", [])
        .unwrap();
    let t = generate(&c, Kind::Protection, Some("acme"), 0, NOW, NOW).unwrap();
    let r = t.rows.iter().find(|r| col(&t, r, "source") == "vm-100").unwrap();
    assert_eq!(col(&t, r, "consistency"), "application");
}

#[test]
fn failed_report() {
    let cat = seeded();
    let c = cat.conn();
    let t = generate(&c, Kind::Failed, None, NOW - 7 * 24 * H, NOW, NOW).unwrap();
    assert_eq!(t.rows.len(), 2);
    assert_eq!(col(&t, &t.rows[0], "target"), "group web");
    assert_eq!(col(&t, &t.rows[0], "error"), "ERROR: vzdump: \"disk, full\"");
    assert_eq!(col(&t, &t.rows[1], "error"), "last line");
    assert!(t.csv().contains("\"ERROR: vzdump: \"\"disk, full\"\"\""));
    // range and scope
    assert!(generate(&c, Kind::Failed, None, NOW - 24 * H, NOW, NOW)
        .unwrap()
        .rows
        .is_empty());
    let t = generate(&c, Kind::Failed, Some("globex"), NOW - 7 * 24 * H, NOW, NOW).unwrap();
    assert_eq!((t.rows.len(), col(&t, &t.rows[0], "kind")), (1, "verify".into()));
}

#[test]
fn sla_report() {
    let cat = seeded();
    let c = cat.conn();
    let t = generate(&c, Kind::Sla, Some("acme"), NOW - 7 * 24 * H, NOW, NOW).unwrap();
    let kinds: Vec<String> = t.rows.iter().map(|r| col(&t, r, "type")).collect();
    // vm-101: backups 9 days ago (job result only) and 3 days ago: the gap breaches
    // from 7 days ago (range start) until 3 days ago, then again from 36 h after the
    // last one until now; vm-100: fresh, never breached in the range
    assert_eq!(kinds, ["rpo_breach", "sla_missed", "rpo_breach"]);
    let r = &t.rows[0];
    assert_eq!(col(&t, r, "start"), iso(NOW - 7 * 24 * H));
    assert_eq!(col(&t, r, "end"), iso(NOW - 3 * 24 * H));
    assert_eq!(col(&t, r, "target_hours"), "36");
    assert_eq!(col(&t, &t.rows[0], "tier"), "gold");
    let r = &t.rows[1];
    assert_eq!(col(&t, r, "groups"), "web");
    assert_eq!(col(&t, r, "tier"), "gold");
    assert_eq!(col(&t, r, "hours"), "3");
    assert_eq!(col(&t, r, "target_hours"), "1");
    let r = &t.rows[2];
    assert_eq!(col(&t, r, "start"), iso(NOW - 3 * 24 * H + 36 * H));
    assert_eq!(col(&t, r, "end"), "");
    assert!(col(&t, r, "detail").starts_with("ongoing"));
    // globex sees neither
    let t = generate(&c, Kind::Sla, Some("globex"), NOW - 7 * 24 * H, NOW, NOW).unwrap();
    assert!(
        t.rows.is_empty(),
        "never backed up: shown by the protection report only"
    );
}

#[test]
fn storage_report() {
    let cat = seeded();
    let c = cat.conn();
    let t = generate(&c, Kind::Storage, None, 0, NOW, NOW).unwrap();
    let levels: Vec<(String, String)> = t
        .rows
        .iter()
        .map(|r| (col(&t, r, "level"), col(&t, r, "tenant")))
        .collect();
    assert_eq!(
        levels,
        [
            ("tenant".into(), "acme".into()),
            ("tenant".into(), "globex".into()),
            ("group".into(), "acme".into())
        ]
    );
    let r = &t.rows[0];
    assert_eq!(
        (
            col(&t, r, "logical_bytes"),
            col(&t, r, "stored_bytes"),
            col(&t, r, "dedup"),
            col(&t, r, "compression")
        ),
        ("1000".into(), "250".into(), "2".into(), "2".into())
    );
    assert_eq!(
        (col(&t, r, "used_bytes"), col(&t, r, "growth_7d_bytes")),
        ("300".into(), "200".into())
    );
    assert_eq!(col(&t, &t.rows[2], "group"), "web");
    let t = generate(&c, Kind::Storage, Some("globex"), 0, NOW, NOW).unwrap();
    assert_eq!(t.rows.len(), 1);
}

fn sched(schedule: &str) -> Scheduled {
    Scheduled {
        name: "weekly-ops".into(),
        types: vec![Kind::Protection, Kind::Failed],
        schedule: schedule.into(),
        timezone: "Europe/Berlin".into(),
        recipients: vec!["ops@example.com".into()],
        tenant: None,
    }
}

#[test]
fn scheduled_checks_and_ranges() {
    let r = sched("Mon 07:00");
    assert_eq!(r.check(), Ok(()));
    // NOW is a Monday; 07:00 Berlin (CEST) = 05:00 UTC
    let s = r.schedule().unwrap();
    let slot = s.last_slot(NOW + 6 * H);
    assert_eq!(slot, NOW + 5 * H);
    assert_eq!(r.range_at(slot).unwrap(), (NOW + 5 * H - 7 * 24 * H, NOW + 5 * H));
    assert!(s.due(NOW - 24 * H, NOW + 6 * H));
    assert!(!s.due(NOW + 5 * H, NOW + 6 * H), "sent this week already");
    assert_eq!(r.attachment(Kind::Failed, slot), "weekly-ops-failed-2026-10-12.csv");
    let m = sched("monthly 1 06:00");
    let slot = m.schedule().unwrap().last_slot(NOW);
    assert_eq!(iso(slot), "2026-10-01T04:00:00Z");
    assert_eq!(iso(m.range_at(slot).unwrap().0), "2026-09-01T04:00:00Z");
    assert!(sched("hourly 05").check().unwrap_err().contains("weekdays"));
    assert!(sched("Mon 25:00").check().is_err());
    let mut bad = sched("Mon 07:00");
    bad.types = vec![Kind::Sla, Kind::Sla];
    assert!(bad.check().unwrap_err().contains("each once"));
    bad.types = vec![];
    assert!(bad.check().is_err());
    let mut bad = sched("Mon 07:00");
    bad.name = "../x".into();
    assert!(bad.check().is_err());
    bad = sched("Mon 07:00");
    bad.timezone = "Mars/Olympus".into();
    assert!(bad.check().is_err());
    bad = sched("Mon 07:00");
    bad.recipients.clear();
    assert!(bad.check().is_err());
    // stored form
    let v: Scheduled = serde_json::from_value(serde_json::json!({
        "name": "m", "types": ["storage", "sla"], "schedule": "monthly 1 06:00", "recipients": ["a@b.example"]}))
    .unwrap();
    assert_eq!((v.timezone.as_str(), v.tenant.as_deref()), ("UTC", None));
    assert!(serde_json::from_value::<Scheduled>(serde_json::json!({
        "name": "m", "types": ["bogus"], "schedule": "Mon 07:00", "recipients": []}))
    .is_err());
}

#[test]
fn mail_composition_escapes() {
    let cat = seeded();
    cat.conn()
        .execute("UPDATE groups SET name = '<b>web</b> & co' WHERE id = 1", [])
        .unwrap();
    let mut r = sched("Mon 07:00");
    r.types = vec![Kind::Protection, Kind::Failed, Kind::Sla, Kind::Storage];
    r.name = "ops".into();
    let m = compose(&cat.conn(), &r, "nexus<1>", NOW - 7 * 24 * H, NOW, NOW).unwrap();
    assert_eq!(
        m.attachments.iter().map(|a| a.0.as_str()).collect::<Vec<_>>(),
        [
            "ops-protection-2026-10-11.csv",
            "ops-failed-2026-10-11.csv",
            "ops-sla-2026-10-11.csv",
            "ops-storage-2026-10-11.csv"
        ]
    );
    assert!(m.html.contains("&lt;b&gt;web&lt;/b&gt; &amp; co"));
    assert!(!m.html.contains("<b>web"));
    assert!(m.html.contains("appliance nexus&lt;1&gt;"));
    assert!(m.html.contains("&quot;disk, full&quot;"));
    assert!(m.subject.contains("report ops: 2026-10-05 – 2026-10-11"));
    assert!(m.text.contains("Failed jobs: 2 rows"));
    assert_eq!(
        m.attachments[1].1,
        generate(&cat.conn(), Kind::Failed, None, NOW - 7 * 24 * H, NOW, NOW)
            .unwrap()
            .csv()
    );
    // a tenant's report holds that tenant only
    r.tenant = Some("globex".into());
    let m = compose(&cat.conn(), &r, "nexus", NOW - 7 * 24 * H, NOW, NOW).unwrap();
    assert!(m.attachments.iter().all(|a| !a.1.contains("acme")));
    assert!(m.html.contains("tenant globex"));
}

#[test]
fn escaping() {
    assert_eq!(
        escape(r#"<a href="x">'&'</a>"#),
        "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
    );
}
