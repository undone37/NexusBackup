use super::*;

const F: &str = "aaaabbbbccccdddd";

/// Scan → candidates → auto-accept (within max uses) → enrollment with the fleet
/// digest; scans are queued once per interval; the firewall opens the ranges on the
/// fleet port only while the fleet is usable; a revoked fleet enrolls nobody.
#[test]
fn fleet_scan_auto_accept_and_enrollment() {
    let mut e = env(4);
    let dir = e.d.path().to_owned();
    script(
        &dir.join("agentctl"),
        &format!(
            r#"cp "$1" {0}/ctl-$2.json
case "$2" in
fleet-scan) cat "$(dirname "$1")/fleet-digest" > {0}/digest-seen
  echo 'fleet-agent {{"host":"10.1.0.1","port":7444,"hostname":"web-1.lan","os":"Debian 13","version":"0.2.0"}}'
  echo 'fleet-agent {{"host":"10.1.0.2","port":7444,"hostname":"db-2","os":"Windows Server 2022","version":"0.2.0"}}' ;;
enroll) cat "$(dirname "$1")/token" > {0}/token-seen
  id=$(sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' "$1" | head -1)
  echo "enrolled {{\"agent_id\":\"$id\",\"cert_sha256\":\"{1}\",\"appliance_id\":\"x\"}}" ;;
esac"#,
            dir.display(),
            "c".repeat(64)
        ),
    );
    e.cfg.agentctl_bin = dir.join("agentctl");
    let mut s = sched(&e);
    let sealed = s
        .secrets
        .public()
        .seal(&catalog::fleet::secret_location(F), "fleet-digest-1")
        .unwrap();
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO agents (id, tenant, name, host, port) VALUES ('0123456789abcdef', 't1', 'tmpl', 'h', 7444);
             INSERT INTO sources (id, tenant, kind, name, config) VALUES
               (10, 't1', 'linux', 'tmpl', '{{\"agent_id\":\"0123456789abcdef\",\"paths\":[\"/srv\"]}}');
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
               (10, 't1', 10, 1, 'tmpl', '[\"0123456789abcdef\"]');
             INSERT INTO fleets (id, tenant, name, secret_hash, created, created_by, expires, max_uses, auto_accept,
                                 port, ranges, default_group)
               VALUES ('{F}', 't1', 'clients', '{sealed}', 1, 'alice', 9999999999, 1, 1, 7444,
                       '[\"10.1.0.0/30\"]', 'tmpl');"
        ))
        .unwrap();
    let count = |s: &Scheduler, sql: &str| -> i64 { s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
    let fw = s.fleet_targets().unwrap();
    assert_eq!(fw, vec![("10.1.0.1".to_string(), 7444), ("10.1.0.2".to_string(), 7444)]);

    s.now = 1_000_000;
    s.queue_fleet_scans(s.now).unwrap();
    s.queue_fleet_scans(s.now + 60).unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'fleet_scan'"),
        1,
        "once per interval"
    );
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM jobs WHERE kind = 'fleet_scan' AND state = 'ok'"
        ),
        1
    );
    assert_eq!(fs::read_to_string(dir.join("digest-seen")).unwrap(), "fleet-digest-1");
    let cfg: Value = serde_json::from_slice(&fs::read(dir.join("ctl-fleet-scan.json")).unwrap()).unwrap();
    assert_eq!(cfg["fleet"]["targets"], json!(["10.1.0.1", "10.1.0.2"]));
    assert_eq!(
        (cfg["fleet"]["id"].as_str(), cfg["fleet"]["port"].as_u64()),
        (Some(F), Some(7444))
    );

    // two candidates; max_uses 1: only the first is auto-accepted
    let states: Vec<(String, String)> =
        s.db.conn()
            .prepare("SELECT hostname, state FROM fleet_candidates ORDER BY host")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    assert_eq!(
        states,
        vec![
            ("web-1.lan".into(), "accepted".into()),
            ("db-2".into(), "awaiting".into())
        ]
    );
    let agent: String =
        s.db.conn()
            .query_row("SELECT id FROM agents WHERE name = 'web-1'", [], |r| r.get(0))
            .unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM groups WHERE name = 'web-1' AND tenant = 't1'"),
        1
    );
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM audit WHERE action = 'fleet.auto_accept'"),
        1
    );
    assert_eq!(count(&s, "SELECT uses FROM fleets"), 1);
    // no scans and no firewall targets for a used-up fleet
    assert!(s.fleet_targets().unwrap().is_empty());
    s.queue_fleet_scans(s.now + 10_000).unwrap();
    assert_eq!(count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'fleet_scan'"), 1);

    // the queued enrollment proves the fleet digest
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(fs::read_to_string(dir.join("token-seen")).unwrap(), "fleet-digest-1");
    let fp: Option<String> =
        s.db.conn()
            .query_row("SELECT cert_sha256 FROM agents WHERE id = ?1", [&agent], |r| r.get(0))
            .unwrap();
    assert_eq!(fp, Some("c".repeat(64)));

    // revoked: an enrollment with the fleet fails; a fleet_id for a token agent fails too
    s.db.conn().execute("UPDATE fleets SET revoked = 1", []).unwrap();
    let job = |p: Value| Job {
        id: 0,
        kind: "agent_enroll".into(),
        tenant: "t1".into(),
        params: p,
    };
    let err = s.plan(&job(json!({"agent_id": agent, "fleet_id": F}))).unwrap_err();
    assert!(format!("{err:#}").contains("revoked"), "{err:#}");
    s.db.conn().execute("UPDATE fleets SET revoked = 0", []).unwrap();
    let err = s
        .plan(&job(json!({"agent_id": "0123456789abcdef", "fleet_id": F})))
        .unwrap_err();
    assert!(format!("{err:#}").contains("not accepted from fleet"), "{err:#}");
}
