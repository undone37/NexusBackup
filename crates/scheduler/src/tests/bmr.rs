use super::*;
use catalog::secret::{rescue_p2v_token_location, rescue_token_location};

const A: &str = "0123456789abcdef";
const R: &str = "fedcba9876543210";

fn job(id: i64, kind: &str, p: Value) -> Job {
    Job {
        id,
        kind: kind.into(),
        tenant: "t1".into(),
        params: p,
    }
}

fn setup(s: &Scheduler, p2v: Option<Value>) {
    let pk = s.secrets.public();
    let sealed = pk.seal(&rescue_token_location(R, A), "d1g3st").unwrap();
    let p2v = p2v.map(|mut v| {
        v["token"] = json!(pk.seal(&rescue_p2v_token_location(R, A), "TOKEN").unwrap());
        v.to_string()
    });
    s.db.conn()
        .execute(
            "INSERT INTO rescue_sessions (id, tenant, agent_id, lookup, token_hash, token_expires, state, host, port, \
             reboot, p2v, created, created_by) VALUES (?1,'t1',?2,'lk',?3,9999999999,'waiting','192.0.2.50',7444,1,?4,0,'a')",
            params![R, A, sealed, p2v],
        )
        .unwrap();
}

#[test]
fn bmr_plan_enrolls_with_the_sealed_token_then_pins() {
    let e = env(2);
    let s = sched(&e);
    setup(&s, None);
    let p = json!({"session": R, "source_agent": A, "time": 1000});
    let plan = s.plan(&job(50, "bmr", p.clone())).unwrap();
    assert_eq!(plan.key, format!("agent:{R}"));
    let [Step::Cli { bin, args, .. }] = &plan.steps[..] else {
        panic!("one step")
    };
    assert_eq!(bin, &e.cfg.agentctl_bin);
    assert_eq!(args[1], "rescue");
    let token = plan.files.iter().find(|(n, _)| n == "token").unwrap();
    assert_eq!(token.1, b"d1g3st");
    let (_, cfg) = plan.files.iter().find(|(n, _)| n == "rescue.json").unwrap();
    let cfg: Value = serde_json::from_slice(cfg).unwrap();
    assert_eq!(cfg["agent"], json!({"id": R, "host": "192.0.2.50", "port": 7444}));
    assert_eq!(cfg["rescue"], json!({"source_agent": A, "time": 1000, "reboot": true}));
    assert_eq!(cfg["token_file"], json!(plan.dir.join("token")));
    // the rescue address is on the firewall allow-list while the session is open
    assert_eq!(s.rescue_targets().unwrap(), [("192.0.2.50".to_string(), 7444)]);

    // a mismatched agent is refused
    let mut bad = p.clone();
    bad["source_agent"] = json!("1111111111111111");
    assert!(s.plan(&job(51, "bmr", bad)).is_err());

    // the job's lines: enrolled (pin, token spent), failure at the restore step
    let log = format!(
        "rescue-enrolled {{\"agent_id\":\"{R}\",\"cert_sha256\":\"{}\"}}\nrescue-step apply\nrescue-step restore\nError: connection reset\n",
        "a".repeat(64)
    );
    s.rescue_bookkeeping(&job(50, "bmr", p.clone()), &log, false).unwrap();
    let row = |c: &str| -> Option<String> {
        s.db.conn()
            .query_row(&format!("SELECT {c} FROM rescue_sessions WHERE id = ?1"), [R], |r| {
                r.get(0)
            })
            .unwrap()
    };
    assert_eq!(row("cert_sha256"), Some("a".repeat(64)));
    assert_eq!(row("token_hash"), None);
    assert_eq!(row("state").as_deref(), Some("failed"));
    assert_eq!(row("step").as_deref(), Some("restore"));
    assert!(row("message").unwrap().contains("connection reset"));
    assert!(s.rescue_targets().unwrap().is_empty());

    // a retry pins the certificate instead of a token
    s.db.conn()
        .execute("UPDATE rescue_sessions SET state = 'running' WHERE id = ?1", [R])
        .unwrap();
    let plan = s.plan(&job(52, "bmr", p.clone())).unwrap();
    assert!(!plan.files.iter().any(|(n, _)| n == "token"));
    let (_, cfg) = plan.files.iter().find(|(n, _)| n == "rescue.json").unwrap();
    let cfg: Value = serde_json::from_slice(cfg).unwrap();
    assert_eq!(cfg["agent"]["cert_sha256"], json!("a".repeat(64)));
    s.rescue_bookkeeping(&job(52, "bmr", p), "rescue-step finish\nrescue-done {}\n", true)
        .unwrap();
    assert_eq!(row("state").as_deref(), Some("done"));
    // the tenant must match
    let mut other = job(53, "bmr", json!({"session": R, "source_agent": A, "time": 1}));
    other.tenant = "t2".into();
    assert!(s.plan(&other).is_err());
}

#[test]
fn p2v_plan_and_cleanup_step() {
    let e = env(2);
    let s = sched(&e);
    let vm = json!({"source_id": 1, "node": "n1", "vmid": 0, "name": "", "storage": "local-lvm",
                    "iso": "local:iso/nexus-rescue.iso", "iso_storage": "local", "bridge": "vmbr0",
                    "memory": 2048, "cores": 2, "appliance": "nexus.lab:443", "appliance_sha256": ""});
    setup(&s, Some(vm));
    let p = json!({"session": R, "source_agent": A, "time": 1000});
    let plan = s.plan(&job(60, "p2v", p.clone())).unwrap();
    let [Step::Cli { args: a1, .. }, Step::Cli { bin, args: a2, .. }] = &plan.steps[..] else {
        panic!("two steps")
    };
    assert_eq!(&a1[1..4], ["layout", A, "1000"]);
    assert_eq!(bin, &e.cfg.pve_bin);
    assert_eq!(a2[1], "p2v");
    let (_, req) = plan.files.iter().find(|(n, _)| n == "p2v.json").unwrap();
    let req: Value = serde_json::from_slice(req).unwrap();
    assert_eq!(req["rescue"]["token"], "TOKEN", "unsealed only into the 0600 job file");
    assert_eq!(req["rescue"]["disks"], json!(["auto"]));
    assert_eq!(req["rescue"]["appliance"], "nexus.lab:443");
    assert!(req.get("token").is_none());
    assert!(plan.files.iter().any(|(n, _)| n == "pve.json"));
    // the VM line records where the config disk is; the bmr job then cleans it up
    s.rescue_bookkeeping(
        &job(60, "p2v", p.clone()),
        "p2v-vm {\"vmid\":123,\"node\":\"n1\",\"config_volid\":\"local:iso/nexus-rescue-cfg-x.iso\"}\n",
        true,
    )
    .unwrap();
    let plan = s.plan(&job(61, "bmr", p.clone())).unwrap();
    let Step::Cli { args, .. } = plan.steps.last().unwrap() else {
        panic!()
    };
    assert_eq!(
        &args[1..],
        ["p2v-cleanup", "n1", "123", "local:iso/nexus-rescue-cfg-x.iso"]
    );
    // a failed p2v job fails the session and voids the token
    s.rescue_bookkeeping(&job(60, "p2v", p), "Error: PVE API 500\n", false)
        .unwrap();
    let (state, tok): (String, Option<String>) =
        s.db.conn()
            .query_row("SELECT state, token_hash FROM rescue_sessions", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((state.as_str(), tok), ("failed", None));
}
