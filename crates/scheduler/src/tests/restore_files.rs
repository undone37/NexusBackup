use super::*;

const A: &str = "0123456789abcdef";
const OTHER: &str = "fedcba9876543210";

fn job(id: i64, p: Value) -> Job {
    Job {
        id,
        kind: "restore_files".into(),
        tenant: "t1".into(),
        params: p,
    }
}

#[test]
fn vm_and_ct_files_go_through_a_staging_tar() {
    let e = env(2);
    let s = sched(&e);
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO agents (id, tenant, name, host, port, cert_sha256) VALUES
               ('{A}','t1','web01','10.0.0.9',7444,'ab'), ('{OTHER}','t2','other','10.0.0.10',7444,'cd');"
        ))
        .unwrap();
    let base = json!({"source": "vm-100", "time": 5, "paths": ["/sda1/etc"], "target": "/srv/vm",
                      "overwrite": "never", "confirm": "web01", "agent_id": A});
    let p = s.plan(&job(40, base.clone())).unwrap();
    assert_eq!(p.key, format!("agent:{A}"));
    let [Step::Cli { bin, args, .. }, Step::Cli {
        bin: ctl,
        args: ctl_args,
        ..
    }] = &p.steps[..]
    else {
        panic!("two steps expected: {:?}", p.steps.len());
    };
    assert_eq!(bin, &e.cfg.pve_bin);
    assert_eq!(&args[1..5], ["files", "100", "5", "get"]);
    assert_eq!(args[6], "/sda1/etc");
    let staging = Path::new(&args[5]);
    assert_eq!(staging.parent(), Some(e.cfg.downloads.as_path()));
    assert!(staging
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("restore-40-"));
    assert_eq!(p.download.as_deref(), Some(staging), "removed when the job fails");
    assert_eq!(ctl, &e.cfg.agentctl_bin);
    assert_eq!(ctl_args[1], "restore");
    let (_, cfg) = p.files.iter().find(|(n, _)| n.starts_with("agent-")).unwrap();
    let cfg: Value = serde_json::from_slice(cfg).unwrap();
    assert_eq!(cfg["restore"]["tar"], json!(staging));
    assert_eq!(cfg["restore"]["source"], "vm-100");
    assert!(p.files.iter().any(|(n, _)| n == "pve.json"));

    let mut ct = base.clone();
    ct["source"] = json!("ct-100");
    let p = s.plan(&job(41, ct)).unwrap();
    let Step::Cli { args, .. } = &p.steps[0] else { panic!() };
    assert_eq!(args[1], "ct-files");

    // tenant isolation, a target agent is required, hostile paths
    let mut x = base.clone();
    x["agent_id"] = json!(OTHER);
    assert!(format!("{:#}", s.plan(&job(42, x)).unwrap_err()).contains("another tenant"));
    let mut x = base.clone();
    x.as_object_mut().unwrap().remove("agent_id");
    assert!(s.plan(&job(43, x)).is_err());
    let mut x = base.clone();
    x["paths"] = json!(["--evil"]);
    assert!(s.plan(&job(44, x)).is_err());
    let mut x = base;
    x["source"] = json!("vm-999");
    assert!(s.plan(&job(45, x)).is_err(), "no PVE source protects guest 999");
}
