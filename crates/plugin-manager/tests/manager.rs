use catalog::Catalog;
use plugin_manager::*;
use plugin_proto::bundle;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn manifest(id: &str, version: &str, publisher: &str, kind: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id, "name": id, "version": version, "publisher": publisher, "api": 1,
        "kinds": [{"kind": kind, "title": kind, "config_schema": {"type": "object", "properties": {}},
                   "restores": [{"id": "download", "title": "Download"}]}]
    }))
    .unwrap()
}

fn bundle_of(id: &str, version: &str, publisher: &str, kind: &str) -> Vec<u8> {
    let mut assets = BTreeMap::new();
    assets.insert("doc/readme.txt".into(), b"hi".to_vec());
    bundle::pack(&manifest(id, version, publisher, kind), b"\x7fELF test binary", &assets).unwrap()
}

struct Env {
    _d: tempfile::TempDir,
    cat: Catalog,
    paths: Paths,
    project_key: String,
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let keys = d.path().join("keys");
    fs::create_dir_all(&keys).unwrap();
    let (sk, pk) = bundle::generate_key().unwrap();
    fs::write(keys.join("project.pub"), pk).unwrap();
    let paths = Paths {
        staging: d.path().join("staging"),
        plugins: d.path().join("plugins"),
        project_keys: keys,
    };
    fs::create_dir_all(&paths.staging).unwrap();
    fs::create_dir_all(&paths.plugins).unwrap();
    Env {
        cat: Catalog::open_memory().unwrap(),
        paths,
        project_key: sk,
        _d: d,
    }
}

impl Env {
    /// upload as the web-api does: verify, stage, record pending (quorum id 1)
    fn upload(&self, b: &[u8], sig: &str) -> Result<Verified, Error> {
        let c = self.cat.conn();
        let v = verify_upload(&c, &self.paths.project_keys, b, sig.as_bytes())?;
        stage(&self.paths.staging, &v, b, sig.as_bytes()).unwrap();
        record_pending(&c, &v, "admin", Some(1))?;
        Ok(v)
    }
    fn install(&self, v: &Verified) {
        let m = &v.bundle.manifest;
        approve_install(&self.cat.conn(), &m.id, &m.version, &v.sha256).unwrap();
        let out = run_pending(&self.cat, &self.paths).unwrap();
        assert!(out.iter().any(|l| l.starts_with("installed")), "{out:?}");
    }
}

#[test]
fn signatures_publishers_versions() {
    let e = env();
    let b = bundle_of("pg", "1.0.0", "nexusbackup", "postgresql");
    // bad signature
    let (other, other_pub) = bundle::generate_key().unwrap();
    let err = e.upload(&b, &bundle::sign(&b, &other).unwrap()).unwrap_err();
    assert_eq!(err.status, 400);
    assert!(err.message.contains("does not verify"), "{err}");
    let err = e.upload(&b, "garbage!").unwrap_err();
    assert_eq!(err.status, 400);

    // project key: accepted
    let v = e.upload(&b, &bundle::sign(&b, &e.project_key).unwrap()).unwrap();
    assert!(v.signer.contains("project.pub"));
    e.install(&v);
    let dir = e.paths.plugins.join("pg/1.0.0");
    assert_eq!(fs::read(dir.join("bin/plugin")).unwrap(), b"\x7fELF test binary");
    assert_eq!(fs::read(dir.join("assets/doc/readme.txt")).unwrap(), b"hi");
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        (
            mode(&dir),
            mode(&dir.join("bin/plugin")),
            mode(&dir.join("manifest.json"))
        ),
        (0o555, 0o555, 0o444)
    );
    assert_eq!(
        fs::read_link(e.paths.plugins.join("pg/current")).unwrap(),
        Path::new("1.0.0")
    );
    assert!(
        !staged_paths(&e.paths.staging, &v.sha256).0.exists(),
        "staged bundle removed"
    );
    let cur = current_for_kind(&e.cat.conn(), "postgresql").unwrap().unwrap();
    assert_eq!((cur.id.as_str(), cur.version.as_str()), ("pg", "1.0.0"));

    // downgrade / same version refused
    for ver in ["1.0.0", "0.9.0"] {
        let b2 = bundle_of("pg", ver, "nexusbackup", "postgresql");
        let err = e.upload(&b2, &bundle::sign(&b2, &e.project_key).unwrap()).unwrap_err();
        assert_eq!(err.status, 409, "{ver}: {err}");
    }

    // unknown publisher: signed with its own key, not trusted yet
    let acme = bundle_of("acme-db", "1.0.0", "acme", "acmedb");
    let sig = bundle::sign(&acme, &other).unwrap();
    assert!(e.upload(&acme, &sig).unwrap_err().message.contains("does not verify"));
    // the key is added (quorum-approved in the web-api) → accepted
    let point = bundle::parse_public_key(&other_pub).unwrap();
    e.cat
        .conn()
        .execute(
            "INSERT INTO plugin_keys (fingerprint, publisher, public_key, added_by, approved_by, added_at) VALUES (?1, 'acme', ?2, 'admin', 'so', 1)",
            [format!("sha256:{}", bundle::fingerprint(&point)), other_pub.clone()],
        )
        .unwrap();
    let v = e.upload(&acme, &sig).unwrap();
    assert!(v.signer.starts_with("acme/"));

    // a publisher key cannot sign for another publisher
    let fake = bundle_of("evil", "1.0.0", "nexusbackup", "evil");
    let err = e.upload(&fake, &bundle::sign(&fake, &other).unwrap()).unwrap_err();
    assert!(err.message.contains("claims publisher nexusbackup"), "{err}");

    // id takeover: acme may not publish `pg`
    let take = bundle_of("pg", "2.0.0", "acme", "postgresql");
    let err = e.upload(&take, &bundle::sign(&take, &other).unwrap()).unwrap_err();
    assert_eq!(err.status, 409);
    assert!(err.message.contains("belongs to publisher nexusbackup"), "{err}");
    // nor provide a kind of another plugin
    let kind = bundle_of("acme-pg", "1.0.0", "acme", "postgresql");
    let err = e.upload(&kind, &bundle::sign(&kind, &other).unwrap()).unwrap_err();
    assert!(err.message.contains("already provided"), "{err}");

    // upgrade: newer version installs and becomes current
    let b3 = bundle_of("pg", "1.1.0", "nexusbackup", "postgresql");
    let v3 = e.upload(&b3, &bundle::sign(&b3, &e.project_key).unwrap()).unwrap();
    assert_eq!(v3.upgrade_from.as_deref(), Some("1.0.0"));
    e.install(&v3);
    let cur = current_for_kind(&e.cat.conn(), "postgresql").unwrap().unwrap();
    assert_eq!(cur.version, "1.1.0");
    assert!(
        e.paths.plugins.join("pg/1.0.0").is_dir(),
        "older version stays for a switch back"
    );
}

#[test]
fn installer_refuses_tampered_staging_and_removes() {
    let e = env();
    let b = bundle_of("files", "1.0.0", "nexusbackup", "files");
    let v = e.upload(&b, &bundle::sign(&b, &e.project_key).unwrap()).unwrap();
    approve_install(&e.cat.conn(), "files", "1.0.0", &v.sha256).unwrap();
    // swap the staged bundle for another (validly signed!) one after approval
    let other = bundle_of("files", "1.0.0", "nexusbackup", "files2");
    fs::write(staged_paths(&e.paths.staging, &v.sha256).0, &other).unwrap();
    let out = run_pending(&e.cat, &e.paths).unwrap();
    assert!(out[0].contains("failed"), "{out:?}");
    assert!(!e.paths.plugins.join("files/1.0.0").exists());
    let state: String = e
        .cat
        .conn()
        .query_row("SELECT state FROM plugins WHERE id='files'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "failed");
    // re-upload of a failed version is allowed
    let v = e.upload(&b, &bundle::sign(&b, &e.project_key).unwrap()).unwrap();
    e.install(&v);
    // remove: refused by the web-api while sources exist (sources_using), executed by the installer
    let c = e.cat.conn();
    c.execute("INSERT INTO tenants (name) VALUES ('t')", []).unwrap();
    c.execute(
        "INSERT INTO sources (tenant, kind, name, config) VALUES ('t', 'plugin:files', 's', '{}')",
        [],
    )
    .unwrap();
    assert_eq!(sources_using(&c, "files").unwrap(), 1);
    c.execute("DELETE FROM sources", []).unwrap();
    assert_eq!(sources_using(&c, "files").unwrap(), 0);
    c.execute("UPDATE plugins SET state='removing' WHERE id='files'", [])
        .unwrap();
    drop(c);
    let out = run_pending(&e.cat, &e.paths).unwrap();
    assert!(out.contains(&"removed files".to_string()), "{out:?}");
    assert!(!e.paths.plugins.join("files").exists());
    assert!(e.cat.verify_audit().unwrap() >= 3);
}
