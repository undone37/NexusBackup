//! `nexusctl update upload` (#28) against the real web-api router: an administrator's session (password +
//! TOTP), the bundle in the update directory, a fake nexus-update answering the import.

use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use nexusctl::update::{upload, Login};
use serde_json::json;
use std::time::Duration;
use web_api::AppState;

const PW: &str = "correct horse battery";

#[tokio::test(flavor = "multi_thread")]
async fn upload_signs_in_as_admin_and_waits_for_the_verification() {
    let dir = tempfile::tempdir().unwrap();
    let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
    let st = AppState::with_keys(cat, None, dir.path().join("dl"), TotpKey::generate(), None);
    let upd = dir.path().join("update");
    std::fs::create_dir_all(&upd).unwrap();
    st.update_dir.set(upd.clone()).unwrap();
    let mut secrets = std::collections::HashMap::new();
    for (name, role) in [("ada", "admin"), ("otto", "operator")] {
        let secret = catalog::auth::new_totp_secret();
        st.cat
            .conn()
            .execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES (?1, ?2, ?3, ?4, 0)",
                params![
                    name,
                    catalog::auth::hash_password(PW).unwrap(),
                    st.totp.encrypt(name, &secret).unwrap(),
                    role
                ],
            )
            .unwrap();
        secrets.insert(name, secret);
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let app = web_api::router(st.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    // nexus-update: takes the import request, checks what arrived, writes its verdict
    let u = upd.clone();
    std::thread::spawn(move || loop {
        if std::fs::read_to_string(u.join("request")).is_ok_and(|r| r.trim() == "import") {
            let ok = std::fs::read(u.join("bundle.tar")).unwrap() == b"BUNDLE";
            let result = if ok {
                "staged sha256:aa from the uploaded bundle"
            } else {
                "refused: checksums"
            };
            let api = json!({"status": if ok { "staged" } else { "refused" },
                             "last_result": {"time": 100, "request": "import", "result": result}});
            std::fs::remove_file(u.join("bundle.tar")).unwrap();
            std::fs::write(u.join("status.json"), json!({"api": api}).to_string()).unwrap();
            std::fs::remove_file(u.join("request")).unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    });
    let file = dir.path().join("bundle.tar");
    std::fs::write(&file, b"BUNDLE").unwrap();
    tokio::task::spawn_blocking(move || {
        let st = st;
        let fresh = |name: &str| {
            st.cat
                .conn()
                .execute("UPDATE users SET totp_last_step = 0 WHERE name = ?1", [name])
                .unwrap();
            catalog::auth::totp_now(&secrets[name]).unwrap()
        };
        let go = |user: &str, password: &str, code: String| {
            let mut totp = || Ok(code.clone());
            let mut login = Login {
                user: user.into(),
                password: password.into(),
                totp: &mut totp,
            };
            upload(&url, None, &mut login, &file, Duration::from_secs(20), &mut |_| {})
        };
        // tokens never act as administrators: an operator is refused before anything is uploaded
        let e = go("otto", PW, fresh("otto")).unwrap_err();
        assert!(format!("{e:#}").contains("not an administrator"), "{e:#}");
        let e = go("ada", PW, "000000".into()).unwrap_err();
        assert!(format!("{e:#}").contains("sign-in: HTTP 401"), "{e:#}");
        assert!(!upd.join("bundle.tar").exists() && !upd.join("request").exists());
        let v = go("ada", PW, fresh("ada")).unwrap();
        assert_eq!(v["status"], "staged", "{v}");
        assert_eq!(v["last_result"]["result"], "staged sha256:aa from the uploaded bundle");
        let n: i64 = st
            .cat
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE action = 'update.upload' AND actor = 'ada'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    })
    .await
    .unwrap();
}
