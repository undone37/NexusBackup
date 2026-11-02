//! `nexusctl system` (#179) against the real web-api router: an administrator's session, the reboot request
//! waiting for approval, the status.

use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use nexusctl::system::{parse, render, run};
use nexusctl::update::Login;
use web_api::AppState;

const PW: &str = "correct horse battery";

#[tokio::test(flavor = "multi_thread")]
async fn reboot_request_waits_for_approval() {
    let dir = tempfile::tempdir().unwrap();
    let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
    let st = AppState::with_keys(cat, None, dir.path().join("dl"), TotpKey::generate(), None);
    for d in ["power", "update"] {
        std::fs::create_dir_all(dir.path().join(d)).unwrap();
    }
    st.power_dir.set(dir.path().join("power")).unwrap();
    st.update_dir.set(dir.path().join("update")).unwrap();
    let secret = catalog::auth::new_totp_secret();
    st.cat
        .conn()
        .execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('ada', ?1, ?2, 'admin', 0)",
            params![
                catalog::auth::hash_password(PW).unwrap(),
                st.totp.encrypt("ada", &secret).unwrap()
            ],
        )
        .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let app = web_api::router(st.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    tokio::task::spawn_blocking(move || {
        let go = |line: &str| {
            st.cat
                .conn()
                .execute("UPDATE users SET totp_last_step = 0 WHERE name = 'ada'", [])
                .unwrap();
            let code = catalog::auth::totp_now(&secret).unwrap();
            let mut totp = || Ok(code.clone());
            let mut login = Login {
                user: "ada".into(),
                password: PW.into(),
                totp: &mut totp,
            };
            let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
            let (cmd, _) = parse(&args).unwrap();
            let v = run(&url, None, &mut login, &cmd).unwrap();
            render(&cmd, &v)
        };
        let out = go("reboot --user ada --reason kernel-update --delay 30");
        assert!(out.contains("approval #"), "{out}");
        assert!(
            !dir.path().join("power/request.json").exists(),
            "nothing before the approval"
        );
        let out = go("status --user ada");
        assert!(out.contains("scheduled: nothing\nwaiting for approval: #"), "{out}");
        assert!(out.contains("running jobs: 0"), "{out}");
    })
    .await
    .unwrap();
}
