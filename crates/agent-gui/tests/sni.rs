//! The Linux tray (src/sni.rs) on a private session bus (dbus-daemon): registration with a
//! StatusNotifierWatcher, the properties and menu layout a panel reads, a menu click.
//! Skipped without dbus-daemon.
#![cfg(target_os = "linux")]

use nexus_agent_gui::model::Badge;
use nexus_agent_gui::tray::{self, Action, Tray};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zbus::{interface, OwnedVariant, Proxy};

struct Watcher(Arc<Mutex<Vec<String>>>);

#[interface(name = "org.kde.StatusNotifierWatcher")]
impl Watcher {
    fn register_status_notifier_item(&self, service: &str) {
        self.0.lock().unwrap().push(service.to_string());
    }
}

/// stops the private bus also when an assertion fails (it would hold the test's output open)
struct Bus(std::process::Child);
impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// (s a(iiay) s s): icon name, pixmaps, title, text
type ToolTip = (String, Vec<(i32, i32, Vec<u8>)>, String, String);
type Layout = (i32, std::collections::HashMap<String, OwnedVariant>, Vec<OwnedVariant>);

#[test]
fn tray_on_a_private_session_bus() {
    let Ok(child) = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        eprintln!("skipped: no dbus-daemon");
        return;
    };
    let mut bus = Bus(child);
    let mut addr = String::new();
    BufReader::new(bus.0.stdout.take().unwrap())
        .read_line(&mut addr)
        .unwrap();
    // the only test in this binary: nothing else reads the environment meanwhile
    std::env::set_var("DBUS_SESSION_BUS_ADDRESS", addr.trim());

    let registered = Arc::new(Mutex::new(Vec::new()));
    let panel = zbus::block_on(
        zbus::connection::Builder::session()
            .name("org.kde.StatusNotifierWatcher")
            .serve_at("/StatusNotifierWatcher", Watcher(registered.clone()))
            .build(),
    )
    .unwrap();

    let mut t = Tray::new("Protected").unwrap();
    let name = registered
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("item registered with the watcher");
    assert_eq!(name, format!("org.kde.StatusNotifierItem-{}-1", std::process::id()));

    let item = || async {
        Proxy::new(
            &panel,
            name.as_str(),
            "/StatusNotifierItem",
            "org.kde.StatusNotifierItem",
        )
        .await
        .unwrap()
    };
    let menu = || async {
        Proxy::new(&panel, name.as_str(), "/MenuBar", "com.canonical.dbusmenu")
            .await
            .unwrap()
    };
    let layout = || async {
        let r: (u32, Layout) = menu()
            .await
            .call("GetLayout", &(0i32, -1i32, Vec::<String>::new()))
            .await
            .unwrap();
        r
    };
    let tooltip = || async {
        let t: ToolTip = item().await.get_property("ToolTip").await.unwrap();
        t.3
    };

    let rev = zbus::block_on(async {
        let px: Vec<(i32, i32, Vec<u8>)> = item().await.get_property("IconPixmap").await.unwrap();
        assert_eq!((px[0].0, px[0].1, px[0].2.len()), (32, 32, 32 * 32 * 4));
        assert_eq!(tooltip().await, "Protected");
        let path: zbus::OwnedObjectPath = item().await.get_property("Menu").await.unwrap();
        assert_eq!(path.as_str(), "/MenuBar");
        let (rev, (_, _, children)) = layout().await;
        assert_eq!(children.len(), 4);
        rev
    });

    // policy hides "request backup now": a new layout revision, the item invisible
    t.update(Badge::Cross, "Backup failed", None);
    zbus::block_on(async {
        let (rev2, (_, _, children)) = layout().await;
        assert!(rev2 > rev);
        let (_, props, _): Layout = children[1].clone().try_into().unwrap();
        assert!(!bool::try_from(&props["visible"]).unwrap());
        assert_eq!(tooltip().await, "Backup failed");

        // a click on Quit (id 4), a left click on the icon
        let _: () = menu()
            .await
            .call("Event", &(4i32, "clicked", zbus::Variant::from(0i32), 0u32))
            .await
            .unwrap();
        let _: () = item().await.call("Activate", &(0i32, 0i32)).await.unwrap();
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got = Vec::new();
    while got.len() < 2 && Instant::now() < deadline {
        got.extend(tray::poll());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(got, [Action::Quit, Action::Open]);
}
