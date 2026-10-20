//! Linux tray: StatusNotifierItem (org.kde.StatusNotifierItem) with a com.canonical.dbusmenu
//! menu, desktop notifications and the portal's dark-mode setting, all over zbus 6 (pure
//! Rust; KDE, XFCE, Cinnamon, LXQt show it, GNOME needs the AppIndicator extension). Replaces
//! ksni, notify-rust and iced's mundy, which are still on the unmaintained zbus 5 (RUSTSEC-2026-0370..0372).
//! The connection is driven by zbus's own runtime; the UI thread only blocks for a signal send.

use super::Action;
use crate::model::Badge;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use zbus::object_server::SignalEmitter;
use zbus::{interface, Connection, OwnedObjectPath, OwnedVariant, Variant};

const ITEM_PATH: &str = "/StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
const ICON_SIZE: u32 = 32;
const TITLE: &str = "NexusBackup Agent";
// menu item ids (0 is the root)
const OPEN: i32 = 1;
const BACKUP_NOW: i32 = 2;
const SEPARATOR: i32 = 3;
const QUIT: i32 = 4;

/// Clicks, menu choices and theme changes, read by `poll` on the UI thread.
fn events() -> &'static (Sender<Action>, Mutex<Receiver<Action>>) {
    static EVENTS: OnceLock<(Sender<Action>, Mutex<Receiver<Action>>)> = OnceLock::new();
    EVENTS.get_or_init(|| {
        let (tx, rx) = channel();
        (tx, Mutex::new(rx))
    })
}

fn send(a: Action) {
    let _ = events().0.send(a);
}

/// Pending tray clicks, menu choices and dark-mode changes.
pub fn poll() -> Vec<Action> {
    events().1.lock().map(|rx| rx.try_iter().collect()).unwrap_or_default()
}

#[derive(Clone)]
struct State {
    badge: Badge,
    tooltip: String,
    /// None = hidden by policy, Some(enabled)
    backup_now: Option<bool>,
    revision: u32,
}

type Shared = Arc<Mutex<State>>;
/// a(iiay): width, height, ARGB32 pixels
type Pixmaps = Vec<(i32, i32, Vec<u8>)>;
/// (ia{sv}av): id, properties, children
type Layout = (i32, HashMap<String, OwnedVariant>, Vec<OwnedVariant>);

fn state(s: &Shared) -> State {
    s.lock().map(|g| g.clone()).unwrap_or_else(|e| e.into_inner().clone())
}

/// ARGB32 in network byte order, as the specification wants it.
fn pixmap(badge: Badge) -> Pixmaps {
    let rgba = crate::icon::rgba(badge, ICON_SIZE);
    let argb = rgba.chunks_exact(4).flat_map(|p| [p[3], p[0], p[1], p[2]]).collect();
    vec![(ICON_SIZE as i32, ICON_SIZE as i32, argb)]
}

struct Item(Shared);

#[interface(name = "org.kde.StatusNotifierItem")]
impl Item {
    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }
    #[zbus(property)]
    fn id(&self) -> &str {
        "nexus-agent-gui"
    }
    #[zbus(property)]
    fn title(&self) -> &str {
        TITLE
    }
    #[zbus(property)]
    fn status(&self) -> &str {
        "Active"
    }
    #[zbus(property)]
    fn window_id(&self) -> i32 {
        0
    }
    #[zbus(property)]
    fn icon_name(&self) -> &str {
        ""
    }
    #[zbus(property)]
    fn icon_pixmap(&self) -> Pixmaps {
        pixmap(state(&self.0).badge)
    }
    #[zbus(property)]
    fn tool_tip(&self) -> (String, Pixmaps, String, String) {
        (String::new(), Vec::new(), TITLE.to_string(), state(&self.0).tooltip)
    }
    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn menu(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from(MENU_PATH).expect("valid object path")
    }

    fn activate(&self, _x: i32, _y: i32) {
        send(Action::Open);
    }
    fn secondary_activate(&self, _x: i32, _y: i32) {}
    fn scroll(&self, _delta: i32, _orientation: &str) {}

    #[zbus(signal)]
    async fn new_icon(e: &SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn new_tool_tip(e: &SignalEmitter<'_>) -> zbus::Result<()>;
}

fn ov<'a>(v: impl Into<Variant<'a>>) -> OwnedVariant {
    v.into()
        .try_into_owned()
        .expect("no file descriptors in menu properties")
}

/// Properties of one menu item; `None` for an unknown id.
fn props(s: &State, id: i32) -> Option<HashMap<String, OwnedVariant>> {
    let mut p = HashMap::new();
    match id {
        0 => {
            p.insert("children-display".into(), ov("submenu"));
        }
        OPEN => {
            p.insert("label".into(), ov("Open NexusBackup Agent"));
        }
        BACKUP_NOW => {
            p.insert("label".into(), ov("Request backup now"));
            p.insert("visible".into(), ov(s.backup_now.is_some()));
            p.insert("enabled".into(), ov(s.backup_now.unwrap_or(false)));
        }
        SEPARATOR => {
            p.insert("type".into(), ov("separator"));
        }
        QUIT => {
            p.insert("label".into(), ov("Quit"));
        }
        _ => return None,
    }
    Some(p)
}

struct Menu(Shared);

#[interface(name = "com.canonical.dbusmenu")]
impl Menu {
    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }
    #[zbus(property)]
    fn text_direction(&self) -> &str {
        "ltr"
    }
    #[zbus(property)]
    fn status(&self) -> &str {
        "normal"
    }
    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }

    /// One flat menu: the root's children only.
    fn get_layout(&self, parent: i32, _depth: i32, _names: Vec<String>) -> zbus::fdo::Result<(u32, Layout)> {
        let s = state(&self.0);
        let root = props(&s, parent).ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("no menu item {parent}")))?;
        let children = if parent == 0 {
            [OPEN, BACKUP_NOW, SEPARATOR, QUIT]
                .into_iter()
                .filter_map(|id| props(&s, id).map(|p| ov((id, p, Vec::<OwnedVariant>::new()))))
                .collect()
        } else {
            Vec::new()
        };
        Ok((s.revision, (parent, root, children)))
    }

    fn get_group_properties(&self, ids: Vec<i32>, _names: Vec<String>) -> Vec<(i32, HashMap<String, OwnedVariant>)> {
        let s = state(&self.0);
        let ids = if ids.is_empty() {
            vec![0, OPEN, BACKUP_NOW, SEPARATOR, QUIT]
        } else {
            ids
        };
        ids.into_iter()
            .filter_map(|id| props(&s, id).map(|p| (id, p)))
            .collect()
    }

    fn get_property(&self, id: i32, name: &str) -> zbus::fdo::Result<OwnedVariant> {
        props(&state(&self.0), id)
            .and_then(|mut p| p.remove(name))
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("no property {name} on menu item {id}")))
    }

    fn event(&self, id: i32, event: &str, _data: OwnedVariant, _time: u32) {
        if event != "clicked" {
            return;
        }
        match id {
            OPEN => send(Action::Open),
            BACKUP_NOW if state(&self.0).backup_now == Some(true) => send(Action::BackupNow),
            QUIT => send(Action::Quit),
            _ => {}
        }
    }

    fn event_group(&self, events: Vec<(i32, String, OwnedVariant, u32)>) -> Vec<i32> {
        for (id, event, data, time) in events {
            self.event(id, &event, data, time);
        }
        Vec::new()
    }

    fn about_to_show(&self, _id: i32) -> bool {
        false
    }

    fn about_to_show_group(&self, _ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        (Vec::new(), Vec::new())
    }

    #[zbus(signal)]
    async fn layout_updated(e: &SignalEmitter<'_>, revision: u32, parent: i32) -> zbus::Result<()>;
}

pub struct Tray {
    conn: Connection,
    state: Shared,
}

impl Tray {
    pub fn new(tooltip: &str) -> Result<Tray, String> {
        let state: Shared = Arc::new(Mutex::new(State {
            badge: Badge::None,
            tooltip: tooltip.to_string(),
            backup_now: Some(true),
            revision: 1,
        }));
        let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
        let conn = zbus::block_on(async {
            let conn = zbus::connection::Builder::session()
                .name(name.as_str())
                .serve_at(ITEM_PATH, Item(state.clone()))
                .serve_at(MENU_PATH, Menu(state.clone()))
                .build()
                .await?;
            conn.call_method(
                Some("org.kde.StatusNotifierWatcher"),
                "/StatusNotifierWatcher",
                Some("org.kde.StatusNotifierWatcher"),
                "RegisterStatusNotifierItem",
                &(name.as_str(),),
            )
            .await?;
            Ok::<_, zbus::Error>(conn)
        })
        .map_err(|e| {
            format!("no tray (StatusNotifierWatcher on the session bus; GNOME needs the AppIndicator extension): {e}")
        })?;
        // ponytail: registered once; a restarted panel (new watcher) does not show the icon until the program restarts
        Ok(Tray { conn, state })
    }

    /// Applies a new state; only the changed parts are signalled.
    pub fn update(&mut self, badge: Badge, tooltip: &str, backup_now: Option<bool>) {
        let (icon, tip, menu) = {
            let Ok(mut s) = self.state.lock() else { return };
            let icon = s.badge != badge;
            let tip = s.tooltip != tooltip;
            let menu = s.backup_now != backup_now;
            s.badge = badge;
            s.tooltip = tooltip.to_string();
            s.backup_now = backup_now;
            if menu {
                s.revision += 1;
            }
            (icon, tip, menu.then_some(s.revision))
        };
        if !icon && !tip && menu.is_none() {
            return;
        }
        let conn = &self.conn;
        let _ = zbus::block_on(async {
            if icon || tip {
                let e = SignalEmitter::new(conn, ITEM_PATH)?;
                if icon {
                    Item::new_icon(&e).await?;
                }
                if tip {
                    Item::new_tool_tip(&e).await?;
                }
            }
            if let Some(rev) = menu {
                Menu::layout_updated(&SignalEmitter::new(conn, MENU_PATH)?, rev, 0).await?;
            }
            Ok::<_, zbus::Error>(())
        });
    }
}

/// Desktop notification (org.freedesktop.Notifications), off the UI thread; failures are
/// ignored (no notification daemon).
pub fn notify(title: String, body: String) {
    std::thread::spawn(move || {
        let _ = zbus::block_on(async {
            Connection::session()
                .await?
                .call_method(
                    Some("org.freedesktop.Notifications"),
                    "/org/freedesktop/Notifications",
                    Some("org.freedesktop.Notifications"),
                    "Notify",
                    &(
                        TITLE,
                        0u32,
                        "",
                        title.as_str(),
                        body.as_str(),
                        Vec::<&str>::new(),
                        HashMap::<&str, Variant<'_>>::new(),
                        -1i32,
                    ),
                )
                .await
                .map(|_| ())
        });
    });
}

/// The desktop's dark-mode preference (XDG desktop portal, org.freedesktop.appearance
/// color-scheme: 1 = dark), now and on every change, as `Action::Dark`. Without a portal
/// nothing is sent and the light theme stays.
pub fn watch_dark_mode() {
    std::thread::spawn(|| {
        let _ = zbus::block_on(async {
            use iced::futures::StreamExt;
            let conn = Connection::session().await?;
            let portal = zbus::Proxy::new(
                &conn,
                "org.freedesktop.portal.Desktop",
                "/org/freedesktop/portal/desktop",
                "org.freedesktop.portal.Settings",
            )
            .await?;
            let mut changes = portal.receive_signal("SettingChanged").await?;
            if let Ok(v) = portal
                .call::<_, _, OwnedVariant>("ReadOne", &("org.freedesktop.appearance", "color-scheme"))
                .await
            {
                send(Action::Dark(u32::try_from(v).ok() == Some(1)));
            }
            while let Some(m) = changes.next().await {
                if let Ok((ns, key, v)) = m.body().deserialize::<(String, String, OwnedVariant)>() {
                    if ns == "org.freedesktop.appearance" && key == "color-scheme" {
                        send(Action::Dark(u32::try_from(v).ok() == Some(1)));
                    }
                }
            }
            Ok::<_, zbus::Error>(())
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixmap_is_argb_in_network_order() {
        let rgba = crate::icon::rgba(Badge::None, ICON_SIZE);
        let p = &pixmap(Badge::None)[0];
        assert_eq!((p.0, p.1), (32, 32));
        assert_eq!(&p.2[..4], &[rgba[3], rgba[0], rgba[1], rgba[2]]);
        assert_eq!(p.2.len(), rgba.len());
    }

    #[test]
    fn backup_now_follows_the_policy() {
        let mut s = State {
            badge: Badge::None,
            tooltip: String::new(),
            backup_now: None,
            revision: 1,
        };
        let p = props(&s, BACKUP_NOW).unwrap();
        assert!(!bool::try_from(&p["visible"]).unwrap());
        s.backup_now = Some(false);
        let p = props(&s, BACKUP_NOW).unwrap();
        assert!(bool::try_from(&p["visible"]).unwrap());
        assert!(!bool::try_from(&p["enabled"]).unwrap());
        assert!(props(&s, 99).is_none());
    }
}
