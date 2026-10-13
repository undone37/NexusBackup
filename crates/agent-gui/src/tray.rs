//! Tray icon (tray-icon crate): Windows notification area, Linux StatusNotifierItem
//! (D-Bus, pure Rust; GNOME needs the AppIndicator extension). Created on the UI thread,
//! whose event loop (winit) pumps the Windows messages; events are read from tray-icon's
//! global channels on every UI tick.

use crate::model::Badge;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Open,
    BackupNow,
    Quit,
}

pub struct Tray {
    icon: TrayIcon,
    menu: Menu,
    backup_now: MenuItem,
    backup_now_shown: bool,
    badge: Badge,
    tooltip: String,
}

const ICON_SIZE: u32 = 32;

fn icon(badge: Badge) -> Option<Icon> {
    Icon::from_rgba(crate::icon::rgba(badge, ICON_SIZE), ICON_SIZE, ICON_SIZE).ok()
}

impl Tray {
    pub fn new(tooltip: &str) -> Result<Tray, String> {
        let menu = Menu::new();
        let open = MenuItem::with_id("open", "Open NexusBackup Agent", true, None);
        let backup_now = MenuItem::with_id("backup_now", "Request backup now", true, None);
        let quit = MenuItem::with_id("quit", "Quit", true, None);
        menu.append_items(&[&open, &backup_now, &PredefinedMenuItem::separator(), &quit])
            .map_err(|e| e.to_string())?;
        let icon = TrayIconBuilder::new()
            .with_id("nexus-agent-gui")
            .with_title("NexusBackup Agent")
            .with_tooltip(tooltip)
            .with_icon(icon(Badge::None).ok_or("icon")?)
            .with_menu(Box::new(menu.clone()))
            .with_menu_on_left_click(false)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Tray {
            icon,
            menu,
            backup_now,
            backup_now_shown: true,
            badge: Badge::None,
            tooltip: tooltip.to_string(),
        })
    }

    /// Applies a new state; unchanged parts are not sent again.
    pub fn update(&mut self, badge: Badge, tooltip: &str, backup_now: Option<bool>) {
        if badge != self.badge {
            self.badge = badge;
            let _ = self.icon.set_icon(icon(badge));
        }
        if tooltip != self.tooltip {
            self.tooltip = tooltip.to_string();
            let _ = self.icon.set_tooltip(Some(tooltip));
        }
        // None = hidden by policy, Some(enabled)
        match (backup_now, self.backup_now_shown) {
            (None, true) => {
                let _ = self.menu.remove(&self.backup_now);
                self.backup_now_shown = false;
            }
            (Some(_), false) => {
                let _ = self.menu.insert(&self.backup_now, 1);
                self.backup_now_shown = true;
            }
            _ => {}
        }
        if let Some(enabled) = backup_now {
            self.backup_now.set_enabled(enabled);
        }
    }
}

/// Pending tray clicks and menu choices.
pub fn poll() -> Vec<Action> {
    let mut out = Vec::new();
    while let Ok(e) = MenuEvent::receiver().try_recv() {
        match e.id.0.as_str() {
            "open" => out.push(Action::Open),
            "backup_now" => out.push(Action::BackupNow),
            "quit" => out.push(Action::Quit),
            _ => {}
        }
    }
    while let Ok(e) = TrayIconEvent::receiver().try_recv() {
        match e {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: tray_icon::MouseButtonState::Up,
                ..
            }
            | TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => out.push(Action::Open),
            _ => {}
        }
    }
    out
}
