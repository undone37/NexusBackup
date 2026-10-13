//! The iced program: a daemon that owns the tray icon and opens the Control Panel window on
//! demand (Veeam Agent for Windows style, docs/endpoint-ui.md).

use crate::ipc::{self, Endpoint, Snapshot};
use crate::model::{self, Metric, TrayState};
use crate::settings::{self, Settings};
use crate::tray::{self, Tray};
use agent_ui_proto::{Session, SessionDetail, SessionResult};
use iced::widget::{
    button, canvas, checkbox, column, container, progress_bar, row, rule, scrollable, space, text, Column,
};
use iced::{keyboard, mouse, theme, time, window, Color, Element, Font, Length, Point, Rectangle, Renderer};
use iced::{Size, Subscription, Task, Theme};
use std::path::PathBuf;
use std::time::Duration;

/// Command-line options (src/main.rs).
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// open the window at start (application menu entry); the autostart entry starts in the tray
    pub open: bool,
    pub endpoint: Endpoint,
    /// per-user settings file; `None` = not persisted
    pub settings_path: Option<PathBuf>,
    /// receives "open" from a second instance (src/main.rs)
    pub wakeups: Option<std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>>,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    Refresh,
    Fetched(Result<Snapshot, String>),
    Select(u64),
    Detail(u64, Result<SessionDetail, String>),
    Metric(Metric),
    BackupNow,
    BackupDone(Result<String, String>),
    Notify(bool),
    DismissNotice,
    Opened(window::Id),
    Closed(window::Id),
    Key(keyboard::Event),
    Mode(theme::Mode),
}

pub struct App {
    opts: Options,
    settings: Settings,
    /// last good answer of the service
    snap: Option<Snapshot>,
    /// latest refresh failed (service down, no permission)
    error: Option<String>,
    fetching: bool,
    selected: Option<u64>,
    detail: Option<Result<SessionDetail, String>>,
    /// notification bar text (answers to "request backup now")
    notice: Option<Result<String, String>>,
    window: Option<window::Id>,
    tray: Option<Tray>,
    tray_error: Option<String>,
    mode: theme::Mode,
    /// newest session id already seen (desktop notifications only for newer ones)
    seen: Option<u64>,
}

pub fn run(opts: Options) -> iced::Result {
    iced::daemon(move || App::boot(opts.clone()), App::update, App::view)
        .title(|_: &App, _| "NexusBackup Agent".to_string())
        .theme(App::theme)
        .subscription(App::subscription)
        .run()
}

pub fn window_settings() -> window::Settings {
    window::Settings {
        size: Size::new(960.0, 760.0),
        min_size: Some(Size::new(720.0, 560.0)),
        icon: window::icon::from_rgba(crate::icon::rgba(model::Badge::None, 64), 64, 64).ok(),
        #[cfg(target_os = "linux")]
        platform_specific: window::settings::PlatformSpecific {
            application_id: "nexus-agent-gui".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

impl App {
    pub fn new(opts: Options) -> App {
        let settings = opts.settings_path.as_deref().map(settings::load).unwrap_or_default();
        App {
            opts,
            settings,
            snap: None,
            error: None,
            fetching: false,
            selected: None,
            detail: None,
            notice: None,
            window: None,
            tray: None,
            tray_error: None,
            mode: theme::Mode::None,
            seen: None,
        }
    }

    fn boot(opts: Options) -> (App, Task<Message>) {
        let open = opts.open;
        let mut app = App::new(opts);
        match Tray::new(&model::tooltip(&TrayState::NoJob, None)) {
            Ok(t) => app.tray = Some(t),
            Err(e) => app.tray_error = Some(e),
        }
        let mut tasks = vec![iced::system::theme().map(Message::Mode), Task::done(Message::Refresh)];
        // without a tray there is no other way into the program
        if open || app.tray.is_none() {
            tasks.push(app.open_window());
        }
        (app, Task::batch(tasks))
    }

    /// Test/screenshot constructor with a fixed snapshot.
    pub fn with_snapshot(snap: Snapshot, selected: Option<u64>, detail: Option<SessionDetail>) -> App {
        let mut app = App::new(Options::default());
        app.snap = Some(snap);
        app.selected = selected;
        app.detail = detail.map(Ok);
        app
    }

    /// As the OS dark mode would (screenshots).
    pub fn dark(mut self) -> App {
        self.mode = theme::Mode::Dark;
        self
    }

    fn open_window(&mut self) -> Task<Message> {
        if let Some(id) = self.window {
            return window::gain_focus(id);
        }
        let (id, task) = window::open(window_settings());
        self.window = Some(id);
        task.map(Message::Opened)
    }

    fn state(&self) -> TrayState {
        match (&self.error, &self.snap) {
            (Some(e), _) => TrayState::from_snapshot(Err(e), &[]),
            (None, Some(s)) => TrayState::from_snapshot(Ok(&s.status), &s.sessions),
            (None, None) => TrayState::NoJob,
        }
    }

    fn status(&self) -> Option<&agent_ui_proto::Status> {
        self.snap.as_ref().filter(|_| self.error.is_none()).map(|s| &s.status)
    }

    fn sessions(&self) -> &[Session] {
        self.snap.as_ref().map_or(&[], |s| &s.sessions)
    }

    fn sync_tray(&mut self) {
        let status = self.status().cloned();
        if !model::tray_visible(status.as_ref()) {
            self.tray = None;
            return;
        }
        if self.tray.is_none() && self.tray_error.is_none() {
            self.tray = Tray::new("").map_err(|e| self.tray_error = Some(e)).ok();
        }
        let state = self.state();
        let tip = model::tooltip(&state, status.as_ref());
        let backup_now = model::backup_now_visible(status.as_ref()).then(|| model::backup_now_enabled(status.as_ref()));
        if let Some(t) = &mut self.tray {
            t.update(state.badge(), &tip, backup_now);
        }
    }

    fn save_settings(&self) {
        if let Some(p) = &self.opts.settings_path {
            let _ = settings::save(p, &self.settings);
        }
    }

    fn select(&mut self, id: u64) -> Task<Message> {
        self.selected = Some(id);
        self.detail = None;
        let ep = self.opts.endpoint.clone();
        Task::perform(async move { (id, ipc::session(&ep, id)) }, |(id, r)| {
            Message::Detail(id, r)
        })
    }

    /// Moves the selection by `delta` sessions (positive = older).
    fn step(&mut self, delta: isize) -> Task<Message> {
        let s = self.sessions();
        if s.is_empty() {
            return Task::none();
        }
        let cur = self.selected.and_then(|id| s.iter().position(|x| x.id == id));
        let next = match cur {
            None => 0,
            Some(i) => (i as isize + delta).clamp(0, s.len() as isize - 1) as usize,
        };
        let id = s[next].id;
        self.select(id)
    }

    fn backup_now(&mut self) -> Task<Message> {
        if !model::backup_now_enabled(self.status()) {
            return Task::none();
        }
        let ep = self.opts.endpoint.clone();
        Task::perform(async move { ipc::request_backup(&ep) }, Message::BackupDone)
    }

    pub fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::Tick => {
                let mut tasks = Vec::new();
                for a in tray::poll() {
                    match a {
                        tray::Action::Open => tasks.push(self.open_window()),
                        tray::Action::BackupNow => tasks.push(self.backup_now()),
                        tray::Action::Quit => return iced::exit(),
                    }
                }
                let woken = self
                    .opts
                    .wakeups
                    .as_ref()
                    .is_some_and(|rx| rx.lock().is_ok_and(|rx| rx.try_recv().is_ok()));
                if woken {
                    tasks.push(self.open_window());
                }
                Task::batch(tasks)
            }
            Message::Refresh => {
                if self.fetching {
                    return Task::none();
                }
                self.fetching = true;
                let ep = self.opts.endpoint.clone();
                Task::perform(async move { ipc::fetch(&ep) }, Message::Fetched)
            }
            Message::Fetched(r) => {
                self.fetching = false;
                match r {
                    Ok(s) => {
                        if self.settings.notify {
                            if let Some((title, body)) = model::notification(self.seen, &s.sessions) {
                                std::thread::spawn(move || {
                                    let _ = notify_rust::Notification::new()
                                        .appname("NexusBackup Agent")
                                        .summary(&title)
                                        .body(&body)
                                        .show();
                                });
                            }
                        }
                        self.seen = s.sessions.first().map(|s| s.id).or(self.seen);
                        self.error = None;
                        self.snap = Some(s);
                    }
                    Err(e) => self.error = Some(e),
                }
                self.sync_tray();
                // no tray (policy or no tray host) and no window: nothing left to show
                if self.tray.is_none() && self.window.is_none() && !self.settings.notify {
                    return iced::exit();
                }
                Task::none()
            }
            Message::Select(id) => self.select(id),
            Message::Detail(id, r) => {
                if self.selected == Some(id) {
                    self.detail = Some(r);
                }
                Task::none()
            }
            Message::Metric(m) => {
                self.settings.metric = m;
                self.save_settings();
                Task::none()
            }
            Message::Notify(on) => {
                self.settings.notify = on;
                self.save_settings();
                Task::none()
            }
            Message::BackupNow => self.backup_now(),
            Message::BackupDone(r) => {
                self.notice = Some(r);
                Task::done(Message::Refresh)
            }
            Message::DismissNotice => {
                self.notice = None;
                Task::none()
            }
            Message::Opened(_) => Task::done(Message::Refresh),
            Message::Closed(id) => {
                if self.window == Some(id) {
                    self.window = None;
                }
                if self.tray.is_none() {
                    return iced::exit();
                }
                Task::none()
            }
            Message::Mode(m) => {
                self.mode = m;
                Task::none()
            }
            Message::Key(keyboard::Event::KeyPressed { key, modifiers, .. }) => {
                use keyboard::key::Named;
                if modifiers.control() || modifiers.alt() || modifiers.logo() {
                    return Task::none();
                }
                match key.as_ref() {
                    keyboard::Key::Named(Named::ArrowDown | Named::ArrowLeft) => self.step(1),
                    keyboard::Key::Named(Named::ArrowUp | Named::ArrowRight) => self.step(-1),
                    keyboard::Key::Named(Named::Home) => self.step(-(isize::MAX / 2)),
                    keyboard::Key::Named(Named::End) => self.step(isize::MAX / 2),
                    keyboard::Key::Named(Named::Escape) => match self.window {
                        Some(id) => window::close(id),
                        None => Task::none(),
                    },
                    keyboard::Key::Character("t") => {
                        let m = match self.settings.metric {
                            Metric::Transferred => Metric::Duration,
                            Metric::Duration => Metric::Transferred,
                        };
                        self.update(Message::Metric(m))
                    }
                    keyboard::Key::Character("b") => self.backup_now(),
                    keyboard::Key::Character("r") => self.update(Message::Refresh),
                    keyboard::Key::Character("n") => self.update(Message::Notify(!self.settings.notify)),
                    _ => Task::none(),
                }
            }
            Message::Key(_) => Task::none(),
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![
            time::every(Duration::from_millis(250)).map(|_| Message::Tick),
            // faster while a backup runs or a request waits (progress in the tooltip)
            time::every(Duration::from_secs(if self.fetch_fast() { 2 } else { 10 })).map(|_| Message::Refresh),
            window::close_events().map(Message::Closed),
            iced::system::theme_changes().map(Message::Mode),
        ];
        if self.window.is_some() {
            subs.push(keyboard::listen().map(Message::Key));
        }
        Subscription::batch(subs)
    }

    fn fetch_fast(&self) -> bool {
        self.status().is_some_and(|s| {
            matches!(
                s.state,
                agent_ui_proto::AgentState::Running | agent_ui_proto::AgentState::Requested
            )
        })
    }

    pub fn theme(&self, _: window::Id) -> Theme {
        let dark = self.mode == theme::Mode::Dark;
        let mut p = if dark {
            theme::Palette::DARK
        } else {
            theme::Palette::LIGHT
        };
        p.primary = if dark { rgb(0x2ec4b2) } else { rgb(0x0f766e) };
        p.success = rgb(RESULT_COLORS[0]);
        p.danger = rgb(RESULT_COLORS[2]);
        if let Some([r, g, b]) = self
            .status()
            .and_then(|s| s.ui_policy.accent.as_deref())
            .and_then(model::parse_accent)
        {
            p.primary = Color::from_rgb8(r, g, b);
        }
        Theme::custom(if dark { "NexusBackup dark" } else { "NexusBackup light" }, p)
    }

    pub fn view(&self, _: window::Id) -> Element<'_, Message> {
        let status = self.status();
        let state = self.state();

        // header: accent colour + header text from the UI policy
        let title = status.map_or_else(|| model::PRODUCT.to_string(), |s| model::header_title(&s.ui_policy));
        let managed = match status {
            Some(s) if s.enrolled => format!(
                "Managed by {}{}",
                s.managed_by.as_deref().unwrap_or("NexusBackup appliance"),
                s.appliance
                    .as_deref()
                    .map(|a| format!(" (appliance {a})"))
                    .unwrap_or_default()
            ),
            Some(_) => "Not enrolled with an appliance yet".into(),
            None => String::new(),
        };
        let agent = status
            .map(|s| format!("Agent {} · version {}", s.agent_id, s.version))
            .unwrap_or_default();
        let header = container(
            row![
                text(title).size(22),
                space().width(Length::Fill),
                column![text(managed).size(13), text(agent).size(12)].align_x(iced::Alignment::End),
            ]
            .align_y(iced::Alignment::Center),
        )
        .padding([12, 18])
        .width(Length::Fill)
        .style(|t: &Theme| {
            let p = t.extended_palette().primary.base;
            container::Style {
                background: Some(p.color.into()),
                text_color: Some(p.text),
                ..Default::default()
            }
        });

        let mut body = Column::new().spacing(14).padding(18);
        if let Some(e) = &self.error {
            body = body.push(bar(format!("Cannot reach the agent service: {e}"), true, None));
        }
        if let Some(n) = &self.notice {
            let (t, err) = match n {
                Ok(t) => (t.clone(), false),
                Err(e) => (format!("Backup request refused: {e}"), true),
            };
            body = body.push(bar(t, err, Some(Message::DismissNotice)));
        }
        if let (Some(e), None) = (&self.tray_error, &self.window) {
            body = body.push(bar(format!("No tray icon: {e}"), false, None));
        }

        // status card
        let badge = state.badge();
        let mut card = column![row![
            container(text(badge_symbol(badge)).size(18).color(Color::WHITE))
                .center_x(34)
                .center_y(34)
                .style(move |_: &Theme| container::Style {
                    background: Some(rgb(crate::icon::badge_color(badge)).into()),
                    border: iced::Border::default().rounded(17),
                    ..Default::default()
                }),
            text(state.label()).size(20),
        ]
        .spacing(12)
        .align_y(iced::Alignment::Center)]
        .spacing(8);
        if let Some(r) = status.and_then(|s| s.running.as_ref()) {
            let p = r.percent.unwrap_or(0) as f32;
            card = card.push(progress_bar(0.0..=100.0, p).girth(10));
            card = card.push(text(format!(
                "Started {} · {} read · {} transferred",
                model::fmt_time(r.started),
                model::fmt_bytes(r.read_bytes),
                model::fmt_bytes(r.transferred_bytes)
            )));
        }
        if let Some(s) = status {
            let reach = if s.reachable {
                format!(
                    "Reached by the appliance: {}",
                    model::fmt_opt_time(s.last_seen_by_appliance, "yes")
                )
            } else {
                format!(
                    "Not reached by the appliance since {} (backups resume when this computer is on the network again)",
                    model::fmt_opt_time(s.last_seen_by_appliance, "enrollment")
                )
            };
            card = card.push(
                row![
                    kv("Last successful backup", model::fmt_opt_time(s.last_success, "never")),
                    kv("Next backup", model::fmt_opt_time(s.next_run, "not scheduled")),
                ]
                .spacing(40),
            );
            card = card.push(text(reach).size(13));
        }
        if model::backup_now_visible(status) {
            let enabled = model::backup_now_enabled(status);
            card = card.push(
                row![
                    button(text("Request backup now"))
                        .on_press_maybe(enabled.then_some(Message::BackupNow))
                        .style(button::primary)
                        .padding([8, 16]),
                    text("The appliance starts the backup with its next poll (within about 2 minutes).").size(12),
                ]
                .spacing(12)
                .align_y(iced::Alignment::Center),
            );
        }
        body = body.push(
            container(card)
                .padding(14)
                .width(Length::Fill)
                .style(container::bordered_box),
        );

        // session chart
        let sessions = self.sessions();
        let metric = self.settings.metric;
        let toggle = |m: Metric| {
            button(text(m.label()).size(13))
                .on_press(Message::Metric(m))
                .style(if m == metric {
                    button::primary
                } else {
                    button::secondary
                })
                .padding([4, 10])
        };
        let bars: Vec<(model::Bar, String)> = model::chart_bars(sessions, metric)
            .into_iter()
            .map(|b| {
                let s = sessions
                    .iter()
                    .find(|s| s.id == b.id)
                    .map(model::session_summary)
                    .unwrap_or_default();
                (b, s)
            })
            .collect();
        let chart = canvas(Chart {
            bars,
            selected: self.selected,
        })
        .width(Length::Fill)
        .height(150);
        let legend =
            text("Bars: plain = success, marked ! warning, X failed, - cancelled; hover for details, click to select")
                .size(12);
        body = body.push(
            container(
                column![
                    row![
                        text(format!("Last {} sessions", model::CHART_SESSIONS)).size(16),
                        space().width(Length::Fill),
                        text("Height:").size(13),
                        toggle(Metric::Transferred),
                        toggle(Metric::Duration),
                    ]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
                    chart,
                    legend,
                ]
                .spacing(8),
            )
            .padding(14)
            .style(container::bordered_box),
        );

        // session list + detail panel
        let mut list = Column::new().spacing(2);
        list = list.push(
            row![
                text("Result").width(110),
                text("Started").width(140),
                text("Duration").width(100),
                text("Transferred").width(Length::Fill),
            ]
            .spacing(8)
            .padding([0, 8]),
        );
        if sessions.is_empty() {
            list = list.push(text("No sessions yet.").size(13));
        }
        for s in sessions {
            let sel = self.selected == Some(s.id);
            let kind = match s.kind {
                agent_ui_proto::SessionKind::Backup => "",
                agent_ui_proto::SessionKind::Restore => " (restore)",
            };
            let r = s.result;
            list = list.push(
                button(
                    row![
                        text(format!("{} {}{kind}", model::result_symbol(r), model::result_label(r)))
                            .width(110)
                            .color(result_color(r)),
                        text(model::fmt_time(s.started)).width(140),
                        text(model::fmt_duration(model::duration(s))).width(100),
                        text(model::fmt_bytes(s.transferred_bytes)).width(Length::Fill),
                    ]
                    .spacing(8),
                )
                .on_press(Message::Select(s.id))
                .width(Length::Fill)
                .padding([4, 8])
                .style(if sel { button::secondary } else { button::text }),
            );
        }
        let detail = self.detail_view();
        body = body.push(
            row![
                container(scrollable(list).height(260))
                    .width(Length::FillPortion(3))
                    .padding(8)
                    .style(container::bordered_box),
                container(detail)
                    .width(Length::FillPortion(2))
                    .padding(12)
                    .style(container::bordered_box),
            ]
            .spacing(14),
        );

        let footer = container(
            row![
                checkbox(self.settings.notify)
                    .label("Notify me when a backup fails or ends with warnings")
                    .on_toggle(Message::Notify),
                space().width(Length::Fill),
                text("Keys: ↑/↓ session · T chart height · B backup now · R refresh · N notifications · Esc close")
                    .size(12),
            ]
            .align_y(iced::Alignment::Center),
        )
        .padding([8, 18]);

        column![
            header,
            scrollable(body).height(Length::Fill),
            rule::horizontal(1),
            footer
        ]
        .into()
    }

    fn detail_view(&self) -> Element<'_, Message> {
        let d = match (&self.detail, self.selected) {
            (_, None) => return text("Select a session to see its details.").size(13).into(),
            (None, Some(_)) => return text("Loading…").size(13).into(),
            (Some(Err(e)), _) => return text(format!("Details unavailable: {e}")).size(13).into(),
            (Some(Ok(d)), _) => d,
        };
        let s = &d.session;
        let kind = match s.kind {
            agent_ui_proto::SessionKind::Backup => "Backup",
            agent_ui_proto::SessionKind::Restore => "Restore",
        };
        let mut c = column![
            text(format!("{kind} session {}", s.id)).size(16),
            text(format!(
                "{} {}",
                model::result_symbol(s.result),
                model::result_label(s.result)
            ))
            .color(result_color(s.result)),
            kv("Started", model::fmt_time(s.started)),
            kv("Ended", model::fmt_time(s.ended)),
            kv("Duration", model::fmt_duration(model::duration(s))),
        ]
        .spacing(4);
        if let Some(t) = s.snapshot_time {
            c = c.push(kv("Restore point", model::fmt_time(t)));
        }
        c = c.push(kv("Read", model::fmt_bytes(s.read_bytes)));
        c = c.push(kv("Transferred", model::fmt_bytes(s.transferred_bytes)));
        c = c.push(kv("New data", model::fmt_bytes(s.new_bytes)));
        c = c.push(kv("Warnings", s.warnings.to_string()));
        if let Some(e) = &s.first_error {
            c = c.push(
                text(format!("First error: {e}"))
                    .size(13)
                    .color(result_color(SessionResult::Failed)),
            );
        }
        if !d.log_tail.is_empty() {
            c = c.push(text("Log (last lines)").size(13));
            c = c.push(
                container(scrollable(text(d.log_tail.join("\n")).font(Font::MONOSPACE).size(11)).height(110))
                    .padding(6)
                    .width(Length::Fill)
                    .style(container::rounded_box),
            );
        }
        c.into()
    }
}

/// success, warning, failed, cancelled
const RESULT_COLORS: [u32; 4] = [0x1f9d55, 0xd08c00, 0xd13438, 0x8a8a8a];

fn rgb(c: u32) -> Color {
    Color::from_rgb8((c >> 16) as u8, (c >> 8) as u8, c as u8)
}

fn result_color(r: SessionResult) -> Color {
    rgb(match r {
        SessionResult::Success => RESULT_COLORS[0],
        SessionResult::Warning => RESULT_COLORS[1],
        SessionResult::Failed => RESULT_COLORS[2],
        SessionResult::Cancelled => RESULT_COLORS[3],
    })
}

fn badge_symbol(b: model::Badge) -> &'static str {
    use model::Badge::*;
    match b {
        None => "N",
        Clock => "…",
        Play => ">",
        Check => "OK",
        Warn => "!",
        Cross => "X",
        Stop => "-",
        Offline => "?",
    }
}

fn kv<'a>(k: &'a str, v: String) -> Element<'a, Message> {
    row![text(format!("{k}:")).size(13).width(170), text(v).size(13)].into()
}

/// Notification bar (Veeam Control Panel style) with an optional dismiss button.
fn bar<'a>(msg: String, error: bool, dismiss: Option<Message>) -> Element<'a, Message> {
    let mut r = row![text(msg).size(13).width(Length::Fill)]
        .spacing(10)
        .align_y(iced::Alignment::Center);
    if let Some(m) = dismiss {
        r = r.push(button(text("Dismiss").size(12)).on_press(m).style(button::text));
    }
    container(r)
        .padding([8, 12])
        .width(Length::Fill)
        .style(move |t: &Theme| {
            let p = if error {
                t.extended_palette().danger.weak
            } else {
                t.extended_palette().primary.weak
            };
            container::Style {
                background: Some(p.color.into()),
                text_color: Some(p.text),
                border: iced::Border::default().rounded(4),
                ..Default::default()
            }
        })
        .into()
}

/// Session bar chart: one bar per session, colour + symbol = result, height = metric.
struct Chart {
    bars: Vec<(model::Bar, String)>,
    selected: Option<u64>,
}

impl Chart {
    /// Bar slot under `p` (fixed 30 slots, newest at the right edge).
    fn index_at(&self, bounds: Rectangle, p: Point) -> Option<usize> {
        let w = bounds.width / model::CHART_SESSIONS as f32;
        let first = model::CHART_SESSIONS - self.bars.len();
        let slot = (p.x / w) as usize;
        (slot >= first && slot < model::CHART_SESSIONS).then(|| slot - first)
    }
}

impl canvas::Program<Message> for Chart {
    type State = Option<usize>;

    fn update(
        &self,
        hovered: &mut Option<usize>,
        event: &iced::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<Message>> {
        let at = cursor.position_in(bounds).and_then(|p| self.index_at(bounds, p));
        match event {
            iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                at.map(|i| canvas::Action::publish(Message::Select(self.bars[i].0.id)).and_capture())
            }
            iced::Event::Mouse(_) if at != *hovered => {
                *hovered = at;
                Some(canvas::Action::request_redraw())
            }
            _ => None,
        }
    }

    fn draw(
        &self,
        hovered: &Option<usize>,
        renderer: &Renderer,
        theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut f = canvas::Frame::new(renderer, bounds.size());
        let pal = theme.extended_palette();
        let fg = pal.background.base.text;
        let (top, base) = (18.0, bounds.height - 2.0);
        f.fill_rectangle(
            Point::new(0.0, base),
            Size::new(bounds.width, 1.0),
            pal.background.strong.color,
        );
        if self.bars.is_empty() {
            f.fill_text(canvas::Text {
                content: "No sessions yet".into(),
                position: Point::new(8.0, base - 24.0),
                color: fg,
                size: 13.into(),
                ..Default::default()
            });
        }
        let w = bounds.width / model::CHART_SESSIONS as f32;
        let first = model::CHART_SESSIONS - self.bars.len();
        for (i, (b, _)) in self.bars.iter().enumerate() {
            let h = (base - top) * b.height;
            let x = (first + i) as f32 * w + w * 0.15;
            let bw = w * 0.7;
            f.fill_rectangle(Point::new(x, base - h), Size::new(bw, h), result_color(b.result));
            if self.selected == Some(b.id) || *hovered == Some(i) {
                let path = canvas::Path::rectangle(Point::new(x - 1.5, base - h - 1.5), Size::new(bw + 3.0, h + 1.5));
                f.stroke(&path, canvas::Stroke::default().with_color(fg).with_width(2.0));
            }
            if bw >= 10.0 && b.result != SessionResult::Success {
                f.fill_text(canvas::Text {
                    content: model::result_symbol(b.result).into(),
                    position: Point::new(x + bw / 2.0, base - h - 3.0),
                    color: fg,
                    size: 11.into(),
                    align_x: iced::widget::text::Alignment::Center,
                    align_y: iced::alignment::Vertical::Bottom,
                    ..Default::default()
                });
            }
        }
        // hover tooltip: status, time, duration, size
        if let (Some(i), Some(p)) = (*hovered, cursor.position_in(bounds)) {
            let tip = &self.bars[i].1;
            let tw = tip.chars().count() as f32 * 6.6 + 16.0;
            let x = (p.x + 12.0).min(bounds.width - tw).max(0.0);
            let y = (p.y - 34.0).max(0.0);
            let bg = canvas::Path::rounded_rectangle(Point::new(x, y), Size::new(tw, 24.0), 4.0.into());
            f.fill(&bg, pal.background.weak.color);
            f.stroke(&bg, canvas::Stroke::default().with_color(pal.background.strong.color));
            f.fill_text(canvas::Text {
                content: tip.clone(),
                position: Point::new(x + 8.0, y + 5.0),
                color: pal.background.weak.text,
                size: 12.into(),
                ..Default::default()
            });
        }
        vec![f.into_geometry()]
    }

    fn mouse_interaction(&self, _: &Option<usize>, bounds: Rectangle, cursor: mouse::Cursor) -> mouse::Interaction {
        match cursor.position_in(bounds).and_then(|p| self.index_at(bounds, p)) {
            Some(_) => mouse::Interaction::Pointer,
            None => mouse::Interaction::default(),
        }
    }
}
