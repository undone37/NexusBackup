//! `nexus-agent tui`: control panel in the style of Veeam Agent for Linux (docs/endpoint-ui.md).
//! Keyboard only, works over SSH, 80x24 minimum, colours optional (`NO_COLOR`): every state
//! also has a text label. Input handling (`App::key`) is separate from I/O (`run`) so the
//! screens can be rendered and tested without a terminal.

use super::proto::{Session, SessionDetail, Status};
use super::{bytes, connect, duration, failure, rate, reach_label, result_label, secs, state_label, Clock};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;
use std::path::Path;
use std::time::{Duration, Instant};

pub enum View {
    Main,
    Detail(SessionDetail),
    Log { detail: SessionDetail, scroll: u16 },
}

/// What the event loop has to do after a key press.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Refresh,
    Open(u64),
    Log(u64),
    RequestBackup,
}

pub struct App {
    pub clock: Clock,
    pub color: bool,
    pub now: u64,
    pub status: Option<Status>,
    pub sessions: Vec<Session>,
    pub selected: usize,
    pub view: View,
    pub confirm: bool,
    /// (is_error, text) shown above the session list
    pub message: Option<(bool, String)>,
    /// the agent service could not be reached at all
    pub conn_error: Option<String>,
}

impl App {
    pub fn new(clock: Clock, color: bool) -> App {
        App {
            clock,
            color,
            now: 0,
            status: None,
            sessions: vec![],
            selected: 0,
            view: View::Main,
            confirm: false,
            message: None,
            conn_error: None,
        }
    }

    fn backup_now_allowed(&self) -> bool {
        self.status
            .as_ref()
            .is_some_and(|s| s.enrolled && !s.ui_policy.hide_backup_now)
    }

    pub fn key(&mut self, code: KeyCode, mods: KeyModifiers) -> Action {
        if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            return Action::Quit;
        }
        let ch = match code {
            KeyCode::Char(c) => Some(c.to_ascii_lowercase()),
            _ => None,
        };
        if self.confirm {
            self.confirm = false;
            return match (code, ch) {
                (KeyCode::Enter, _) | (_, Some('y')) => Action::RequestBackup,
                _ => Action::None,
            };
        }
        if self.conn_error.is_some() {
            return match (code, ch) {
                (KeyCode::Esc, _) | (_, Some('q')) => Action::Quit,
                (_, Some('r')) => Action::Refresh,
                _ => Action::None,
            };
        }
        match &mut self.view {
            View::Main => match (code, ch) {
                (KeyCode::Esc, _) | (_, Some('q')) => Action::Quit,
                (_, Some('r')) => Action::Refresh,
                (_, Some('s')) if self.backup_now_allowed() => {
                    self.confirm = true;
                    Action::None
                }
                (KeyCode::Up, _) | (_, Some('k')) => {
                    self.selected = self.selected.saturating_sub(1);
                    Action::None
                }
                (KeyCode::Down, _) | (_, Some('j')) => {
                    self.selected = (self.selected + 1).min(self.sessions.len().saturating_sub(1));
                    Action::None
                }
                (KeyCode::PageUp, _) => {
                    self.selected = self.selected.saturating_sub(10);
                    Action::None
                }
                (KeyCode::PageDown, _) => {
                    self.selected = (self.selected + 10).min(self.sessions.len().saturating_sub(1));
                    Action::None
                }
                (KeyCode::Home, _) => {
                    self.selected = 0;
                    Action::None
                }
                (KeyCode::End, _) => {
                    self.selected = self.sessions.len().saturating_sub(1);
                    Action::None
                }
                (KeyCode::Enter, _) => self
                    .sessions
                    .get(self.selected)
                    .map_or(Action::None, |s| Action::Open(s.id)),
                (_, Some('l')) => self
                    .sessions
                    .get(self.selected)
                    .map_or(Action::None, |s| Action::Log(s.id)),
                _ => Action::None,
            },
            View::Detail(d) => match (code, ch) {
                (_, Some('q')) => Action::Quit,
                (KeyCode::Esc | KeyCode::Backspace, _) => {
                    self.view = View::Main;
                    Action::None
                }
                (_, Some('r')) => Action::Open(d.session.id),
                (_, Some('l')) => {
                    let detail = d.clone();
                    self.view = View::Log { detail, scroll: 0 };
                    Action::None
                }
                _ => Action::None,
            },
            View::Log { detail, scroll } => match (code, ch) {
                (_, Some('q')) => Action::Quit,
                (KeyCode::Esc | KeyCode::Backspace, _) | (_, Some('l')) => {
                    self.view = View::Detail(detail.clone());
                    Action::None
                }
                (_, Some('r')) => Action::Log(detail.session.id),
                (KeyCode::Up, _) | (_, Some('k')) => {
                    *scroll = scroll.saturating_sub(1);
                    Action::None
                }
                (KeyCode::Down, _) | (_, Some('j')) => {
                    *scroll = scroll.saturating_add(1).min(detail.log_tail.len() as u16);
                    Action::None
                }
                (KeyCode::PageUp, _) => {
                    *scroll = scroll.saturating_sub(10);
                    Action::None
                }
                (KeyCode::PageDown, _) => {
                    *scroll = scroll.saturating_add(10).min(detail.log_tail.len() as u16);
                    Action::None
                }
                _ => Action::None,
            },
        }
    }

    /// Reloads status and sessions (and the open session).
    pub fn refresh(&mut self, sock: &Path) {
        self.now = super::now();
        let r = connect(sock).and_then(|mut c| {
            let st = c.status().map_err(|e| failure(sock, e))?;
            let se = c
                .sessions(Some(super::proto::MAX_SESSIONS))
                .map_err(|e| failure(sock, e))?;
            Ok((st, se))
        });
        match r {
            Ok((st, se)) => {
                self.status = Some(st);
                self.sessions = se;
                self.selected = self.selected.min(self.sessions.len().saturating_sub(1));
                self.conn_error = None;
            }
            Err(f) => self.conn_error = Some(f.message),
        }
    }

    fn load(&mut self, sock: &Path, id: u64, log: bool) {
        match connect(sock).and_then(|mut c| c.session(id).map_err(|e| failure(sock, e))) {
            Ok(d) => {
                self.view = match &self.view {
                    View::Log { scroll, detail } if log && detail.session.id == id => View::Log {
                        detail: d,
                        scroll: *scroll,
                    },
                    _ if log => View::Log { detail: d, scroll: 0 },
                    _ => View::Detail(d),
                }
            }
            Err(f) => self.message = Some((true, f.message)),
        }
    }

    fn request_backup(&mut self, sock: &Path) {
        match connect(sock).and_then(|mut c| c.request_backup().map_err(|e| failure(sock, e))) {
            Ok(r) => {
                self.message = Some((
                    false,
                    format!(
                        "Backup requested at {}; it starts at the appliance's next poll.",
                        self.clock.fmt(r.queued_at)
                    ),
                ));
                self.refresh(sock);
            }
            Err(f) => self.message = Some((true, format!("Backup request refused: {}", f.message))),
        }
    }

    // ------------------------------------------------------------ rendering

    fn fg(&self, c: Color) -> Style {
        if self.color {
            Style::default().fg(c)
        } else {
            Style::default()
        }
    }

    fn accent(&self) -> Style {
        let c = self
            .status
            .as_ref()
            .and_then(|s| s.ui_policy.accent.as_deref())
            .and_then(parse_hex)
            .unwrap_or(Color::Cyan);
        self.fg(c)
    }

    fn result_style(&self, r: super::proto::SessionResult) -> Style {
        use super::proto::SessionResult::*;
        match r {
            Success => self.fg(Color::Green),
            Warning => self.fg(Color::Yellow),
            Failed => self.fg(Color::Red).add_modifier(Modifier::BOLD),
            Cancelled => self.fg(Color::Gray),
        }
    }

    pub fn render(&self, f: &mut Frame) {
        let area = f.area();
        let [head, body, keys] =
            Layout::vertical([Constraint::Length(7), Constraint::Min(5), Constraint::Length(1)]).areas(area);
        self.render_header(f, head);
        f.render_widget(Paragraph::new(self.key_help()), keys);
        if let Some(e) = &self.conn_error {
            let p = Paragraph::new(vec![
                Line::styled(
                    "Cannot reach the agent service",
                    self.fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw(e.clone()),
            ])
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title(" Agent service "));
            f.render_widget(p, body);
            return;
        }
        match &self.view {
            View::Main => self.render_main(f, body),
            View::Detail(d) => self.render_detail(f, body, d),
            View::Log { detail, scroll } => self.render_log(f, body, detail, *scroll),
        }
        if self.confirm {
            self.render_confirm(f, area);
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let title = self
            .status
            .as_ref()
            .and_then(|s| s.ui_policy.header.clone())
            .unwrap_or_else(|| "NexusBackup Agent".into());
        let block = Block::bordered()
            .title(format!(" {title} "))
            .border_style(self.accent());
        let Some(s) = &self.status else {
            f.render_widget(Paragraph::new("Status unknown").block(block), area);
            return;
        };
        let c = self.clock;
        let label = Style::default().add_modifier(Modifier::BOLD);
        let pair = |l1: &str, v1: String, l2: &str, v2: String, v2_style: Style| {
            let left = format!("{v1:<width$}", width = 37usize.saturating_sub(l1.len()));
            Line::from(vec![
                Span::styled(l1.to_string(), label),
                Span::raw(left),
                Span::styled(l2.to_string(), label),
                Span::styled(v2, v2_style),
            ])
        };
        let state_style = match s.state {
            super::proto::AgentState::Running | super::proto::AgentState::Requested => self.fg(Color::Cyan),
            super::proto::AgentState::Error => self.fg(Color::Red).add_modifier(Modifier::BOLD),
            _ => Style::default(),
        };
        let reach_style = if s.reachable {
            self.fg(Color::Green)
        } else {
            self.fg(Color::Red).add_modifier(Modifier::BOLD)
        };
        let lines = vec![
            pair(
                "Agent: ",
                if s.agent_id.is_empty() {
                    "-".into()
                } else {
                    s.agent_id.clone()
                },
                "Version: ",
                s.version.clone(),
                Style::default(),
            ),
            pair(
                "Appliance: ",
                s.appliance.clone().unwrap_or_else(|| "-".into()),
                "Managed by: ",
                s.managed_by.clone().unwrap_or_else(|| "-".into()),
                Style::default(),
            ),
            pair(
                "Next run: ",
                c.fmt_opt(s.next_run, "not scheduled"),
                "Last success: ",
                c.fmt_opt(s.last_success, "never"),
                Style::default(),
            ),
            Line::from(vec![
                Span::styled("State: ", label),
                Span::styled(state_label(s), state_style),
            ]),
            Line::from(vec![
                Span::styled("Appliance contact: ", label),
                Span::styled(reach_label(s, c), reach_style),
            ]),
        ];
        f.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn key_help(&self) -> Line<'static> {
        let key = Style::default().add_modifier(Modifier::REVERSED);
        let mut v = vec![];
        let mut k = |k: &str, l: &str| {
            v.push(Span::styled(format!(" {k} "), key));
            v.push(Span::raw(format!(" {l}  ")));
        };
        if self.confirm {
            k("Y", "Request backup");
            k("N", "Cancel");
        } else if self.conn_error.is_some() {
            k("R", "Retry");
            k("Q", "Quit");
        } else {
            match self.view {
                View::Main => {
                    let any = !self.sessions.is_empty();
                    if any {
                        k("Enter", "Details");
                    }
                    if self.backup_now_allowed() {
                        k("S", "Back up now");
                    }
                    if any {
                        k("L", "Log");
                    }
                    k("R", "Refresh");
                    k("Q", "Quit");
                }
                View::Detail(_) => {
                    k("L", "Log");
                    k("R", "Refresh");
                    k("Esc", "Back");
                    k("Q", "Quit");
                }
                View::Log { .. } => {
                    k("Up/Down", "Scroll");
                    k("Esc", "Back");
                    k("Q", "Quit");
                }
            }
        }
        Line::from(v)
    }

    fn render_main(&self, f: &mut Frame, area: Rect) {
        let running = self.status.as_ref().and_then(|s| s.running.as_ref());
        let [prog, msg, list] = Layout::vertical([
            Constraint::Length(if running.is_some() { 1 } else { 0 }),
            Constraint::Length(if self.message.is_some() { 1 } else { 0 }),
            Constraint::Min(3),
        ])
        .areas(area);
        if let Some(r) = running {
            let elapsed = duration(secs(r.started, self.now));
            let data = format!(
                "read {}, transferred {}",
                bytes(r.read_bytes),
                bytes(r.transferred_bytes)
            );
            let g = match r.percent {
                Some(p) => Gauge::default()
                    .ratio((f64::from(p) / 100.0).clamp(0.0, 1.0))
                    .label(format!("Running {p} %  {data}  ({elapsed})")),
                // percent unknown: no bar, only the data counters
                None => Gauge::default()
                    .ratio(0.0)
                    .label(format!("Running  {data}  ({elapsed})")),
            };
            let style = if self.color {
                Style::default().fg(Color::Cyan).bg(Color::DarkGray)
            } else {
                Style::default().add_modifier(Modifier::REVERSED)
            };
            f.render_widget(g.gauge_style(style), prog);
        }
        if let Some((err, m)) = &self.message {
            let st = if *err {
                self.fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                self.fg(Color::Cyan)
            };
            f.render_widget(Paragraph::new(Line::styled(format!(" {m}"), st)), msg);
        }
        let block = Block::bordered().title(" Latest backup sessions ");
        if self.sessions.is_empty() {
            let p = Paragraph::new(vec![
                Line::raw("No backup sessions yet."),
                Line::raw("The appliance sends a summary to this computer after every backup."),
            ])
            .wrap(Wrap { trim: true })
            .block(block);
            f.render_widget(p, list);
            return;
        }
        let rows = self.sessions.iter().map(|s| {
            let (g, l) = result_label(s.result);
            Row::new(vec![
                Span::styled(format!("{g} {l}"), self.result_style(s.result)).into(),
                Line::raw(self.clock.fmt(s.started)),
                Line::raw(duration(secs(s.started, s.ended))).right_aligned(),
                Line::raw(bytes(s.transferred_bytes)).right_aligned(),
                Line::raw(s.warnings.to_string()).right_aligned(),
            ])
        });
        let header = Row::new(vec![
            Line::raw("Result"),
            Line::raw("Start"),
            Line::raw("Duration").right_aligned(),
            Line::raw("Transferred").right_aligned(),
            Line::raw("Warnings").right_aligned(),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));
        let t = Table::new(
            rows,
            [
                Constraint::Length(13),
                Constraint::Length(16),
                Constraint::Length(9),
                Constraint::Length(12),
                Constraint::Length(9),
            ],
        )
        .header(header)
        .block(block)
        .highlight_symbol("> ")
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        let mut state = TableState::default().with_selected(Some(self.selected));
        f.render_stateful_widget(t, list, &mut state);
    }

    fn render_detail(&self, f: &mut Frame, area: Rect, d: &SessionDetail) {
        let s = &d.session;
        let (g, l) = result_label(s.result);
        let t = secs(s.started, s.ended);
        let c = self.clock;
        let bold = Style::default().add_modifier(Modifier::BOLD);
        let kv = |k: &str, v: String| Line::from(vec![Span::styled(format!("{k:<13}"), bold), Span::raw(v)]);
        let [top, rest] = Layout::vertical([Constraint::Length(7), Constraint::Min(3)]).areas(area);
        let [left, right] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(top);
        let summary = vec![
            Line::from(vec![
                Span::styled(format!("{:<13}", "Result"), bold),
                Span::styled(format!("{g} {l}"), self.result_style(s.result)),
            ]),
            kv("Start", c.fmt(s.started)),
            kv("Duration", duration(t)),
            kv("Rate", rate(s.read_bytes, t)),
            kv("Warnings", s.warnings.to_string()),
        ];
        let title = format!(" Session {} ({}) ", s.id, super::cli::kind(s.kind));
        f.render_widget(Paragraph::new(summary).block(Block::bordered().title(title)), left);
        let data = vec![
            kv("Read", bytes(s.read_bytes)),
            kv("Transferred", bytes(s.transferred_bytes)),
            kv("New", bytes(s.new_bytes)),
            kv("Point", c.fmt_opt(s.snapshot_time, "-")),
        ];
        f.render_widget(Paragraph::new(data).block(Block::bordered().title(" Data ")), right);
        let mut lines = vec![];
        if let Some(e) = &s.first_error {
            lines.push(Line::from(vec![
                Span::styled("First error: ", self.fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::raw(e.clone()),
            ]));
        }
        let room = (rest.height as usize).saturating_sub(2 + lines.len());
        let skip = d.log_tail.len().saturating_sub(room);
        lines.extend(d.log_tail[skip..].iter().map(|l| Line::raw(l.clone())));
        if lines.is_empty() {
            lines.push(Line::raw("No log lines."));
        }
        f.render_widget(
            Paragraph::new(lines).block(Block::bordered().title(" Log (last lines) ")),
            rest,
        );
    }

    fn render_log(&self, f: &mut Frame, area: Rect, d: &SessionDetail, scroll: u16) {
        let lines: Vec<Line> = d.log_tail.iter().map(|l| Line::raw(l.clone())).collect();
        let n = lines.len();
        let title = format!(" Log of session {} ({n} lines, newest last) ", d.session.id);
        let p = Paragraph::new(if n == 0 {
            vec![Line::raw("No log lines.")]
        } else {
            lines
        })
        .block(Block::bordered().title(title))
        .scroll((scroll, 0));
        f.render_widget(p, area);
    }

    fn render_confirm(&self, f: &mut Frame, area: Rect) {
        let w = 60.min(area.width);
        let r = Rect::new(
            area.x + (area.width - w) / 2,
            area.y + area.height.saturating_sub(7) / 2,
            w,
            7.min(area.height),
        );
        let p = Paragraph::new(vec![
            Line::raw("Request a backup of this computer now?"),
            Line::raw(""),
            Line::raw("The appliance starts it at its next poll"),
            Line::raw("(usually within a few minutes)."),
            Line::styled(
                "[Y] Request backup    [N] Cancel",
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ])
        .block(
            Block::bordered()
                .borders(Borders::ALL)
                .title(" Back up now ")
                .border_style(self.accent()),
        );
        f.render_widget(Clear, r);
        f.render_widget(p, r);
    }
}

fn parse_hex(s: &str) -> Option<Color> {
    let h = s.strip_prefix('#')?;
    if h.len() != 6 {
        return None;
    }
    let v = u32::from_str_radix(h, 16).ok()?;
    Some(Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8))
}

/// Interactive loop on the real terminal.
pub fn run(sock: &Path) -> std::io::Result<()> {
    let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let mut app = App::new(Clock::Local, color);
    app.refresh(sock);
    let mut term = ratatui::init();
    let res = (|| -> std::io::Result<()> {
        let mut last = Instant::now();
        loop {
            term.draw(|f| app.render(f))?;
            let running = app.status.as_ref().is_some_and(|s| s.running.is_some());
            let every = Duration::from_secs(if running { 2 } else { 10 });
            if event::poll(every.saturating_sub(last.elapsed()))? {
                let Event::Key(k) = event::read()? else { continue };
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match app.key(k.code, k.modifiers) {
                    Action::Quit => return Ok(()),
                    Action::None => continue,
                    Action::Refresh => {
                        app.message = None;
                        app.refresh(sock);
                    }
                    Action::Open(id) => app.load(sock, id, false),
                    Action::Log(id) => app.load(sock, id, true),
                    Action::RequestBackup => app.request_backup(sock),
                }
            } else {
                app.refresh(sock);
            }
            last = Instant::now();
        }
    })();
    ratatui::restore();
    res
}

#[cfg(test)]
mod tests;
