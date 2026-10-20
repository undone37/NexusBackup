//! Console wizard (ratatui + crossterm). Only presentation and input live here;
//! every decision is delegated to `Setup`. Works on an 80x25 Linux console
//! (ASCII plus box drawing and half blocks, 8 colours).

use crate::{
    challenge, check_password_pair, list_nics, parse_static, qr_lines, validate_username, Ipv4Config, KeyState, Link,
    NetConfig, Nic, RecoveryKey, Role, Setup, Step, TlsInfo, WEB_PORT,
};
use anyhow::Result;
use catalog::auth;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io::{stdout, Stdout};
use zeroize::Zeroizing;

type Term = Terminal<CrosstermBackend<Stdout>>;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    Quit,
}

// ---------------------------------------------------------------- forms

enum Kind {
    Text { masked: bool },
    Choice(Vec<String>),
}

struct Field {
    label: String,
    kind: Kind,
    value: Zeroizing<String>,
    choice: usize,
    enabled: bool,
}

impl Field {
    fn text(label: impl Into<String>, value: &str) -> Field {
        Field {
            label: label.into(),
            kind: Kind::Text { masked: false },
            value: Zeroizing::new(value.to_owned()),
            choice: 0,
            enabled: true,
        }
    }
    fn secret(label: impl Into<String>) -> Field {
        Field {
            kind: Kind::Text { masked: true },
            ..Field::text(label, "")
        }
    }
    fn choice(label: impl Into<String>, options: Vec<String>) -> Field {
        Field {
            kind: Kind::Choice(options),
            ..Field::text(label, "")
        }
    }
}

struct Form {
    fields: Vec<Field>,
    focus: usize,
}

impl Form {
    fn new(fields: Vec<Field>) -> Form {
        Form { fields, focus: 0 }
    }
    fn val(&self, i: usize) -> &str {
        &self.fields[i].value
    }
    fn move_focus(&mut self, fwd: bool) {
        let n = self.fields.len();
        for step in 1..=n {
            let i = if fwd {
                (self.focus + step) % n
            } else {
                (self.focus + n - step) % n
            };
            if self.fields[i].enabled {
                self.focus = i;
                return;
            }
        }
    }
    fn last_enabled(&self) -> usize {
        self.fields.iter().rposition(|f| f.enabled).unwrap_or(0)
    }
    /// Returns true when the form is submitted (Enter on the last field).
    fn handle(&mut self, k: KeyEvent) -> bool {
        let last = self.focus >= self.last_enabled();
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let f = &mut self.fields[self.focus];
        match (k.code, &f.kind) {
            (KeyCode::Char('u'), Kind::Text { .. }) if ctrl => f.value.clear(),
            (KeyCode::Char(_), _) if ctrl => {}
            (KeyCode::Enter, _) if last => return true,
            (KeyCode::Enter | KeyCode::Tab | KeyCode::Down, _) => self.move_focus(true),
            (KeyCode::BackTab | KeyCode::Up, _) => self.move_focus(false),
            (KeyCode::Left, Kind::Choice(o)) if !o.is_empty() => f.choice = (f.choice + o.len() - 1) % o.len(),
            (KeyCode::Right | KeyCode::Char(' '), Kind::Choice(o)) if !o.is_empty() => {
                f.choice = (f.choice + 1) % o.len();
            }
            (KeyCode::Char(c), Kind::Text { .. }) if f.value.len() < 256 && !c.is_control() => f.value.push(c),
            (KeyCode::Backspace, Kind::Text { .. }) => {
                f.value.pop();
            }
            _ => {}
        }
        false
    }
    fn lines(&self, cursor: &mut Option<(u16, u16)>, top: u16, left: u16) -> Vec<Line<'static>> {
        const W: usize = 20;
        let mut out = vec![];
        for (i, f) in self.fields.iter().enumerate() {
            let shown = match &f.kind {
                Kind::Text { masked: true } => "*".repeat(f.value.chars().count()),
                Kind::Text { masked: false } => f.value.to_string(),
                Kind::Choice(o) => format!("< {} >", o.get(f.choice).map(String::as_str).unwrap_or("-")),
            };
            let focused = i == self.focus && f.enabled;
            let style = if !f.enabled {
                Style::new().fg(Color::DarkGray)
            } else if focused {
                Style::new().add_modifier(Modifier::REVERSED)
            } else {
                Style::new().add_modifier(Modifier::UNDERLINED)
            };
            let label = format!("{:<W$}", format!("{}:", f.label));
            if focused && matches!(f.kind, Kind::Text { .. }) {
                *cursor = Some((left + (W + 1 + shown.chars().count()) as u16, top + out.len() as u16));
            }
            out.push(Line::from(vec![
                Span::styled(
                    label,
                    if f.enabled {
                        Style::new().fg(Color::Cyan)
                    } else {
                        Style::new().fg(Color::DarkGray)
                    },
                ),
                Span::raw(" "),
                Span::styled(format!("{shown} "), style),
            ]));
        }
        out
    }
}

// ---------------------------------------------------------------- screens

enum Screen {
    Overview {
        sel: usize,
    },
    Network {
        form: Form,
        nics: Vec<Nic>,
    },
    ConfirmReplace {
        role: Role,
        existing: String,
        form: Form,
    },
    /// second person now (security officer) or later (approvals start disabled)
    SecondPerson {
        form: Form,
    },
    Account {
        role: Role,
        replace: bool,
        form: Form,
    },
    Totp {
        role: Role,
        replace: bool,
        name: String,
        password: Zeroizing<String>,
        secret: Zeroizing<String>,
        qr: Vec<String>,
        form: Form,
    },
    KeyIntro,
    ShowKey {
        key: RecoveryKey,
        form: Form,
    },
    Challenge {
        key: RecoveryKey,
        idx: [usize; 3],
        form: Form,
    },
    FullKey {
        form: Form,
    },
    Tls {
        info: TlsInfo,
    },
    Finish,
    /// first boot on a replacement appliance: fetch a configuration backup from an
    /// offsite target and restore it (crate::cfgbackup)
    Restore {
        form: Form,
        sftp: bool,
        /// the public half of the key generated for this restore (SFTP)
        pubkey: String,
        key_file: std::path::PathBuf,
    },
    Done {
        lines: Vec<String>,
    },
}

enum Status {
    Info(String),
    Error(String),
}

struct App<'a> {
    s: &'a mut Setup,
    screen: Screen,
    status: Option<Status>,
    /// `--force-reconfigure-network`: redo the network even if it is recorded as done.
    force_network: bool,
    /// setup-done exists: only the network (plus new certificate) is reconfigured.
    reconfigure_only: bool,
    /// Ctrl-C pressed once on a recovery-key screen.
    abort_armed: bool,
    /// Wipe screen and scrollback before the next draw (after the key was confirmed).
    wipe: bool,
    outcome: Option<Outcome>,
}

const NET_IF: usize = 0;
const NET_METHOD: usize = 1;
const NET_ADDR: usize = 2;
const NET_GW: usize = 3;
const NET_DNS: usize = 4;
const NET_HOST: usize = 5;
const NET_BOND: usize = 6;
const NET_BOND_MODE: usize = 7;
const NET_VLAN: usize = 8;
const NET_MTU: usize = 9;
const BOND_MODES: [&str; 2] = ["active-backup", "802.3ad"];

fn bold(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::new().add_modifier(Modifier::BOLD))
}

fn warn(s: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(
        s.into(),
        Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    ))
}

/// The optional bond / VLAN / MTU fields of the network screen.
fn parse_link(bond: &str, mode: &str, vlan: &str, mtu: &str) -> Result<Link> {
    let bond: Vec<String> = bond
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let num = |s: &str, what: &str| -> Result<Option<u32>> {
        match s.trim() {
            "" => Ok(None),
            v => v.parse().map(Some).map_err(|_| anyhow::anyhow!("invalid {what} {v:?}")),
        }
    };
    let vlan = num(vlan, "VLAN ID")?
        .map(|v| u16::try_from(v).map_err(|_| anyhow::anyhow!("VLAN ID must be 1 to 4094")))
        .transpose()?;
    Ok(Link {
        bond_mode: (!bond.is_empty()).then(|| mode.to_owned()),
        bond,
        vlan,
        mtu: num(mtu, "MTU")?,
    })
}

impl App<'_> {
    fn err(&mut self, e: impl std::fmt::Display) {
        self.status = Some(Status::Error(e.to_string()));
    }
    fn info(&mut self, m: impl Into<String>) {
        self.status = Some(Status::Info(m.into()));
    }

    /// Shows a message while a blocking operation (nmcli, argon2, keygen) runs.
    fn busy(&mut self, term: &mut Term, msg: &str) {
        self.info(msg);
        let _ = term.draw(|f| self.render(f));
    }

    fn network_screen(&mut self) -> Screen {
        let nics = list_nics(&self.s.paths.sys_class_net).unwrap_or_default();
        let nic_field = if nics.is_empty() {
            Field::text("Interface", "")
        } else {
            Field::choice(
                "Interface",
                nics.iter()
                    .map(|n| format!("{} {} {}", n.name, n.mac, if n.up { "link up" } else { "no link" }))
                    .collect(),
            )
        };
        let mut form = Form::new(vec![
            nic_field,
            Field::choice("IPv4 method", vec!["static".into(), "DHCP".into()]),
            Field::text("Address/prefix", ""),
            Field::text("Gateway", ""),
            Field::text("DNS servers", ""),
            Field::text("Hostname", &self.s.management().map(|m| m.0).unwrap_or_default()),
            Field::text("Bond with NICs", ""),
            Field::choice("Bond mode", vec!["active-backup".into(), "802.3ad (LACP)".into()]),
            Field::text("VLAN ID", ""),
            Field::text("MTU", ""),
        ]);
        // preselect the first NIC with link
        form.fields[NET_IF].choice = nics.iter().position(|n| n.up).unwrap_or(0);
        Screen::Network { form, nics }
    }

    fn account_screen(&self, role: Role, replace: bool) -> Screen {
        let name = match (role, replace) {
            (Role::Admin, false) => "admin",
            _ => "",
        };
        Screen::Account {
            role,
            replace,
            form: Form::new(vec![
                Field::text("User name", name),
                Field::secret("Password (min. 12)"),
                Field::secret("Repeat password"),
            ]),
        }
    }

    /// Next screen from the persisted progress. Metrics token is created without a screen.
    fn advance(&mut self) -> Result<()> {
        if self.force_network {
            self.screen = self.network_screen();
            return Ok(());
        }
        if self.reconfigure_only {
            self.screen = Screen::Done {
                lines: vec!["Network reconfigured.".into()],
            };
            return Ok(());
        }
        self.screen = match self.s.next_step()? {
            Some(Step::Network) => self.network_screen(),
            Some(Step::Admin) => self.account_screen(Role::Admin, false),
            Some(Step::SecurityOfficer) => Screen::SecondPerson {
                form: Form::new(vec![Field::choice(
                    "Second person",
                    vec![
                        "create it now (recommended)".into(),
                        "later (approvals start DISABLED)".into(),
                    ],
                )]),
            },
            Some(Step::RecoveryKey) => match self.s.key_state()? {
                KeyState::Unconfirmed => Screen::FullKey {
                    form: Form::new(vec![Field::text("Recovery key", "")]),
                },
                _ => Screen::KeyIntro,
            },
            Some(Step::Tls) => Screen::Tls {
                info: self.s.tls(false)?,
            },
            Some(Step::MetricsToken) => {
                self.s.metrics_token()?;
                return self.advance();
            }
            Some(Step::Finish) => Screen::Finish,
            None => Screen::Done {
                lines: vec!["Setup is already complete.".into()],
            },
        };
        Ok(())
    }

    fn on_key(&mut self, k: KeyEvent, term: &mut Term) -> Result<()> {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            let key_on_screen = matches!(self.screen, Screen::ShowKey { .. } | Screen::Challenge { .. });
            if key_on_screen && !self.abort_armed {
                self.abort_armed = true;
                self.err("Ctrl-C again aborts. The recovery key is then never shown again; the next run requires typing it in full.");
            } else {
                self.outcome = Some(Outcome::Quit);
            }
            return Ok(());
        }
        self.abort_armed = false;
        let screen = std::mem::replace(&mut self.screen, Screen::Overview { sel: 0 });
        self.screen = match screen {
            Screen::Overview { mut sel } => match k.code {
                KeyCode::Up => Screen::Overview {
                    sel: sel.saturating_sub(1),
                },
                KeyCode::Down => Screen::Overview {
                    sel: (sel + 1).min(Step::ALL.len() - 1),
                },
                KeyCode::Char('q') => {
                    self.outcome = Some(Outcome::Quit);
                    Screen::Overview { sel }
                }
                KeyCode::Enter => {
                    self.status = None;
                    self.advance()?;
                    return Ok(());
                }
                KeyCode::Char('b') if !self.reconfigure_only => {
                    self.status = None;
                    match self.restore_screen(true) {
                        Ok(screen) => screen,
                        Err(e) => {
                            self.err(format!("{e:#}"));
                            Screen::Overview { sel }
                        }
                    }
                }
                KeyCode::Char('r') => {
                    let step = Step::ALL[sel];
                    match step {
                        Step::Network => {
                            self.force_network = true;
                            self.network_screen()
                        }
                        Step::Admin | Step::SecurityOfficer => {
                            let role = if step == Step::Admin {
                                Role::Admin
                            } else {
                                Role::SecurityOfficer
                            };
                            match self.s.user_with_role(role)? {
                                Some(existing) => Screen::ConfirmReplace {
                                    role,
                                    existing,
                                    form: Form::new(vec![Field::text("Existing name", "")]),
                                },
                                None => self.account_screen(role, false),
                            }
                        }
                        Step::Tls if self.s.is_done(Step::Tls)? => {
                            self.busy(term, "Generating a new certificate ...");
                            Screen::Tls {
                                info: self.s.tls(true)?,
                            }
                        }
                        _ => {
                            self.err(format!("\"{}\" cannot be redone here", step.title()));
                            sel = sel.min(Step::ALL.len() - 1);
                            Screen::Overview { sel }
                        }
                    }
                }
                _ => Screen::Overview { sel },
            },

            Screen::Network { mut form, nics } => {
                if k.code == KeyCode::Esc && !self.reconfigure_only {
                    self.force_network = false;
                    Screen::Overview { sel: 0 }
                } else if form.handle(k) {
                    self.submit_network(form, nics, term)?
                } else {
                    let dhcp = form.fields[NET_METHOD].choice == 1;
                    form.fields[NET_BOND_MODE].enabled = !form.val(NET_BOND).trim().is_empty();
                    for i in [NET_ADDR, NET_GW, NET_DNS] {
                        form.fields[i].enabled = !dhcp;
                    }
                    Screen::Network { form, nics }
                }
            }

            Screen::ConfirmReplace {
                role,
                existing,
                mut form,
            } => {
                if k.code == KeyCode::Esc {
                    Screen::Overview { sel: 0 }
                } else if form.handle(k) {
                    if form.val(0) == existing {
                        self.info(format!("Replacing {existing}: enter the new credentials."));
                        self.account_screen(role, true)
                    } else {
                        self.err("Name does not match; nothing was changed.");
                        Screen::Overview { sel: 0 }
                    }
                } else {
                    Screen::ConfirmReplace { role, existing, form }
                }
            }

            Screen::SecondPerson { mut form } => {
                if k.code == KeyCode::Esc {
                    Screen::Overview { sel: 0 }
                } else if form.handle(k) {
                    if form.fields[0].choice == 0 {
                        self.status = None;
                        self.account_screen(Role::SecurityOfficer, false)
                    } else {
                        self.s.second_person_later()?;
                        self.info(
                            "No second person: approvals start DISABLED. Add one later in the web UI (Users) \
                             and enable approvals (Approvals page).",
                        );
                        self.advance()?;
                        return Ok(());
                    }
                } else {
                    Screen::SecondPerson { form }
                }
            }

            Screen::Account {
                role,
                replace,
                mut form,
            } => {
                if k.code == KeyCode::Esc {
                    Screen::Overview { sel: 0 }
                } else if form.handle(k) {
                    self.submit_account(role, replace, form)?
                } else {
                    Screen::Account { role, replace, form }
                }
            }

            Screen::Totp {
                role,
                replace,
                name,
                password,
                secret,
                qr,
                mut form,
            } => {
                if k.code == KeyCode::Esc {
                    self.account_screen(role, replace)
                } else if form.handle(k) {
                    self.busy(term, "Hashing password ...");
                    match self
                        .s
                        .create_user(role, &name, &password, &secret, form.val(0), replace)
                    {
                        Ok(()) => {
                            self.info(format!("{} account {name} created.", role.label()));
                            self.advance()?;
                            return Ok(());
                        }
                        Err(e) => {
                            self.err(e);
                            form.fields[0].value.clear();
                            Screen::Totp {
                                role,
                                replace,
                                name,
                                password,
                                secret,
                                qr,
                                form,
                            }
                        }
                    }
                } else {
                    Screen::Totp {
                        role,
                        replace,
                        name,
                        password,
                        secret,
                        qr,
                        form,
                    }
                }
            }

            Screen::KeyIntro => match k.code {
                KeyCode::Enter => {
                    self.busy(term, "Initialising the key service ...");
                    match self.s.keyd_init() {
                        Ok(key) => {
                            self.status = None;
                            Screen::ShowKey {
                                key,
                                form: Form::new(vec![Field::text("Type YES when done", "")]),
                            }
                        }
                        Err(e) => {
                            self.err(e);
                            Screen::KeyIntro
                        }
                    }
                }
                KeyCode::Esc => Screen::Overview { sel: 0 },
                _ => Screen::KeyIntro,
            },

            Screen::ShowKey { key, mut form } => {
                if form.handle(k) {
                    if form.val(0).trim().eq_ignore_ascii_case("yes") {
                        self.status = None;
                        challenge_screen(key)
                    } else {
                        form.fields[0].value.clear();
                        self.err("Type YES once the key is written down.");
                        Screen::ShowKey { key, form }
                    }
                } else {
                    Screen::ShowKey { key, form }
                }
            }

            Screen::Challenge { key, idx, mut form } => {
                if k.code == KeyCode::Esc {
                    self.info("Key shown again. It disappears for good once confirmed.");
                    Screen::ShowKey {
                        key,
                        form: Form::new(vec![Field::text("Type YES when done", "")]),
                    }
                } else if form.handle(k) {
                    let answers: Vec<&str> = (0..3).map(|i| form.val(i)).collect();
                    if self.s.confirm_recovery_words(&key, &idx, &answers)? {
                        drop(key);
                        self.wipe = true;
                        self.info("Recovery key confirmed. It has been removed from the screen and memory.");
                        self.advance()?;
                        return Ok(());
                    }
                    self.err("Words do not match. New words were chosen; Esc shows the key again.");
                    challenge_screen(key)
                } else {
                    Screen::Challenge { key, idx, form }
                }
            }

            Screen::FullKey { mut form } => {
                if form.handle(k) {
                    match self.s.confirm_recovery_full(form.val(0)) {
                        Ok(()) => {
                            self.wipe = true;
                            self.info("Recovery key confirmed.");
                            self.advance()?;
                            return Ok(());
                        }
                        Err(e) => {
                            self.err(e);
                            Screen::FullKey { form }
                        }
                    }
                } else {
                    Screen::FullKey { form }
                }
            }

            Screen::Tls { info } => match k.code {
                KeyCode::Enter => {
                    self.status = None;
                    self.advance()?;
                    return Ok(());
                }
                _ => Screen::Tls { info },
            },

            Screen::Finish => match k.code {
                KeyCode::Enter => {
                    self.busy(term, "Writing setup-done and starting services ...");
                    match self.s.finish() {
                        Ok(()) => {
                            self.status = None;
                            Screen::Done { lines: self.summary()? }
                        }
                        Err(e) if self.s.paths.setup_done.exists() => {
                            let mut lines = self.summary()?;
                            lines.push(String::new());
                            lines.push(format!("WARNING: {e:#}"));
                            Screen::Done { lines }
                        }
                        Err(e) => {
                            self.err(format!("{e:#}"));
                            Screen::Finish
                        }
                    }
                }
                KeyCode::Esc => Screen::Overview { sel: 0 },
                _ => Screen::Finish,
            },

            Screen::Restore {
                mut form,
                sftp,
                pubkey,
                key_file,
            } => {
                let was = form.fields[0].choice;
                if k.code == KeyCode::Esc {
                    let _ = std::fs::remove_file(&key_file);
                    Screen::Overview { sel: 0 }
                } else if form.handle(k) {
                    self.busy(term, "Fetching the configuration backup and restoring it ...");
                    match self.submit_restore(&form, sftp, &key_file) {
                        Ok(lines) => {
                            let _ = std::fs::remove_file(&key_file);
                            self.status = None;
                            Screen::Done { lines }
                        }
                        Err(e) => {
                            self.err(format!("{e:#}"));
                            Screen::Restore {
                                form,
                                sftp,
                                pubkey,
                                key_file,
                            }
                        }
                    }
                } else if form.fields[0].choice != was {
                    // other target type: other fields (the generated key stays)
                    let mut next = restore_form(!sftp);
                    next.fields[0].choice = form.fields[0].choice;
                    Screen::Restore {
                        form: next,
                        sftp: !sftp,
                        pubkey,
                        key_file,
                    }
                } else {
                    Screen::Restore {
                        form,
                        sftp,
                        pubkey,
                        key_file,
                    }
                }
            }

            Screen::Done { lines } => {
                self.outcome = Some(Outcome::Completed);
                Screen::Done { lines }
            }
        };
        Ok(())
    }

    /// New restore screen with a fresh SSH key (private tmp of the wizard, 0600).
    fn restore_screen(&mut self, sftp: bool) -> Result<Screen> {
        if self.s.paths.setup_done.exists() {
            anyhow::bail!("this appliance is already set up");
        }
        let (pem, pubkey) = crate::cfgbackup::ssh_key("nexus-restore");
        let key_file = std::env::temp_dir().join(format!("nexus-restore-{}.key", std::process::id()));
        let _ = std::fs::remove_file(&key_file);
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_file)?
                .write_all(pem.as_bytes())?;
        }
        Ok(Screen::Restore {
            form: restore_form(sftp),
            sftp,
            pubkey,
            key_file,
        })
    }

    /// Fetch + restore; the lines of the Done screen.
    fn submit_restore(&mut self, form: &Form, sftp: bool, key_file: &std::path::Path) -> Result<Vec<String>> {
        let v = |i: usize| form.val(i).trim().to_owned();
        let (remote, rest) = if sftp {
            let port: u16 = v(2).parse().map_err(|_| anyhow::anyhow!("port: a number"))?;
            (
                serde_json::json!({"type": "sftp", "host": v(1), "port": port, "user": v(3), "base_dir": v(4),
                                   "host_key": v(5), "key_file": key_file}),
                6,
            )
        } else {
            let secret = std::env::temp_dir().join(format!("nexus-restore-{}.s3", std::process::id()));
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let _ = std::fs::remove_file(&secret);
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&secret)?
                    .write_all(form.val(6).as_bytes())?;
            }
            (
                serde_json::json!({"type": "s3", "endpoint": v(1), "region": v(2), "bucket": v(3), "prefix": v(4),
                                   "access_key": v(5), "secret_key_file": secret,
                                   "path_style": form.fields[7].choice == 1}),
                8,
            )
        };
        let appliance = Some(v(rest)).filter(|a| !a.is_empty());
        let real = self.s.paths.root == std::path::Path::new("/") && !self.s.dry_run;
        let nft = real.then(|| std::path::Path::new("/usr/sbin/nft"));
        let fetched = crate::cfgbackup::fetch(&serde_json::json!({ "remote": remote }), appliance.as_deref(), nft);
        if !sftp {
            let _ = std::fs::remove_file(std::env::temp_dir().join(format!("nexus-restore-{}.s3", std::process::id())));
        }
        let (id, _, bytes) = fetched?;
        let r = self.s.restore_config(&bytes, form.val(rest + 1))?;
        let mut l = vec![
            format!("The configuration of appliance {id} was restored ({} files).", r.files),
            format!("Bundle made on {} at unix time {}.", r.host, r.created),
            String::new(),
            "The services are started. The recovery key of the lost appliance stays valid;".into(),
            "the administrators and their authenticators are those of the lost appliance.".into(),
            String::new(),
            "Next (manual chapter 14, New appliance from a configuration backup):".into(),
            "  1. sign in to the web UI with your usual account".into(),
            "  2. upload the plugins again, if any were installed".into(),
            "  3. recover each tenant's data from its offsite copy (Tenants -> Attach".into(),
            "     offsite copy, or nexus-offsite ... dr on the console)".into(),
        ];
        l.push(String::new());
        l.extend(self.summary()?.into_iter().skip(1).take(3));
        Ok(l)
    }

    fn submit_network(&mut self, form: Form, nics: Vec<Nic>, term: &mut Term) -> Result<Screen> {
        let nic = match nics.get(form.fields[NET_IF].choice) {
            Some(n) if !nics.is_empty() => n.name.clone(),
            _ => form.val(NET_IF).trim().to_owned(),
        };
        let ipv4 = if form.fields[NET_METHOD].choice == 1 {
            Ok(Ipv4Config::Dhcp)
        } else {
            parse_static(form.val(NET_ADDR), form.val(NET_GW), form.val(NET_DNS))
        };
        let host = form.val(NET_HOST).trim();
        let link = parse_link(
            form.val(NET_BOND),
            BOND_MODES[form.fields[NET_BOND_MODE].choice.min(1)],
            form.val(NET_VLAN),
            form.val(NET_MTU),
        );
        let cfg = ipv4.and_then(|ipv4| {
            Ok(NetConfig {
                nic,
                ipv4,
                hostname: (!host.is_empty()).then(|| host.to_owned()),
                link: link?,
            })
        });
        let cfg = match cfg.and_then(|c| c.validate().map(|_| c)) {
            Ok(c) => c,
            Err(e) => {
                self.err(e);
                return Ok(Screen::Network { form, nics });
            }
        };
        self.busy(term, &format!("Applying network configuration on {} ...", cfg.nic));
        let res = if self.reconfigure_only {
            self.s
                .reconfigure_network(&cfg)
                .map(|_| "Network reconfigured, web UI restarted.".to_owned())
        } else {
            self.s
                .apply_network(&cfg)
                .map(|ips| format!("Network configured, management address(es): {ips:?}"))
        };
        match res {
            Ok(m) => {
                self.info(m);
                self.force_network = false;
                if self.reconfigure_only {
                    let mut lines = vec!["Network reconfigured.".to_owned()];
                    if let Some(t) = self.s.tls_info()? {
                        lines.push("New TLS certificate, fingerprint (SHA-256):".into());
                        lines.push(format!("    {}", &t.fingerprint[..47]));
                        lines.push(format!("    {}", &t.fingerprint[48..]));
                    }
                    return Ok(Screen::Done { lines });
                }
                self.advance()?;
                Ok(std::mem::replace(&mut self.screen, Screen::Overview { sel: 0 }))
            }
            Err(e) => {
                self.err(format!("{e:#}"));
                Ok(Screen::Network { form, nics })
            }
        }
    }

    fn submit_account(&mut self, role: Role, replace: bool, mut form: Form) -> Result<Screen> {
        let name = form.val(0).trim().to_owned();
        let other = match role {
            Role::Admin => self.s.user_with_role(Role::SecurityOfficer)?,
            Role::SecurityOfficer => self.s.user_with_role(Role::Admin)?,
        };
        let check = validate_username(&name).and_then(|_| check_password_pair(form.val(1), form.val(2)));
        let check = check.and_then(|_| match other {
            Some(o) if o == name => Err(anyhow::anyhow!(
                "{name} is already the other role; four-eyes needs two different people"
            )),
            _ => Ok(()),
        });
        if let Err(e) = check {
            self.err(e);
            form.fields[1].value.clear();
            form.fields[2].value.clear();
            form.focus = 1;
            return Ok(Screen::Account { role, replace, form });
        }
        let secret = Zeroizing::new(auth::new_totp_secret());
        let uri = Zeroizing::new(auth::totp_uri(&secret, &name)?);
        let qr = qr_lines(&uri)?;
        self.status = None;
        Ok(Screen::Totp {
            role,
            replace,
            name,
            password: form.fields[1].value.clone(),
            secret,
            qr,
            form: Form::new(vec![Field::text("Current 6-digit code", "")]),
        })
    }

    fn summary(&self) -> Result<Vec<String>> {
        let (host, ips) = self.s.management()?;
        let mut l = vec!["Setup complete. The web UI is reachable at:".to_owned()];
        l.extend(ips.iter().map(|ip| format!("    https://{ip}:{WEB_PORT}/")));
        l.push(format!("    https://{host}:{WEB_PORT}/"));
        if let Some(t) = self.s.tls_info()? {
            l.push(String::new());
            l.push("Certificate fingerprint (SHA-256), compare in the browser:".into());
            l.push(format!("    {}", &t.fingerprint[..47]));
            l.push(format!("    {}", &t.fingerprint[48..]));
        }
        l.push(String::new());
        for r in [Role::Admin, Role::SecurityOfficer] {
            l.push(format!(
                "{:<18} {}",
                format!("{}:", r.label()),
                self.s.user_with_role(r)?.unwrap_or_else(|| "(none yet)".into())
            ));
        }
        if self.s.approvals_start_enabled()? {
            l.push("Approvals:         enabled (two people)".into());
        } else {
            l.push("Approvals:         DISABLED - single administrator. Add a second person".into());
            l.push("                   in the web UI (Users), then enable approvals.".into());
        }
        l.push(format!("Metrics token:     {}", self.s.paths.metrics_token.display()));
        Ok(l)
    }

    // ------------------------------------------------------------ rendering

    fn render(&self, f: &mut Frame) {
        let dry = self.s.dry_run;
        let log_h = if dry && !matches!(self.screen, Screen::Totp { .. }) {
            3
        } else {
            0
        };
        let [head, body, status, log, help] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(log_h),
            Constraint::Length(1),
        ])
        .areas(f.area());

        let mut h = vec![bold(" NexusBackup appliance - first boot setup ")];
        if dry {
            h.push(Span::styled(
                " DRY-RUN ",
                Style::new().fg(Color::Black).bg(Color::Yellow),
            ));
        }
        f.render_widget(
            Paragraph::new(Line::from(h)).style(Style::new().bg(Color::Blue).fg(Color::White)),
            head,
        );

        let mut cursor = None;
        let (title, lines, help_text) = self.body(body, &mut cursor);
        if matches!(self.screen, Screen::Totp { .. }) {
            // no wrapping: a wrapped text line would tear the QR code apart
            f.render_widget(Paragraph::new(lines), body);
        } else {
            let p = Paragraph::new(lines).wrap(Wrap { trim: false });
            f.render_widget(p.block(Block::bordered().title(format!(" {title} "))), body);
        }
        if let Some(c) = cursor {
            f.set_cursor_position(c);
        }

        if let Some(s) = &self.status {
            let (text, style) = match s {
                Status::Info(m) => (m.as_str(), Style::new().fg(Color::Green)),
                Status::Error(m) => (m.as_str(), Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)),
            };
            f.render_widget(
                Paragraph::new(text.to_owned()).style(style).wrap(Wrap { trim: true }),
                status,
            );
        }
        if dry {
            let tail: Vec<Line> = self
                .s
                .log
                .iter()
                .rev()
                .take(3)
                .rev()
                .map(|l| Line::from(format!("$ {l}")))
                .collect();
            f.render_widget(Paragraph::new(tail).style(Style::new().fg(Color::DarkGray)), log);
        }
        f.render_widget(
            Paragraph::new(help_text).style(Style::new().fg(Color::Black).bg(Color::Gray)),
            help,
        );
    }

    /// (title, body lines, help line); sets the text cursor for the focused field.
    fn body(&self, area: Rect, cursor: &mut Option<(u16, u16)>) -> (String, Vec<Line<'static>>, String) {
        let (x, y) = (area.x + 1, area.y + 1);
        let form_help = "Tab/Up/Down: field  Left/Right: choose  Ctrl-U: clear  Enter: next  Esc: back";
        match &self.screen {
            Screen::Overview { sel } => {
                let mut l = vec![
                    Line::from("This wizard prepares the appliance. Progress is saved after every step;"),
                    Line::from("if it is interrupted, run it again and it continues where it stopped."),
                    Line::from(""),
                ];
                for (i, s) in Step::ALL.iter().enumerate() {
                    let done = self.s.is_done(*s).unwrap_or(false);
                    let mark = if done { "[x]" } else { "[ ]" };
                    let style = if i == *sel {
                        Style::new().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::new()
                    };
                    l.push(Line::from(Span::styled(
                        format!("  {mark} {}. {}", i + 1, s.title()),
                        style,
                    )));
                }
                l.push(Line::from(""));
                if self.s.key_state().ok() == Some(KeyState::Unconfirmed) {
                    l.push(warn(
                        "The key service was initialised but its recovery key was never confirmed.",
                    ));
                }
                l.push(Line::from(
                    "Replacing a lost appliance? Set up the network (step 1), then press b to restore",
                ));
                l.push(Line::from("its configuration backup from an offsite target."));
                (
                    "Overview".into(),
                    l,
                    "Enter: continue  Up/Down + r: redo  b: restore a configuration backup  q: quit".into(),
                )
            }

            Screen::Network { form, .. } => {
                let mut l = vec![
                    Line::from("Choose the management NIC. Only this network can reach the web UI (port 8443)."),
                    Line::from("Static: address with prefix (192.0.2.10/24); DNS comma-separated."),
                    Line::from("Optional: more NICs to bond with it (comma-separated), a VLAN ID, an MTU."),
                    Line::from(""),
                ];
                l.extend(form.lines(cursor, y + 3, x));
                if self.reconfigure_only {
                    l.push(Line::from(""));
                    l.push(warn(
                        "Reconfiguring a finished appliance: a new TLS certificate will be created.",
                    ));
                }
                ("Step 1: management network".into(), l, form_help.into())
            }

            Screen::ConfirmReplace { role, existing, form } => {
                let mut l = vec![
                    warn(format!(
                        "A {} account \"{existing}\" already exists.",
                        role.label().to_lowercase()
                    )),
                    Line::from("Replacing it sets a new name, password and TOTP secret; the old ones stop working."),
                    Line::from(format!("To confirm, type the existing name \"{existing}\":")),
                    Line::from(""),
                ];
                l.extend(form.lines(cursor, y + 4, x));
                (
                    "Replace account?".into(),
                    l,
                    "Enter: confirm  Esc: keep the existing account".into(),
                )
            }

            Screen::SecondPerson { form } => {
                let mut l = vec![
                    Line::from("Recommended: a second person (security officer) who approves destructive"),
                    Line::from("or weakening changes: shorter retention, deletions, new admins. That"),
                    Line::from("person sets their own password and authenticator at this console now."),
                    Line::from(""),
                    warn("Without a second person, approvals start DISABLED: such changes"),
                    warn("run at once (audited; retention locks still protect existing backups)."),
                    Line::from("You can add a second person later in the web UI and enable approvals."),
                    Line::from(""),
                ];
                let top = y + l.len() as u16;
                l.extend(form.lines(cursor, top, x));
                (
                    "Step 3: second person (recommended)".into(),
                    l,
                    "Left/Right: choose  Enter: next  Esc: overview".into(),
                )
            }

            Screen::Account { role, form, .. } => {
                let mut l = match role {
                    Role::Admin => vec![
                        Line::from("The administrator configures sources, policies and users."),
                        Line::from("With approvals on, weakening or destructive changes need a second person."),
                    ],
                    Role::SecurityOfficer => vec![
                        warn("Four-eyes principle: this must be a DIFFERENT person than the administrator."),
                        Line::from("The security officer approves requests (shortening retention, deletions,"),
                        Line::from("new admins). That person enters their own password and authenticator."),
                        Line::from("With two people, approvals start enabled."),
                    ],
                };
                l.push(Line::from(""));
                let top = y + l.len() as u16;
                l.extend(form.lines(cursor, top, x));
                let step = if *role == Role::Admin { 2 } else { 3 };
                (
                    format!("Step {step}: {} account", role.label().to_lowercase()),
                    l,
                    form_help.into(),
                )
            }

            Screen::Totp {
                role,
                name,
                secret,
                qr,
                form,
                ..
            } => {
                // drawn without a border (see render) so the QR fits 80x25
                let (x, y) = (area.x, area.y);
                let qr_w = qr.first().map(|s| s.chars().count()).unwrap_or(0) as u16;
                let side_by_side = area.width >= qr_w + 2 + 35;
                let groups: Vec<String> = secret
                    .as_bytes()
                    .chunks(4)
                    .map(|c| String::from_utf8_lossy(c).into_owned())
                    .collect();
                let text = vec![
                    Line::from(bold(format!("{}: {name}", role.label()))),
                    Line::from(""),
                    Line::from("Scan the QR code with an"),
                    Line::from("authenticator app (Aegis,"),
                    Line::from("FreeOTP, ...) or type the"),
                    Line::from("secret manually:"),
                    Line::from(""),
                    Line::from(bold(groups[..groups.len().min(4)].join(" "))),
                    Line::from(bold(groups.get(4..).map(|g| g.join(" ")).unwrap_or_default())),
                    Line::from(""),
                    Line::from(format!("Issuer: NexusBackup, account: {name}")),
                    Line::from("TOTP SHA-1, 6 digits, 30 s"),
                    Line::from(""),
                    Line::from("Then type the code shown now:"),
                    Line::from(""),
                ];
                let mut l: Vec<Line> = vec![];
                if side_by_side {
                    let mut right = text.clone();
                    right.extend(form.lines(cursor, y + text.len() as u16, x + qr_w + 2));
                    for i in 0..qr.len().max(right.len()) {
                        let q = qr.get(i).cloned().unwrap_or_else(|| " ".repeat(qr_w as usize));
                        let mut spans = vec![Span::raw(q), Span::raw("  ")];
                        spans.extend(right.get(i).map(|r| r.spans.clone()).unwrap_or_default());
                        l.push(Line::from(spans));
                    }
                } else {
                    l.extend(qr.iter().map(|q| Line::from(q.clone())));
                    l.extend(text.iter().cloned());
                    let top = y + l.len() as u16;
                    l.extend(form.lines(cursor, top, x));
                }
                (
                    format!("{} {name}: two-factor enrolment", role.label()),
                    l,
                    "Enter: verify code  Esc: back to name/password  Ctrl-C: quit".into(),
                )
            }

            Screen::KeyIntro => (
                "Step 4: key service and recovery key".into(),
                vec![
                    Line::from("The appliance now creates its master key (KEK). All tenant keys are wrapped"),
                    Line::from("under it. A RECOVERY KEY that can unlock the KEK is shown next, ONCE."),
                    Line::from(""),
                    Line::from("You need it to restore after losing this appliance (new hardware +"),
                    Line::from("recovery key + offsite credentials). It is NOT stored on the appliance."),
                    Line::from(""),
                    warn("Have paper and pen ready (or an offline password safe). Do not photograph it."),
                    Line::from("Make sure nobody else can see the screen."),
                    Line::from(""),
                    Line::from("Press Enter to create the key."),
                ],
                "Enter: create key  Esc: back".into(),
            ),

            Screen::ShowKey { key, form } => {
                let w = key.words();
                let mut l = vec![
                    warn("RECOVERY KEY - shown only now. Write down all 24 words, with their numbers:"),
                    Line::from(""),
                ];
                for row in 0..6 {
                    let mut spans = vec![Span::raw("   ")];
                    for col in 0..4 {
                        let i = row * 4 + col;
                        spans.push(Span::styled(format!("{:02} ", i + 1), Style::new().fg(Color::DarkGray)));
                        // BIP39 words have at most 8 letters
                        spans.push(Span::styled(
                            format!("{:<8}", w[i].as_str()),
                            Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
                        ));
                        spans.push(Span::raw(if col < 3 { "    " } else { "" }));
                    }
                    l.push(Line::from(spans));
                }
                l.extend([
                    Line::from(""),
                    Line::from("Words from the BIP39 English list; the first four letters of each are enough."),
                    Line::from("Keep it offline, in a safe. It also yields the boot menu (GRUB) password:"),
                    Line::from("nexus-setup grub-password. Next you re-enter 3 randomly chosen words."),
                    Line::from(""),
                ]);
                let top = y + l.len() as u16;
                l.extend(form.lines(cursor, top, x));
                ("Recovery key".into(), l, "Type YES + Enter when written down".into())
            }

            Screen::Challenge { idx, form, .. } => {
                let mut l = vec![
                    Line::from(format!(
                        "Enter words {}, {} and {} from your written copy (the first four letters are enough).",
                        idx[0] + 1,
                        idx[1] + 1,
                        idx[2] + 1
                    )),
                    Line::from(""),
                ];
                l.extend(form.lines(cursor, y + 2, x));
                (
                    "Confirm the recovery key".into(),
                    l,
                    "Enter: next/verify  Esc: show the key again".into(),
                )
            }

            Screen::FullKey { form } => {
                let mut l = vec![
                    warn("The key service was initialised in an earlier, interrupted run, but its"),
                    warn("recovery key was never confirmed. It cannot be shown again."),
                    Line::from(""),
                    Line::from("If you wrote it down: type all 24 words in order, separated by spaces."),
                    Line::from("If not: stop here and re-install the appliance. Nothing has been encrypted"),
                    Line::from("with this key yet; setup never replaces an existing key by itself."),
                    Line::from(""),
                ];
                l.extend(form.lines(cursor, y + 7, x));
                (
                    "Confirm the existing recovery key".into(),
                    l,
                    "Enter: verify  Ctrl-C: quit".into(),
                )
            }

            Screen::Tls { info } => {
                let fp = &info.fingerprint;
                (
                    "Step 5: TLS certificate".into(),
                    vec![
                        Line::from("A self-signed certificate was created for the web UI."),
                        Line::from(format!("Names/addresses: {}", info.sans.join(", "))),
                        Line::from(""),
                        Line::from("SHA-256 fingerprint - write it down and compare it when your browser"),
                        Line::from("asks you to trust the certificate on first connect:"),
                        Line::from(""),
                        Line::from(vec![Span::raw("   "), bold(fp.get(..47).unwrap_or(fp).to_owned())]),
                        Line::from(vec![Span::raw("   "), bold(fp.get(48..).unwrap_or("").to_owned())]),
                    ],
                    "Enter: continue".into(),
                )
            }

            Screen::Finish => {
                let mut l = vec![Line::from("All steps are complete:"), Line::from("")];
                for s in &Step::ALL[..Step::ALL.len() - 1] {
                    l.push(Line::from(format!("  [x] {}", s.title())));
                }
                l.extend([
                    Line::from(""),
                    Line::from("Enter writes /var/lib/nexus/setup-done and starts nexus-web-api and"),
                    Line::from("nexus-scheduler. This console wizard does not start again afterwards."),
                    Line::from(""),
                ]);
                if self.s.approvals_start_enabled().unwrap_or(false) {
                    l.push(Line::from("Approvals: enabled (administrator + security officer)."));
                } else {
                    l.push(warn("Approvals: DISABLED - single administrator. Changes that weaken"));
                    l.push(warn(
                        "protection run without a second person until you add one + enable them.",
                    ));
                }
                ("Step 7: finish".into(), l, "Enter: finish  Esc: overview".into())
            }

            Screen::Restore { form, sftp, pubkey, .. } => {
                let mut l = if *sftp {
                    vec![
                        Line::from("Add this key to the Storage Box (authorized_keys), then fill in the target:"),
                        Line::from(bold(pubkey.clone())),
                    ]
                } else {
                    vec![Line::from("The S3 bucket of the lost appliance's offsite copy:")]
                };
                l.push(Line::from(
                    "Host key / credentials from your records; the recovery key of the LOST appliance.",
                ));
                l.push(Line::from(""));
                let top = y + l.len() as u16 + if *sftp { 1 } else { 0 };
                l.extend(form.lines(cursor, top, x));
                ("Restore a configuration backup".into(), l, form_help.into())
            }

            Screen::Done { lines } => (
                "Done".into(),
                lines.iter().map(|s| Line::from(s.clone())).collect(),
                "Any key: exit".into(),
            ),
        }
    }
}

/// The target fields of the restore screen; `[0]` chooses the type.
fn restore_form(sftp: bool) -> Form {
    let kind = Field::choice("Offsite target", vec!["Storage Box (SFTP)".into(), "S3".into()]);
    let mut f = if sftp {
        vec![
            kind,
            Field::text("Host", ""),
            Field::text("Port", "23"),
            Field::text("User", ""),
            Field::text("Base directory", ""),
            Field::text("Pinned host key", ""),
        ]
    } else {
        vec![
            kind,
            Field::text("Endpoint (https://)", ""),
            Field::text("Region", ""),
            Field::text("Bucket", ""),
            Field::text("Prefix", ""),
            Field::text("Access key", ""),
            Field::secret("Secret key"),
            Field::choice("Path-style URLs", vec!["no".into(), "yes".into()]),
        ]
    };
    f.push(Field::text("Appliance id (opt.)", ""));
    f.push(Field::secret("Recovery key"));
    if !sftp {
        f[0].choice = 1;
    }
    Form::new(f)
}

fn challenge_screen(key: RecoveryKey) -> Screen {
    let idx = challenge();
    let form = Form::new(
        idx.iter()
            .map(|i| Field::text(format!("Word {:02}", i + 1), ""))
            .collect(),
    );
    Screen::Challenge { key, idx, form }
}

struct StderrGuard(Option<libc::c_int>);

impl StderrGuard {
    fn new() -> StderrGuard {
        // SAFETY: plain fd juggling on fd 2; the saved copy is restored on drop.
        unsafe {
            if libc::isatty(2) != 1 {
                return StderrGuard(None);
            }
            let saved = libc::dup(2);
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if saved < 0 || null < 0 {
                return StderrGuard(None);
            }
            libc::dup2(null, 2);
            libc::close(null);
            StderrGuard(Some(saved))
        }
    }
}

impl Drop for StderrGuard {
    fn drop(&mut self) {
        if let Some(fd) = self.0 {
            // SAFETY: restores the fd saved in new().
            unsafe {
                libc::dup2(fd, 2);
                libc::close(fd);
            }
        }
    }
}

fn restore_terminal() {
    let _ = terminal::disable_raw_mode();
    let mut out = stdout();
    // the alternate screen has no scrollback; Purge clears consoles that keep one anyway
    let _ = execute!(
        out,
        Clear(ClearType::All),
        Clear(ClearType::Purge),
        LeaveAlternateScreen,
        cursor::Show
    );
}

/// Runs the interactive wizard on the controlling terminal.
pub fn run(s: &mut Setup, force_network: bool) -> Result<Outcome> {
    let reconfigure_only = s.paths.setup_done.exists();
    // The audit log also goes to stderr (journal under systemd). On a terminal it
    // would scribble over the screen, so park it on /dev/null while the TUI runs.
    let _quiet = StderrGuard::new();
    terminal::enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |p| {
        restore_terminal();
        hook(p);
    }));
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut app = App {
        s,
        screen: Screen::Overview { sel: 0 },
        status: None,
        force_network: force_network || reconfigure_only,
        reconfigure_only,
        abort_armed: false,
        wipe: false,
        outcome: None,
    };
    if reconfigure_only {
        app.screen = app.network_screen();
    }
    let res = (|| -> Result<Outcome> {
        loop {
            if app.wipe {
                app.wipe = false;
                execute!(stdout(), Clear(ClearType::All), Clear(ClearType::Purge))?;
                term.clear()?;
            }
            term.draw(|f| app.render(f))?;
            if let Some(o) = app.outcome.take() {
                return Ok(o);
            }
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    if let Err(e) = app.on_key(k, &mut term) {
                        app.err(format!("{e:#}"));
                    }
                }
            }
        }
    })();
    restore_terminal();
    res
}
