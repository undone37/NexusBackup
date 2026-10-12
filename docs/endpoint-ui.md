# Endpoint UIs for the agents (Phase 24 design)

Goal (user request 2026-10-12): end users see the protection status of their own machine, in the style of
Veeam Agent for Linux (ncurses control panel) and Veeam Agent for Windows (tray icon + Control Panel with a session
chart). Decisions: plan.md §2 "Endpoint UIs (Phase 24)" — status + requests picked up by an appliance poll (the agent
never connects out), laptops only on LAN/VPN, one Rust + iced GUI with a tray icon for Windows and Linux desktops, no
self-service restore.

## What we take from Veeam (research 2026-10-12, Veeam Help Center 13.x)

| Veeam | NexusBackup |
|---|---|
| Linux TUI main screen "Latest backup sessions", Enter → session statistics (Duration, Processing rate, Processed / Read / Transferred, warnings), key-help line at the bottom | `nexus-agent tui`: same layout; sessions come from the appliance's session summaries |
| `S` start (incremental / `F` active full), queued runs shown as Pending | `S` = **request** "back up now": queued locally, shown as *Requested*, picked up by the next appliance poll (no active full: every backup is forever-full) |
| `veeamconfig session list / info / log` | `nexus-agent status [--json]`, `nexus-agent sessions`, `nexus-agent session <id>` (scriptable, same data) |
| Windows tray icon states (none configured / waiting / running with progress / warning / error / cancelled / not connected to the service) | Same states; plus **"not reached since …"** for laptops off the network and **"managed by appliance <name>"** |
| Control Panel bar chart: one bar per session, colour = result (green / yellow / red / grey), height = size or duration, hover = status, time, size | Same chart (last 30 sessions), height toggle *transferred* / *duration*, hover details; next scheduled run and last successful backup above it |
| Backup Now in the Control Panel / tray menu | "Request backup now" (same request path as the TUI); can be hidden by the administrator per agent |
| Branding / hiding UI parts (Config.xml: accent colour, header text, hide manual runs, hide tray) | Per-agent UI policy set on the appliance, sent with the session summaries: accent colour, header text, hide "backup now", hide tray |
| Managed mode: most local actions disabled, "managed by server" | Always managed: no local job configuration, no local restore (user decision), no encryption settings (per-tenant keys on the appliance) |
| Notifications: Control Panel notification bar, no completion toast | Optional desktop notification on failure / warning (off by default), notification bar in the window |
| Laptops: skip on battery < 20 %, metered connections blocked, Wi-Fi allow-list, "backup once powered on" | Agent reports battery / metered / network state in its poll answer; the appliance skips or defers a scheduled run accordingly (policy options), retries when the laptop is reachable again |

Not taken: local job wizards, local encryption password, recovery-media builder in the endpoint UI (BMR media comes from
the release page, Phase 19), FLR mount on the endpoint (restores stay admin-only), licensing.

## Architecture

- **Session summaries:** at the end of every backup the appliance sends a `SessionSummary` (job id, start, end,
  result, read / transferred / new bytes, warnings count, first error line, next scheduled run) over the existing mTLS
  session (agent protocol, additive message). The agent keeps the last 100 in a local state file (root-only write,
  world-readable summary for the UI or group `nexus-agent-ui`).
- **Poll:** the scheduler opens a short mTLS session to every enrolled agent every 2 minutes (`Poll`): the agent
  answers with queued requests (backup now), its UI policy version and its power/network state. Reachability is
  recorded (`agents.last_seen`); a missed scheduled run is queued when the agent becomes reachable again.
- **Local IPC:** the agent service exposes a read-mostly local socket (`/run/nexus-agent/ui.sock`, named pipe
  `\\.\pipe\nexus-agent-ui` on Windows): `status`, `sessions`, `session <id>`, `request_backup`. Access: local users
  (Linux: group `nexus-agent-ui`; Windows: interactive users), requests rate-limited; nothing on the socket can change
  configuration, start a restore or read backup data.
- **Linux TUI:** `nexus-agent tui` (ratatui), works over SSH, no mouse needed.
- **GUI (Windows + Linux desktop):** `nexus-agent-gui` (Rust, iced + tray-icon), started per user session
  (Windows: Run key / Startup; Linux: XDG autostart), talks only to the local socket/pipe; packaged with the agent
  (MSI / .deb / .rpm, Phase 20) and as a separate "desktop" package for Linux workstations.
