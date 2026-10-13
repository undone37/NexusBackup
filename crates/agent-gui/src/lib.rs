//! `nexus-agent-gui`: desktop UI of the NexusBackup agent for Windows and Linux desktops
//! (docs/endpoint-ui.md). Tray icon with the protection state and a Control Panel window
//! (status, bar chart of the last sessions, session details, "request backup now").
//! Talks only to the local agent service (crate agent-ui-proto); never to the network.

pub mod app;
pub mod demo;
pub mod icon;
pub mod ipc;
pub mod model;
pub mod palette;
pub mod settings;
pub mod tray;
