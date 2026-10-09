//! NexusBackup Windows agent (`nexus-agent.exe`), see docs/agent-windows.md and
//! docs/agent-protocol.md. Protocol, TLS/enrollment, chunking, cache, restore stream
//! and update verification come from `agent-core`; this crate adds the Windows half.
//!
//! The platform-independent modules (path/name mapping, metadata mapping, USN record
//! parsing and the cache decision, restore confinement, the generic walk, VSS writer
//! reporting, update installation) build and are unit-tested on Linux; the Win32 /
//! COM code in [`win`] only builds for Windows (`x86_64-pc-windows-gnu`, cross-compiled
//! by `build.sh`).

pub mod confine;
pub mod meta;
pub mod paths;
pub mod scan;
pub mod update;
pub mod usn;
pub mod writers;

#[cfg(windows)]
pub mod win;

/// Built-in excludes (volume roots): paging, hibernation and swap files, and the
/// System Volume Information directory (shadow copy storage, indexes).
pub const DEFAULT_EXCLUDES: [&str; 4] = [
    "/?/pagefile.sys",
    "/?/hiberfil.sys",
    "/?/swapfile.sys",
    "/?/System Volume Information",
];

/// Exclude matcher for Windows: user patterns (normalised) + the defaults,
/// case-insensitive.
pub fn excludes(user: &[String]) -> agent_core::glob::Excludes {
    let mut all: Vec<String> = user.iter().map(|p| paths::normalize_exclude(p)).collect();
    all.extend(DEFAULT_EXCLUDES.iter().map(|s| s.to_string()));
    agent_core::glob::Excludes::new_case_insensitive(&all)
}

#[cfg(test)]
mod tests {
    #[test]
    fn default_and_user_excludes() {
        let e = super::excludes(&[r"C:\Users\*\AppData\Local\Temp".into(), "*.bak".into()]);
        assert!(e.matches(b"/C/pagefile.sys"));
        assert!(e.matches(b"/D/System Volume Information"));
        assert!(!e.matches(b"/C/data/pagefile.sys"), "only at volume roots");
        assert!(e.matches(b"/C/Users/bob/AppData/Local/Temp"));
        assert!(e.matches(b"/C/x/DB.BAK"));
        assert!(!e.matches(b"/C/x/db.bak2"));
    }
}
