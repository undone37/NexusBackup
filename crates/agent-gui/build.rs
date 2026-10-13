//! Windows: embeds the app icon (dist/nexus-agent-gui.ico, resource id 1: Explorer, taskbar,
//! Start menu) and the version resource (Task Manager shows its FileDescription) into
//! nexus-agent-gui.exe. Compiled with the mingw-w64 `windres` of the cross build container
//! (crates/agent-gui/build.sh); override with WINDRES. Nothing to do on other targets.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=dist/nexus-agent-gui.ico");
    println!("cargo:rerun-if-env-changed=WINDRES");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ico = dir.join("dist/nexus-agent-gui.ico");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let nums: Vec<u16> = version
        .split(['.', '-', '+'])
        .take(3)
        .map(|n| n.parse().unwrap_or(0))
        .collect();
    let v = format!("{},{},{},0", nums[0], nums[1], nums[2]);
    let rc = format!(
        r#"#include <winver.h>
1 ICON "{ico}"
1 VERSIONINFO
FILEVERSION {v}
PRODUCTVERSION {v}
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "NexusBackup"
      VALUE "FileDescription", "NexusBackup Agent"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "nexus-agent-gui"
      VALUE "OriginalFilename", "nexus-agent-gui.exe"
      VALUE "ProductName", "NexusBackup Agent"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        ico = ico.display().to_string().replace('\\', "/"),
    );
    let rc_path = out.join("nexus-agent-gui.rc");
    std::fs::write(&rc_path, rc).unwrap();
    let obj = out.join("nexus-agent-gui-res.o");
    let windres = std::env::var("WINDRES").unwrap_or_else(|_| {
        match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
            Ok("aarch64") => "aarch64-w64-mingw32-windres",
            _ => "x86_64-w64-mingw32-windres",
        }
        .into()
    });
    let status = Command::new(&windres)
        .args(["-O", "coff", "-i"])
        .arg(&rc_path)
        .arg("-o")
        .arg(&obj)
        .status()
        .unwrap_or_else(|e| panic!("{windres}: {e} (mingw-w64 binutils; set WINDRES)"));
    assert!(status.success(), "{windres} failed: {status}");
    // the object itself, not an archive: nothing references the resource section, an archive
    // member would be dropped by the linker
    println!("cargo:rustc-link-arg-bins={}", obj.display());
}
