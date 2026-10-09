//! Volume Shadow Copy via COM (`IVssBackupComponents`, vsbackup.h).
//!
//! The `windows` crate does not project `IVssBackupComponents` (a C++ abstract class in
//! the SDK), so its vtable is declared here with `windows_core::interface`, in the
//! exact slot order of vsbackup.h (checked against mingw-w64's `vsbackup.h`); unused
//! slots are placeholders that are never called.
//!
//! Sequence: CreateVssBackupComponents → InitializeForBackup → SetContext(BACKUP) →
//! DisableWriterClasses(excluded) → SetBackupState(no component selection, COPY) →
//! GatherWriterMetadata → GatherWriterStatus (writer list) → StartSnapshotSet →
//! AddToSnapshotSet per volume → PrepareForBackup → DoSnapshotSet →
//! GatherWriterStatus (which writers froze/thawed fine) → GetSnapshotProperties
//! (shadow device path). Release: BackupComplete (success) or AbortBackup, then
//! dropping the object deletes the non-persistent shadow copies (also if the process
//! dies). COPY backups never truncate SQL Server / Exchange logs, so other backup
//! products' log chains stay intact.

#![allow(non_snake_case)]

use crate::writers;
use agent_proto::VssWriter;
use std::ffi::c_void;
use windows::Win32::Storage::Vss::{IVssAsync, VSS_SNAPSHOT_PROP};
use windows_core::{IUnknown, IUnknown_Vtbl, Interface, BSTR, GUID, HRESULT};

#[windows_core::interface("665c1d5f-c218-414d-a05d-7fef5f9d5c86")]
unsafe trait IVssBackupComponents: IUnknown {
    fn GetWriterComponentsCount(&self, n: *mut u32) -> HRESULT;
    fn GetWriterComponents(&self, i: u32, w: *mut *mut c_void) -> HRESULT;
    fn InitializeForBackup(&self, xml: *const u16) -> HRESULT;
    fn SetBackupState(&self, select_components: bool, bootable_state: bool, backup_type: i32, partial: bool)
        -> HRESULT;
    fn InitializeForRestore(&self, xml: *const u16) -> HRESULT;
    fn SetRestoreState(&self, t: i32) -> HRESULT;
    fn GatherWriterMetadata(&self, a: *mut Option<IVssAsync>) -> HRESULT;
    fn GetWriterMetadataCount(&self, n: *mut u32) -> HRESULT;
    fn GetWriterMetadata(&self, i: u32, id: *mut GUID, m: *mut *mut c_void) -> HRESULT;
    fn FreeWriterMetadata(&self) -> HRESULT;
    fn AddComponent(&self) -> HRESULT;
    fn PrepareForBackup(&self, a: *mut Option<IVssAsync>) -> HRESULT;
    fn AbortBackup(&self) -> HRESULT;
    fn GatherWriterStatus(&self, a: *mut Option<IVssAsync>) -> HRESULT;
    fn GetWriterStatusCount(&self, n: *mut u32) -> HRESULT;
    fn FreeWriterStatus(&self) -> HRESULT;
    fn GetWriterStatus(
        &self,
        i: u32,
        instance: *mut GUID,
        writer: *mut GUID,
        name: *mut BSTR,
        state: *mut i32,
        failure: *mut HRESULT,
    ) -> HRESULT;
    fn SetBackupSucceeded(&self) -> HRESULT;
    fn SetBackupOptions(&self) -> HRESULT;
    fn SetSelectedForRestore(&self) -> HRESULT;
    fn SetRestoreOptions(&self) -> HRESULT;
    fn SetAdditionalRestores(&self) -> HRESULT;
    fn SetPreviousBackupStamp(&self) -> HRESULT;
    fn SaveAsXML(&self, xml: *mut BSTR) -> HRESULT;
    fn BackupComplete(&self, a: *mut Option<IVssAsync>) -> HRESULT;
    fn AddAlternativeLocationMapping(&self) -> HRESULT;
    fn AddRestoreSubcomponent(&self) -> HRESULT;
    fn SetFileRestoreStatus(&self) -> HRESULT;
    fn AddNewTarget(&self) -> HRESULT;
    fn SetRangesFilePath(&self) -> HRESULT;
    fn PreRestore(&self, a: *mut Option<IVssAsync>) -> HRESULT;
    fn PostRestore(&self, a: *mut Option<IVssAsync>) -> HRESULT;
    fn SetContext(&self, ctx: i32) -> HRESULT;
    fn StartSnapshotSet(&self, set: *mut GUID) -> HRESULT;
    fn AddToSnapshotSet(&self, volume: *const u16, provider: GUID, snap: *mut GUID) -> HRESULT;
    fn DoSnapshotSet(&self, a: *mut Option<IVssAsync>) -> HRESULT;
    fn DeleteSnapshots(&self, id: GUID, kind: i32, force: i32, deleted: *mut i32, nondeleted: *mut GUID) -> HRESULT;
    fn ImportSnapshots(&self, a: *mut Option<IVssAsync>) -> HRESULT;
    fn BreakSnapshotSet(&self, set: GUID) -> HRESULT;
    fn GetSnapshotProperties(&self, snap: GUID, prop: *mut VSS_SNAPSHOT_PROP) -> HRESULT;
    fn Query(&self) -> HRESULT;
    fn IsVolumeSupported(&self, provider: GUID, volume: *const u16, supported: *mut i32) -> HRESULT;
    fn DisableWriterClasses(&self, ids: *const GUID, n: u32) -> HRESULT;
    fn EnableWriterClasses(&self, ids: *const GUID, n: u32) -> HRESULT;
    fn DisableWriterInstances(&self, ids: *const GUID, n: u32) -> HRESULT;
    fn ExposeSnapshot(&self) -> HRESULT;
    fn RevertToSnapshot(&self) -> HRESULT;
    fn QueryRevertStatus(&self) -> HRESULT;
}

#[link(name = "vssapi")]
extern "system" {
    fn CreateVssBackupComponentsInternal(pp: *mut *mut c_void) -> HRESULT;
    fn VssFreeSnapshotPropertiesInternal(prop: *mut VSS_SNAPSHOT_PROP);
}

const VSS_CTX_BACKUP: i32 = 0;
const VSS_BT_COPY: i32 = 5;
const VSS_OBJECT_SNAPSHOT_SET: i32 = 2;
const VSS_S_ASYNC_FINISHED: i32 = 0x0004_230A;

fn hr_text(hr: HRESULT) -> String {
    let name = match hr.0 as u32 {
        0x8004_2301 => " VSS_E_BAD_STATE",
        0x8004_2306 => " VSS_E_PROVIDER_VETO",
        0x8004_230C => " VSS_E_VOLUME_NOT_SUPPORTED",
        0x8004_230E => " VSS_E_VOLUME_NOT_SUPPORTED_BY_PROVIDER",
        0x8004_2312 => " VSS_E_MAXIMUM_NUMBER_OF_VOLUMES_REACHED",
        0x8004_2316 => " VSS_E_SNAPSHOT_SET_IN_PROGRESS",
        0x8004_2317 => " VSS_E_MAXIMUM_NUMBER_OF_SNAPSHOTS_REACHED",
        0x8004_231F => " VSS_E_INSUFFICIENT_STORAGE",
        0x8004_23F2 => " VSS_E_WRITERERROR_INCONSISTENTSNAPSHOT",
        0x8004_23F3 => " VSS_E_WRITERERROR_OUTOFRESOURCES",
        0x8004_23F4 => " VSS_E_WRITERERROR_TIMEOUT",
        0x8004_23F5 => " VSS_E_WRITERERROR_RETRYABLE",
        0x8004_23F6 => " VSS_E_WRITERERROR_NONRETRYABLE",
        0x8004_2318 => " VSS_E_WRITER_INFRASTRUCTURE",
        _ => "",
    };
    format!("{:#010x}{name}", hr.0 as u32)
}

fn check(what: &str, hr: HRESULT) -> Result<(), String> {
    if hr.is_ok() {
        Ok(())
    } else {
        Err(format!("VSS {what}: {}", hr_text(hr)))
    }
}

fn wait(what: &str, start: impl FnOnce(*mut Option<IVssAsync>) -> HRESULT) -> Result<(), String> {
    let mut a: Option<IVssAsync> = None;
    check(what, start(&mut a))?;
    let a = a.ok_or_else(|| format!("VSS {what}: no async object"))?;
    // SAFETY: valid COM object.
    unsafe {
        a.Wait(u32::MAX).map_err(|e| format!("VSS {what}: wait: {e}"))?;
        let mut hr = HRESULT(0);
        a.QueryStatus(&mut hr, std::ptr::null_mut())
            .map_err(|e| format!("VSS {what}: status: {e}"))?;
        if hr.0 != VSS_S_ASYNC_FINISHED && hr.is_err() {
            return Err(format!("VSS {what}: {}", hr_text(hr)));
        }
    }
    Ok(())
}

pub fn guid_text(g: &GUID) -> String {
    format!("{{{g:?}}}").to_ascii_lowercase()
}

fn parse_guid(s: &str) -> Option<GUID> {
    let h = s.trim_matches(['{', '}']).replace('-', "");
    let v = u128::from_str_radix(&h, 16).ok()?;
    Some(GUID::from_u128(v))
}

/// One shadow copy set; dropped = shadow copies gone.
pub struct SnapshotSet {
    bc: IVssBackupComponents,
    set: GUID,
    /// (volume GUID path, snapshot id)
    pub members: Vec<(String, GUID)>,
    pub writers: Vec<VssWriter>,
    done: bool,
}

// SAFETY: the object lives in the multithreaded apartment and is only used by the
// session thread that owns the job.
unsafe impl Send for SnapshotSet {}

/// COM for the calling thread (MTA); harmless if already initialised.
pub fn com_init() {
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
    // SAFETY: plain COM initialisation.
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
}

/// Process-wide COM security (once, at service start): writers call back into the
/// requester, which needs at least identify-level impersonation.
pub fn com_security() {
    use windows::Win32::System::Com::{
        CoInitializeSecurity, EOAC_DYNAMIC_CLOAKING, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IDENTIFY,
    };
    com_init();
    // SAFETY: documented parameters for a VSS requester.
    let _ = unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IDENTIFY,
            None,
            EOAC_DYNAMIC_CLOAKING,
            None,
        )
    };
}

impl SnapshotSet {
    /// Steps up to `StartSnapshotSet`; `excluded` = writer class ids to disable.
    pub fn begin(excluded: &[String]) -> Result<SnapshotSet, String> {
        com_init();
        let mut raw: *mut c_void = std::ptr::null_mut();
        // SAFETY: out pointer to an interface pointer.
        check("CreateVssBackupComponents", unsafe {
            CreateVssBackupComponentsInternal(&mut raw)
        })?;
        // SAFETY: the API returned an owned IVssBackupComponents pointer.
        let bc = unsafe { IVssBackupComponents::from_raw(raw) };
        // SAFETY: calls on a valid object, in the documented order.
        unsafe {
            check("InitializeForBackup", bc.InitializeForBackup(std::ptr::null()))?;
            check("SetContext", bc.SetContext(VSS_CTX_BACKUP))?;
            let ids: Vec<GUID> = excluded.iter().filter_map(|s| parse_guid(s)).collect();
            if !ids.is_empty() {
                check(
                    "DisableWriterClasses",
                    bc.DisableWriterClasses(ids.as_ptr(), ids.len() as u32),
                )?;
            }
            check("SetBackupState", bc.SetBackupState(false, false, VSS_BT_COPY, false))?;
            wait("GatherWriterMetadata", |a| bc.GatherWriterMetadata(a))?;
            let mut set = GUID::zeroed();
            check("StartSnapshotSet", bc.StartSnapshotSet(&mut set))?;
            Ok(SnapshotSet {
                bc,
                set,
                members: vec![],
                writers: vec![],
                done: false,
            })
        }
    }

    /// Add a volume (`\\?\Volume{...}\`); an error leaves the volume out of the set.
    pub fn add(&mut self, volume: &str) -> Result<(), String> {
        let w: Vec<u16> = volume.encode_utf16().chain(Some(0)).collect();
        let mut id = GUID::zeroed();
        // SAFETY: valid NUL-terminated volume name; GUID_NULL = default provider.
        check("AddToSnapshotSet", unsafe {
            self.bc.AddToSnapshotSet(w.as_ptr(), GUID::zeroed(), &mut id)
        })?;
        self.members.push((volume.to_string(), id));
        Ok(())
    }

    /// PrepareForBackup + DoSnapshotSet + writer status. `excluded` writers are
    /// reported as not participating.
    pub fn create(&mut self, excluded: &[String]) -> Result<(), String> {
        let bc = &self.bc;
        // SAFETY: valid object, documented order.
        unsafe {
            wait("PrepareForBackup", |a| bc.PrepareForBackup(a))?;
            wait("DoSnapshotSet", |a| bc.DoSnapshotSet(a))?;
        }
        self.done = true;
        self.writers = self.writer_status(excluded)?;
        Ok(())
    }

    fn writer_status(&self, excluded: &[String]) -> Result<Vec<VssWriter>, String> {
        let bc = &self.bc;
        let mut out = vec![];
        // SAFETY: valid object; BSTRs are freed on drop.
        unsafe {
            wait("GatherWriterStatus", |a| bc.GatherWriterStatus(a))?;
            let mut n = 0u32;
            check("GetWriterStatusCount", bc.GetWriterStatusCount(&mut n))?;
            for i in 0..n {
                let (mut inst, mut wid) = (GUID::zeroed(), GUID::zeroed());
                let mut name = BSTR::new();
                let (mut state, mut failure) = (0i32, HRESULT(0));
                if bc
                    .GetWriterStatus(i, &mut inst, &mut wid, &mut name, &mut state, &mut failure)
                    .is_err()
                {
                    continue;
                }
                let class_id = guid_text(&wid);
                let name = name.to_string();
                let failed = failure.is_err() || writers::is_failed_state(state);
                out.push(VssWriter {
                    application: writers::is_application_writer(&class_id, &name),
                    participated: !excluded.contains(&class_id),
                    instance: String::new(),
                    state: writers::state_name(state).into(),
                    failure: if failed { hr_text(failure) } else { String::new() },
                    class_id,
                    name,
                });
            }
            let _ = bc.FreeWriterStatus();
        }
        // excluded writers do not report status: list them explicitly
        for x in excluded {
            if !out.iter().any(|w| &w.class_id == x) {
                out.push(VssWriter {
                    name: "(excluded writer)".into(),
                    class_id: x.clone(),
                    instance: String::new(),
                    participated: false,
                    state: "disabled".into(),
                    failure: String::new(),
                    application: writers::is_application_writer(x, ""),
                });
            }
        }
        Ok(out)
    }

    /// Shadow copy device of a member (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`).
    pub fn device(&self, idx: usize) -> Result<String, String> {
        let (_, id) = self.members.get(idx).ok_or("no such snapshot")?;
        let mut p = VSS_SNAPSHOT_PROP::default();
        // SAFETY: valid object and out struct; freed below.
        unsafe {
            check("GetSnapshotProperties", self.bc.GetSnapshotProperties(*id, &mut p))?;
            let dev = windows_core::PCWSTR(p.m_pwszSnapshotDeviceObject)
                .to_string()
                .unwrap_or_default();
            VssFreeSnapshotPropertiesInternal(&mut p);
            if dev.is_empty() {
                return Err("snapshot without device object".into());
            }
            Ok(dev)
        }
    }

    pub fn set_id(&self) -> String {
        guid_text(&self.set)
    }

    /// Tell the writers how it went, then drop the shadow copies.
    pub fn finish(self, success: bool) -> Vec<String> {
        let mut notes = vec![];
        // SAFETY: valid object.
        unsafe {
            if self.done && success {
                if let Err(e) = wait("BackupComplete", |a| self.bc.BackupComplete(a)) {
                    notes.push(e);
                }
            } else {
                let _ = self.bc.AbortBackup();
            }
            let (mut deleted, mut bad) = (0i32, GUID::zeroed());
            if self.done {
                let _ = self
                    .bc
                    .DeleteSnapshots(self.set, VSS_OBJECT_SNAPSHOT_SET, 1, &mut deleted, &mut bad);
            }
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn guid_roundtrip() {
        let g = super::parse_guid("{a65faa63-5ea8-4ebc-9dbd-a0c4db26912a}").unwrap();
        assert_eq!(super::guid_text(&g), "{a65faa63-5ea8-4ebc-9dbd-a0c4db26912a}");
    }
}
