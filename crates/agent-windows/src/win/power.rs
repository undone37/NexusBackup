//! Battery (GetSystemPowerStatus) and metered network (Network List Manager cost)
//! for `PollReply`; the mapping is in [`crate::endpoint`].

use agent_proto::PowerState;
use windows::Win32::Networking::NetworkListManager::{INetworkCostManager, NetworkListManager};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};
use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

pub fn state() -> PowerState {
    let mut st = SYSTEM_POWER_STATUS::default();
    // SAFETY: valid out pointer.
    let (on_battery, battery_percent) = match unsafe { GetSystemPowerStatus(&mut st) } {
        Ok(()) => crate::endpoint::power_from(st.ACLineStatus, st.BatteryFlag, st.BatteryLifePercent),
        Err(_) => (None, None),
    };
    PowerState {
        on_battery,
        battery_percent,
        metered: metered(),
        network_name: None,
    }
}

fn metered() -> Option<bool> {
    super::vss::com_init();
    // SAFETY: COM is initialised on this thread; the interface is released on drop.
    unsafe {
        let m: INetworkCostManager = CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL).ok()?;
        let mut cost = 0u32;
        m.GetCost(&mut cost, std::ptr::null()).ok()?;
        crate::endpoint::metered_from_cost(cost)
    }
}

/// The user sessions (#31, standalone job triggers): (session id, locked) of the active and disconnected
/// sessions that have a user (not the logon screen), from WTS. `None` when WTS does not answer.
pub fn sessions() -> Option<Vec<(String, bool)>> {
    use windows::Win32::System::RemoteDesktop::{
        WTSActive, WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW,
        WTSSessionInfoEx, WTSINFOEXW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSIONSTATE_LOCK, WTS_SESSION_INFOW,
    };
    let mut p: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut n = 0u32;
    // SAFETY: valid out pointers; the list is freed with WTSFreeMemory below.
    unsafe { WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut p, &mut n) }.ok()?;
    // SAFETY: WTS returned `n` entries at `p`.
    let list = unsafe { std::slice::from_raw_parts(p, n as usize) };
    let mut out = Vec::new();
    for s in list {
        if s.SessionId == 0 || (s.State != WTSActive && s.State != WTSDisconnected) {
            continue;
        }
        let mut buf = windows::core::PWSTR::null();
        let mut len = 0u32;
        // SAFETY: valid out pointers; the buffer is freed with WTSFreeMemory.
        let q = unsafe {
            WTSQuerySessionInformationW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                s.SessionId,
                WTSSessionInfoEx,
                &mut buf,
                &mut len,
            )
        };
        if q.is_err() || buf.is_null() || (len as usize) < std::mem::size_of::<WTSINFOEXW>() {
            continue;
        }
        // SAFETY: WTSSessionInfoEx returns a WTSINFOEXW; level 1 is the only member of the union.
        let (level, user0, flags) = unsafe {
            let i = &*(buf.0 as *const WTSINFOEXW);
            (
                i.Level,
                i.Data.WTSInfoExLevel1.UserName[0],
                i.Data.WTSInfoExLevel1.SessionFlags,
            )
        };
        // SAFETY: allocated by WTSQuerySessionInformationW.
        unsafe { WTSFreeMemory(buf.0.cast()) };
        if level == 1 && user0 != 0 {
            out.push((s.SessionId.to_string(), flags as u32 == WTS_SESSIONSTATE_LOCK));
        }
    }
    // SAFETY: allocated by WTSEnumerateSessionsW.
    unsafe { WTSFreeMemory(p.cast()) };
    Some(out)
}
