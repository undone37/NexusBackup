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
