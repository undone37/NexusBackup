// Reboot and shutdown (issue #179, the design of NexusStor #86): the appliance's power state for the top bar,
// its banner and the dialog, and the wait for the appliance to come back after a reboot.
import { get } from './api';
import type { PowerAction, SystemPower } from './types';

export const power = $state<{
  status: SystemPower | null;
  /** the action ran: the appliance is going down (a reboot comes back, a shutdown does not) */
  down: { action: PowerAction; since: number } | null;
}>({ status: null, down: null });

export async function refreshPower() {
  try {
    power.status = await get<SystemPower>('/system/power');
  } catch {
    // unreachable while it reboots; the role check of GET /system/power decides who sees it
  }
}

/** After a reboot starts: wait until /health fails (it went down) and answers again, then reload the page. A
 * shutdown only shows that it is off. */
export function watchDown(action: PowerAction) {
  if (power.down) return;
  power.down = { action, since: Date.now() };
  if (action === 'poweroff') return;
  let away = false;
  const iv = setInterval(async () => {
    let up = false;
    try {
      up = (await fetch('/health', { cache: 'no-store' })).ok;
    } catch {
      up = false;
    }
    if (!up) away = true;
    // it never seemed to go away (e.g. cancelled on the console): give up after 10 minutes
    else if (away || Date.now() - (power.down?.since ?? 0) > 600_000) {
      clearInterval(iv);
      location.reload();
    }
  }, 3000);
}
