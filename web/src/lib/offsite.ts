// Offsite in the UI (Phase 17d): fetching an offsite-only snapshot back into the local store.
import { act, post } from './api';
import { askConfirm } from './confirm.svelte';
import { fmtTime } from './format';
import { t } from './i18n';
import type { OffsiteListed } from './types';

/** Default local keep of a fetched snapshot (scheduler `offsite_fetch_keep_secs`). */
export const FETCH_KEEP_DAYS = 7;

/** Confirms, then starts an `offsite_restore` job; its id, or null. */
export async function fetchFromOffsite(tenant: string, source: string, time: number, target = 1): Promise<number | null> {
  if (!(await askConfirm(t.offsite.fetchConfirm(source, fmtTime(time), FETCH_KEEP_DAYS)))) return null;
  // Phase 30: target 2 = from the second offsite target
  const params = target === 2 ? { source, time, target } : { source, time };
  const r = await act(post<{ id: number }>('/jobs', { kind: 'offsite_restore', tenant, params }), (d) =>
    t.offsite.fetchStarted(d.id),
  );
  return r && !r.quorum ? (r.data.id ?? null) : null;
}

/** Status of one listed snapshot: chip class and text. */
export function listedStatus(x: OffsiteListed): [string, string] {
  if (!x.remote) return ['bad', t.offsite.sMissing];
  if (!x.inventory) return ['warn', t.offsite.sUnknown];
  return x.local ? ['ok', t.offsite.sLocal] : ['info', t.offsite.sOffsiteOnly];
}
