import { get, post } from './api';
import { t } from './i18n';
import { notify } from './notify.svelte';
import type { Agent, AgentStatus, FileEntry, Job, JobKind } from './types';

export const JOB_KINDS: JobKind[] = [
  'backup',
  'restore',
  'restore_ct',
  'instant_recover',
  'instant_disk',
  'files_list',
  'files_get',
  'restore_files',
  'offsite',
  'retention',
  'gc',
  'verify',
  'chunk_repair',
  'agent_enroll',
  'agent_update',
  'agent_renew',
  'plugin_validate',
  'plugin_guests',
  'plugin_backup',
  'plugin_restore',
  'plugin_mount',
  'replica_enroll',
  'replica_sync',
  'inventory',
  'file_search',
  'file_index',
  'file_changes',
  'snapshot_diff',
  'offsite_list',
  'offsite_restore',
  'offsite_attach',
  'fleet_scan',
];

/** Human-readable job kind (falls back to the raw kind for kinds the UI does not know yet). */
export const kindLabel = (k: string) => t.jobs.kinds[k] ?? k;

export const terminal = (s: string) => s === 'ok' || s === 'failed' || s === 'cancelled';

/**
 * Submits a job and polls it until it finishes (or `signal` aborts).
 * Returns the finished job plus the `download_token` that `files_get` answers with.
 */
export async function runJob(
  kind: string,
  tenant: string,
  params: Record<string, unknown>,
  signal: AbortSignal,
  intervalMs = 1000,
): Promise<{ job: Job; token?: string } | null> {
  const o = await post<{ id: number; download_token?: string }>('/jobs', { kind, tenant, params });
  // approval first (vault mode, Phase 17c): the job starts once approved
  if (o.quorum) {
    notify('pending', t.vault.requested(o.quorumId));
    return null;
  }
  for (;;) {
    await new Promise((r) => setTimeout(r, intervalMs));
    if (signal.aborted) return null;
    const job = await get<Job>(`/jobs/${o.data.id}`);
    if (terminal(job.state)) return { job, token: o.data.download_token };
  }
}

/** Directory entries of a finished `files_list` job (structured `job.result`). */
export function fileEntries(job: Job): FileEntry[] {
  const e = job.result?.entries;
  return Array.isArray(e) ? e : [];
}

export const downloadUrl = (token: string) => `/api/v1/downloads/${encodeURIComponent(token)}`;

/** Agent id of a host snapshot source (`host-<agent id>`), else null. */
export const hostAgentId = (source: string) => (source.startsWith('host-') ? source.slice(5) : null);

/** Snapshots whose files can be restored onto a host through an agent (`restore_files`, Phase 15b). */
export const restorableToHost = (source: string) => /^(host|nas|share|plugin|vm|ct)-/.test(source);

export function agentStatus(a: Agent, now = Date.now() / 1000): AgentStatus {
  if (a.enrolled_at !== null) return 'enrolled';
  return a.token_expires !== null && a.token_expires > now ? 'pending' : 'expired';
}

/** Job log lines with their time: `@<unix seconds>` mark lines (written by the scheduler before
 * output whenever the second changed) set the time of the lines after them and are not shown. */
export function logLines(log: string | null | undefined): { time: number | null; text: string }[] {
  const out: { time: number | null; text: string }[] = [];
  let time: number | null = null;
  for (const text of (log ?? '').split('\n')) {
    const m = /^@(\d+)$/.exec(text);
    if (m) time = Number(m[1]);
    else out.push({ time, text });
  }
  if (out.length && out[out.length - 1].text === '') out.pop();
  return out;
}

/** HH:MM:SS of a unix time, local. */
export const clock = (s: number) =>
  new Date(s * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
