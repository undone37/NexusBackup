import { get, post } from './api';
import { t } from './i18n';
import type { Agent, AgentStatus, FileEntry, Job, JobKind } from './types';

export const JOB_KINDS: JobKind[] = [
  'backup',
  'restore',
  'restore_ct',
  'instant_recover',
  'files_list',
  'files_get',
  'restore_files',
  'offsite',
  'retention',
  'gc',
  'verify',
  'agent_enroll',
  'agent_update',
  'plugin_validate',
  'plugin_guests',
  'plugin_backup',
  'plugin_restore',
  'plugin_mount',
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
  if (o.quorum) return null;
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

export function agentStatus(a: Agent, now = Date.now() / 1000): AgentStatus {
  if (a.enrolled_at !== null) return 'enrolled';
  return a.token_expires !== null && a.token_expires > now ? 'pending' : 'expired';
}
