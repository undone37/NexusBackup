import { get, post } from './api';
import type { FileEntry, Job } from './types';

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

/**
 * Directory entries of a finished `files_list` job. web-api v1 has no structured
 * result column: `nexus-pve … ls` prints a JSON array into the job log, possibly
 * surrounded by progress lines, so the array is cut out of the log.
 */
export function fileEntries(job: Job): FileEntry[] {
  if (job.result?.entries) return job.result.entries;
  const log = job.log ?? '';
  const start = log.search(/^\[/m);
  const end = log.lastIndexOf(']');
  if (start < 0 || end < start) return [];
  try {
    const v = JSON.parse(log.slice(start, end + 1));
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

export const downloadUrl = (token: string) => `/api/v1/downloads/${encodeURIComponent(token)}`;
