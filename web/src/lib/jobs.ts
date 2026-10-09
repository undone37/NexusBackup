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

/** Directory entries of a finished `files_list` job (structured `job.result`). */
export function fileEntries(job: Job): FileEntry[] {
  const e = job.result?.entries;
  return Array.isArray(e) ? e : [];
}

export const downloadUrl = (token: string) => `/api/v1/downloads/${encodeURIComponent(token)}`;
