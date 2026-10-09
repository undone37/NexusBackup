import { get, post } from './api';
import type { Job } from './types';

export const terminal = (s: string) => s === 'ok' || s === 'failed' || s === 'cancelled';

/** Submits a job and polls it until it finishes (or `signal` aborts). */
export async function runJob(
  kind: string,
  tenant: string,
  params: Record<string, unknown>,
  signal: AbortSignal,
  intervalMs = 1000,
): Promise<Job | null> {
  const o = await post<{ id: number }>('/jobs', { kind, tenant, params });
  if (o.quorum) return null;
  for (;;) {
    await new Promise((r) => setTimeout(r, intervalMs));
    if (signal.aborted) return null;
    const j = await get<Job>(`/jobs/${o.data.id}`);
    if (terminal(j.state)) return j;
  }
}

export const downloadUrl = (token: string) => `/api/v1/downloads/${encodeURIComponent(token)}`;
