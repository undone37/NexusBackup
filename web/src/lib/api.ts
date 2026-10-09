import { session, setSession } from './session.svelte';
import { notify } from './notify.svelte';
import { t } from './i18n';

export const API = '/api/v1';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Result of a mutating call: either done, or parked as a four-eyes quorum request (HTTP 202 {quorum_id}). */
export type Outcome<T> = { quorum: false; data: T } | { quorum: true; quorumId: number };

async function request(method: string, path: string, body?: unknown): Promise<{ status: number; data: unknown }> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && session.csrf) headers['X-CSRF-Token'] = session.csrf;
  let r: Response;
  try {
    r = await fetch(API + path, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, t.err.network);
  }
  const text = await r.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!r.ok) {
    const msg =
      data && typeof data === 'object' && 'error' in data ? String((data as { error: unknown }).error) : r.statusText;
    // Session expired or revoked: drop local state; App shows the login screen.
    if (r.status === 401 && !path.startsWith('/auth/')) {
      setSession(null, null);
      notify('info', t.err.sessionExpired);
    }
    throw new ApiError(r.status, msg || `HTTP ${r.status}`);
  }
  return { status: r.status, data };
}

export async function get<T>(path: string): Promise<T> {
  return (await request('GET', path)).data as T;
}

async function mutate<T>(method: string, path: string, body?: unknown): Promise<Outcome<T>> {
  const { status, data } = await request(method, path, body);
  if (status === 202 && data && typeof data === 'object' && 'quorum_id' in data) {
    return { quorum: true, quorumId: Number((data as { quorum_id: unknown }).quorum_id) };
  }
  return { quorum: false, data: data as T };
}

export const post = <T>(path: string, body: unknown = {}) => mutate<T>('POST', path, body);
export const put = <T>(path: string, body: unknown) => mutate<T>('PUT', path, body);
export const del = <T>(path: string) => mutate<T>('DELETE', path);

/**
 * Runs a mutation and reports the outcome to the user. Returns `null` on error,
 * otherwise `{data}` — with `data: null` when the request is waiting for quorum.
 */
export async function act<T>(
  p: Promise<Outcome<T>>,
  okText: string | ((data: T) => string),
): Promise<{ data: T | null } | null> {
  try {
    const o = await p;
    if (o.quorum) {
      notify('pending', t.quorumPending(o.quorumId));
      return { data: null };
    }
    notify('ok', typeof okText === 'function' ? okText(o.data) : okText);
    return { data: o.data };
  } catch (e) {
    notify('error', errText(e));
    return null;
  }
}

export function errText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 403) return `${t.err.forbidden}: ${e.message}`;
    if (e.status === 429) return `${t.err.rateLimited}: ${e.message}`;
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}

/** Query-string helper that drops empty values. */
export function qs(params: Record<string, string | number | undefined | null>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : '';
}
