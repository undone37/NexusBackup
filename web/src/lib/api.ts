import { session, setSession } from './session.svelte';
import { notify } from './notify.svelte';
import { t } from './i18n';
import { askStepUp } from './stepup.svelte';

export const API = '/api/v1';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Result of a mutating call: either done, or parked as a four-eyes quorum request
 * (HTTP 202 {quorum_id, ...}). Some quorum answers carry extra fields (e.g. `totp_uri`
 * when creating a privileged user), so the body is kept in both cases.
 */
export type Outcome<T> = { quorum: false; data: T } | { quorum: true; quorumId: number; data: Partial<T> };

/** A request body sent as-is (e.g. a plugin bundle) with its own Content-Type and extra headers. */
export interface RawBody {
  raw: Blob | ArrayBuffer;
  headers: Record<string, string>;
}
const isRaw = (b: unknown): b is RawBody => !!b && typeof b === 'object' && 'raw' in b && 'headers' in b;

async function request(
  method: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal,
  retried = false,
): Promise<{ status: number; data: unknown }> {
  const raw = isRaw(body) ? body : null;
  const headers: Record<string, string> = { Accept: 'application/json', ...(raw?.headers ?? {}) };
  if (body !== undefined && !raw) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && session.csrf) headers['X-CSRF-Token'] = session.csrf;
  let r: Response;
  try {
    r = await fetch(API + path, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      body: raw ? raw.raw : body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch (e) {
    // a cancelled request (AbortController) is not a network error
    if (signal?.aborted) throw e;
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
    // Phase 29: the account is marked by a risk signal: re-authenticate (POST /auth/step-up in the
    // dialog), then send the request once more.
    if (r.status === 428 && !retried && path !== '/auth/step-up' && (await askStepUp(msg))) {
      return request(method, path, body, signal, true);
    }
    throw new ApiError(r.status, msg || `HTTP ${r.status}`);
  }
  return { status: r.status, data };
}

/** GET; `signal` cancels the request (the promise then rejects with the abort reason). */
export async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return (await request('GET', path, undefined, signal)).data as T;
}

async function mutate<T>(method: string, path: string, body?: unknown): Promise<Outcome<T>> {
  const { status, data } = await request(method, path, body);
  if (status === 202 && data && typeof data === 'object' && 'quorum_id' in data) {
    return { quorum: true, quorumId: Number((data as { quorum_id: unknown }).quorum_id), data: data as Partial<T> };
  }
  return { quorum: false, data: data as T };
}

export const post = <T>(path: string, body: unknown = {}) => mutate<T>('POST', path, body);
export const put = <T>(path: string, body: unknown) => mutate<T>('PUT', path, body);
export const del = <T>(path: string) => mutate<T>('DELETE', path);
/** POST of a raw body (`Content-Type` and extra headers in `headers`); CSRF header as usual. */
export const postRaw = <T>(path: string, raw: Blob | ArrayBuffer, headers: Record<string, string>) =>
  mutate<T>('POST', path, { raw, headers } satisfies RawBody);

/**
 * Runs a mutation and reports the outcome to the user ("pending approval" for 202
 * {quorum_id}). Returns `null` on error, otherwise the outcome.
 */
export async function act<T>(
  p: Promise<Outcome<T>>,
  okText: string | ((data: T) => string),
): Promise<Outcome<T> | null> {
  try {
    const o = await p;
    if (o.quorum) {
      // Phase 29: a production restore of a flagged snapshot waits for approval `restore.infected`
      const inf = (o.data as { infected?: boolean } | null)?.infected;
      notify('pending', inf ? t.p29.infected.pending(o.quorumId) : t.quorumPending(o.quorumId));
      return o;
    }
    const ok = typeof okText === 'function' ? okText(o.data) : okText;
    // Approvals disabled: a gated action answers 200 {approvals: "disabled", executed, quorum_id?}.
    const d = o.data as { approvals?: string; executed?: boolean; quorum_id?: number } | null;
    if (d && typeof d === 'object' && d.approvals === 'disabled') {
      const inf = (d as { infected?: boolean }).infected;
      notify(
        'ok',
        inf && d.quorum_id
          ? t.p29.infected.approvalsOff(d.quorum_id)
          : d.executed === false && d.quorum_id
            ? t.approvalsOffScheduled(d.quorum_id)
            : t.approvalsOff(ok),
      );
      return o;
    }
    notify('ok', ok);
    return o;
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
