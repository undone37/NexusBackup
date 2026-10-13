import type { Impersonation, IncidentBanner, User } from './types';

// The CSRF token lives in memory only (never localStorage); after a reload it is
// recovered from GET /auth/me.
// `vault`: vault mode is on (Phase 17c; from GET /auth/me): restore buttons become requests.
// `impersonating`: "view as tenant" is active (Phase 19b; from GET /auth/me): banner + end button.
// `incident`: incident mode is active (Phase 21b; from GET /auth/me, set at once by Settings → Incident mode).
export const session = $state<{
  user: User | null;
  csrf: string | null;
  ready: boolean;
  vault: boolean;
  impersonating: Impersonation | null;
  incident: IncidentBanner | null;
}>({
  user: null,
  csrf: null,
  ready: false,
  vault: false,
  impersonating: null,
  incident: null,
});

export function setSession(user: User | null, csrf: string | null) {
  session.user = user;
  session.csrf = csrf;
  // a new session never starts impersonating; callers set it from GET /auth/me
  session.impersonating = null;
}
