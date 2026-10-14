import type { Elevation, FreezeBanner, Impersonation, IncidentBanner, RestorePriority, StepUpState, User } from './types';

// The CSRF token lives in memory only (never localStorage); after a reload it is
// recovered from GET /auth/me.
// `vault`: vault mode is on (Phase 17c; from GET /auth/me): restore buttons become requests.
// `impersonating`: "view as tenant" is active (Phase 19b; from GET /auth/me): banner + end button.
// `incident`: incident mode is active (Phase 21b; from GET /auth/me, set at once by Settings → Incident mode).
// `priority`: the restore-priority switch (Phase 22b; GET /restore-priority, set at once by the Dashboard).
// `freeze` / `stepUp`: incident-mode freezes and the account's risk mark (Phase 29; from GET /auth/me).
// `elevation`: this session acts in an eligible role until a time (Phase 30; from GET /auth/me).
export const session = $state<{
  user: User | null;
  csrf: string | null;
  ready: boolean;
  vault: boolean;
  impersonating: Impersonation | null;
  incident: IncidentBanner | null;
  priority: RestorePriority | null;
  freeze: FreezeBanner | null;
  stepUp: StepUpState | null;
  elevation: Elevation | null;
}>({
  user: null,
  csrf: null,
  ready: false,
  vault: false,
  impersonating: null,
  incident: null,
  priority: null,
  freeze: null,
  stepUp: null,
  elevation: null,
});

export function setSession(user: User | null, csrf: string | null) {
  session.user = user;
  session.csrf = csrf;
  // a new session never starts impersonating; callers set it from GET /auth/me
  session.impersonating = null;
  session.elevation = null;
}
