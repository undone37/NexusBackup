import type { User } from './types';

// The CSRF token lives in memory only (never localStorage); after a reload it is
// recovered from GET /auth/me.
// `vault`: vault mode is on (Phase 17c; from GET /auth/me): restore buttons become requests.
export const session = $state<{ user: User | null; csrf: string | null; ready: boolean; vault: boolean }>({
  user: null,
  csrf: null,
  ready: false,
  vault: false,
});

export function setSession(user: User | null, csrf: string | null) {
  session.user = user;
  session.csrf = csrf;
}
