import type { User } from './types';

// The CSRF token lives in memory only (never localStorage); after a reload it is
// recovered from GET /auth/me.
export const session = $state<{ user: User | null; csrf: string | null; ready: boolean }>({
  user: null,
  csrf: null,
  ready: false,
});

export function setSession(user: User | null, csrf: string | null) {
  session.user = user;
  session.csrf = csrf;
}
