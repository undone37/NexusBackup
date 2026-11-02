// Tiny hash router: #/path?query. Hash routing needs no server fallback and keeps
// the index.html cacheable; the web-api's index fallback is harmless either way.

function parse() {
  const raw = location.hash.replace(/^#/, '') || '/';
  const [path, q = ''] = raw.split('?', 2);
  return { path: path || '/', query: new URLSearchParams(q) };
}

export const route = $state(parse());

/**
 * A page with unsaved edits registers a guard: given the address being opened (path and query, so
 * switching a Settings section counts too), it returns a question (leave and lose the edits?) or null.
 * A refused navigation puts the old address back without a page change; closing or reloading the tab
 * asks through the browser's own dialog. Ported from NexusStor.
 */
type LeaveGuard = { ask: (to: string) => string | null; confirm: (q: string) => Promise<boolean> };
let guard: LeaveGuard | null = null;
let shown = location.hash;
export function setLeaveGuard(g: LeaveGuard): () => void {
  guard = g;
  return () => {
    if (guard === g) guard = null;
  };
}
window.addEventListener('beforeunload', (e) => {
  if (guard?.ask('')) e.preventDefault();
});

window.addEventListener('hashchange', async () => {
  const r = parse();
  const to = location.hash.replace(/^#/, '') || '/';
  const q = location.hash === shown ? null : (guard?.ask(to) ?? null);
  if (q) {
    const target = location.hash;
    history.replaceState(history.state, '', shown || '#/');
    if (!(await guard!.confirm(q))) return;
    guard = null;
    location.hash = target;
    return;
  }
  shown = location.hash;
  route.path = r.path;
  route.query = r.query;
  // Move focus to the main landmark so keyboard/screen-reader users land on the new page.
  // (without scrolling: the sticky top bar would cover the page heading) and start at the top.
  document.getElementById('main')?.focus({ preventScroll: true });
  window.scrollTo(0, 0);
});

export function navigate(path: string) {
  location.hash = path;
}

export function href(path: string) {
  return `#${path}`;
}

/** Matches '/jobs/:id' against the current path; returns params or null. */
export function match(pattern: string, path: string): Record<string, string> | null {
  const a = pattern.split('/');
  const b = path.split('/');
  if (a.length !== b.length) return null;
  const out: Record<string, string> = {};
  for (let i = 0; i < a.length; i++) {
    if (a[i].startsWith(':')) out[a[i].slice(1)] = decodeURIComponent(b[i]);
    else if (a[i] !== b[i]) return null;
  }
  return out;
}
