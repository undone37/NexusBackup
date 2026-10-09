// Tiny hash router: #/path?query. Hash routing needs no server fallback and keeps
// the index.html cacheable; the web-api's index fallback is harmless either way.

function parse() {
  const raw = location.hash.replace(/^#/, '') || '/';
  const [path, q = ''] = raw.split('?', 2);
  return { path: path || '/', query: new URLSearchParams(q) };
}

export const route = $state(parse());

window.addEventListener('hashchange', () => {
  const r = parse();
  route.path = r.path;
  route.query = r.query;
  // Move focus to the main landmark so keyboard/screen-reader users land on the new page.
  document.getElementById('main')?.focus();
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
