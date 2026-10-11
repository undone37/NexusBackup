// UI smoke test against a real appliance (not the mock): signs in as admin and as security officer in
// headless Chrome, opens every page and every Settings tab in light and dark theme, and fails on
// uncaught exceptions, console errors, CSP violations and /api answers >= 400.
//   ROOT=<appliance root> PORT=<api port> node --experimental-websocket lab/e2e/ui-smoke.mjs [out-dir]   (node 20)
// ROOT holds secrets.env (ADMIN_PW/ADMIN_TOTP/SO_PW/SO_TOTP) and etc/nexus/tls/cert.pem (pinned).
import { spawn, execSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { writeFileSync, mkdirSync, readFileSync, existsSync, rmSync } from 'node:fs';

const OUT = process.argv[2] ?? 'target/ui-smoke';
const { ROOT, PORT = '28481' } = process.env;
const sec = Object.fromEntries(
  readFileSync(`${ROOT}/secrets.env`, 'utf8')
    .split('\n')
    .filter((l) => l.includes('='))
    .map((l) => l.split(/=(.*)/s).slice(0, 2).map((v) => v.replace(/^'|'$/g, ''))),
);
const BASE = `https://nexus-m5:${PORT}/`;
rmSync(`${OUT}/profile`, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
const PAGES = ['/', '/snapshots', '/jobs', '/alerts', '/quorum', '/audit', '/tenants', '/sources', '/agents',
  '/replication', '/policies', '/groups', '/users', '/plugins'];
const TABS = ['approvals', 'alerts', 'sso', 'ssh', 'updates'];

const b32 = (s) => {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '')) bits += a.indexOf(c).toString(2).padStart(5, '0');
  return Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
};
const totp = (secret, step) => {
  const m = Buffer.alloc(8);
  m.writeBigUInt64BE(BigInt(step));
  const h = createHmac('sha1', b32(secret)).update(m).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// TOTP codes are single-use per step: share the "last code" file with lab/e2e/api-lib.sh
const freshCode = async (user, secret) => {
  const f = `${ROOT}/run/lastcode-${user}`;
  let step = Math.floor(Date.now() / 30000);
  if (existsSync(f) && readFileSync(f, 'utf8').trim() === totp(secret, step)) {
    await sleep((step + 1) * 30000 - Date.now() + 500);
    step += 1;
  }
  const c = totp(secret, step);
  writeFileSync(f, c + '\n');
  return c;
};

const spki = execSync(
  `openssl x509 -in ${ROOT}/etc/nexus/tls/cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`,
).toString().trim();
const chrome = spawn('google-chrome', ['--headless=new', '--remote-debugging-port=9335', `--user-data-dir=${OUT}/profile`,
  '--no-first-run', '--window-size=1440,900', '--host-resolver-rules=MAP nexus-m5 127.0.0.1',
  `--ignore-certificate-errors-spki-list=${spki}`, 'about:blank'], { stdio: 'ignore' });
// never leave Chrome behind (it would keep the debugging port with another appliance's certificate pin)
process.on('exit', () => chrome.kill());
process.on('uncaughtException', (e) => { console.error(e); process.exit(2); });
process.on('unhandledRejection', (e) => { console.error(e); process.exit(2); });
await sleep(1500);
const page = (await (await fetch('http://127.0.0.1:9335/json')).json()).find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0;
let where = 'start';
const pending = new Map();
const problems = [];
ws.addEventListener('message', (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) return pending.get(d.id)(d), pending.delete(d.id);
  if (d.method === 'Runtime.exceptionThrown') problems.push(`${where}: EXC ${d.params.exceptionDetails.exception?.description ?? d.params.exceptionDetails.text}`);
  if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error')
    problems.push(`${where}: CONSOLE ${d.params.args.map((a) => a.value ?? a.description).join(' ')}`);
  if (d.method === 'Network.responseReceived') {
    const { url, status } = d.params.response;
    // 401 on /auth/me = the SPA's "is there a session?" probe before sign-in
    if (url.includes('/api/') && status >= 400 && !(status === 401 && url.endsWith('/auth/me')))
      problems.push(`${where}: HTTP ${status} ${url.replace(BASE, '/')}`);
  }
});
const cdp = (method, params = {}) => new Promise((r) => {
  const i = ++id;
  pending.set(i, r);
  ws.send(JSON.stringify({ id: i, method, params }));
});
const ev = async (expr) => {
  const r = await cdp('Runtime.evaluate', { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(expr + ' -> ' + JSON.stringify(r.result.exceptionDetails).slice(0, 300));
  return r.result?.result?.value;
};
const until = async (expr, ms = 30000) => {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(300)) if (await ev(expr)) return true;
  return false;
};
for (const d of ['Runtime', 'Page', 'Network']) await cdp(`${d}.enable`);
await cdp('Page.addScriptToEvaluateOnNewDocument', {
  source: `document.addEventListener('securitypolicyviolation', e => console.error('CSP VIOLATION', e.violatedDirective, e.blockedURI));
  window.$fill = (sel, v) => { const el = document.querySelector(sel); Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value').set.call(el, v);
    el.dispatchEvent(new Event('input', {bubbles:true})); };`,
});
const visited = [];
const visit = async (hash, theme, user) => {
  where = `${user}/${theme}${hash}`;
  await ev(`location.hash = ${JSON.stringify(hash)}`);
  // a page is settled when its heading is there and no spinner is left
  const ok = await until(`return !!document.querySelector('main h1') && !document.querySelector('[aria-busy="true"]')`, 20000);
  await sleep(600);
  if (!ok) problems.push(`${where}: page did not render`);
  visited.push(where);
  if (theme === 'dark' && hash === '#/') {
    const r = await cdp('Page.captureScreenshot', { format: 'png' });
    writeFileSync(`${OUT}/${user}-dashboard-dark.png`, Buffer.from(r.result.data, 'base64'));
  }
};
const signIn = async (user, pw, secret) => {
  await cdp('Network.clearBrowserCookies');
  await cdp('Page.navigate', { url: 'about:blank' });
  await cdp('Page.navigate', { url: BASE + '#/login' });
  if (!(await until(`return !!document.querySelector('#l-name')`))) {
    const r = await cdp('Page.captureScreenshot', { format: 'png' });
    writeFileSync(`${OUT}/no-sign-in-form.png`, Buffer.from(r.result.data, 'base64'));
    throw new Error(`no sign-in form at ${await ev('return location.href')}: ${(await ev('return document.body?.innerText ?? ""')).slice(0, 300)}`);
  }
  const code = await freshCode(user, secret);
  await ev(`$fill('#l-name', ${JSON.stringify(user)}); $fill('#l-pw', ${JSON.stringify(pw)}); $fill('#l-totp', '${code}');
            document.querySelector('form').requestSubmit();`);
  if (!(await until(`return !!document.querySelector('.topbar')`))) throw new Error(`sign-in as ${user} failed`);
};

for (const [user, pw, secret] of [['admin', sec.ADMIN_PW, sec.ADMIN_TOTP], ['so', sec.SO_PW, sec.SO_TOTP]]) {
  await signIn(user, pw, secret);
  for (const theme of ['light', 'dark']) {
    await cdp('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }] });
    for (const p of PAGES) await visit('#' + p, theme, user);
    for (const tab of TABS) {
      // tabs the role may not see fall back to the first one: still a valid render
      await visit(`#/settings?tab=${tab}`, theme, user);
    }
  }
}
ws.close();
chrome.kill();
writeFileSync(`${OUT}/report.txt`, [...visited.map((v) => `visited ${v}`), ...problems].join('\n') + '\n');
console.log(`${visited.length} page views, ${problems.length} problems`);
for (const p of problems) console.log('PROBLEM ' + p);
process.exit(problems.length ? 1 : 0);
