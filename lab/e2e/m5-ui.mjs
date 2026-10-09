// Drives the real SPA (embedded in nexus-web-api) in headless Chrome over CDP,
// after lab/e2e/m5-api.sh: admin sees protection status + snapshots + audit
// (newest first), the operator browses the CT snapshot and downloads /etc/hostname.
//   node --experimental-websocket lab/e2e/m5-ui.mjs <out-dir>   (node 20; 22+ has WebSocket built in)   (env from `lab/e2e/m5.sh env` + $ROOT/run/api/op.env)
// TLS: Chrome trusts exactly the appliance certificate (SPKI pin), host nexus-m5 -> 127.0.0.1.
import { spawn, execSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';

const OUT = process.argv[2] ?? 'target/m5-ui';
const { ROOT, PORT = '18443' } = process.env;
const env = (f) =>
  Object.fromEntries(
    readFileSync(f, 'utf8')
      .split('\n')
      .filter((l) => l.includes('='))
      .map((l) => l.split(/=(.*)/s).slice(0, 2).map((v) => v.replace(/^'|'$/g, ''))),
  );
const sec = { ...env(`${ROOT}/secrets.env`), ...env(`${ROOT}/run/api/op.env`) };
const BASE = `https://nexus-m5:${PORT}/`;
mkdirSync(OUT, { recursive: true });

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
// codes are single-use per 30 s step and user: wait for a step nobody used yet
const freshCode = async (user, secret) => {
  const f = `${ROOT}/run/api/${user}.lastcode`;
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
)
  .toString()
  .trim();
const chrome = spawn(
  'google-chrome',
  [
    '--headless=new',
    '--remote-debugging-port=9334',
    `--user-data-dir=${OUT}/profile`,
    '--no-first-run',
    '--window-size=1366,900',
    `--host-resolver-rules=MAP nexus-m5 127.0.0.1`,
    `--ignore-certificate-errors-spki-list=${spki}`,
    'about:blank',
  ],
  { stdio: 'ignore' },
);
await sleep(1500);
const page = (await (await fetch('http://127.0.0.1:9334/json')).json()).find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0;
const pending = new Map();
const problems = [];
ws.addEventListener('message', (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) return pending.get(d.id)(d), pending.delete(d.id);
  if (d.method === 'Runtime.exceptionThrown') problems.push('EXC ' + JSON.stringify(d.params.exceptionDetails).slice(0, 400));
  // 401 on /auth/me = "no session yet" probe of the SPA before login
  if (d.method === 'Log.entryAdded' && d.params.entry.level !== 'verbose' && !/status of 401.*\/auth\/me$/.test(`${d.params.entry.text} ${d.params.entry.url}`))
    problems.push(`LOG[${d.params.entry.source}/${d.params.entry.level}] ${d.params.entry.text} ${d.params.entry.url ?? ''}`);
  if (d.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(d.params.type))
    problems.push('CONSOLE ' + d.params.args.map((a) => a.value ?? a.description).join(' '));
});
const cdp = (method, params = {}) =>
  new Promise((r) => {
    const i = ++id;
    pending.set(i, r);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
const ev = async (expr) => {
  const r = await cdp('Runtime.evaluate', { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(expr + ' -> ' + JSON.stringify(r.result.exceptionDetails).slice(0, 300));
  return r.result?.result?.value;
};
const shot = async (name) => {
  const r = await cdp('Page.captureScreenshot', { format: 'png' });
  writeFileSync(`${OUT}/${name}.png`, Buffer.from(r.result.data, 'base64'));
};
const until = async (expr, ms = 120000) => {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(500)) if (await ev(expr)) return true;
  return false;
};
await cdp('Runtime.enable');
await cdp('Log.enable');
await cdp('Page.enable');
await cdp('Page.addScriptToEvaluateOnNewDocument', {
  source: `document.addEventListener('securitypolicyviolation', e => console.error('CSP VIOLATION', e.violatedDirective, e.blockedURI));
  window.$fill = (sel, v) => { const el = document.querySelector(sel); Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value').set.call(el, v);
    el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); };
  window.$click = (text) => { const b = [...document.querySelectorAll('button, a')].find(e => e.textContent.trim().startsWith(text) && e.offsetParent !== null);
    if (!b) throw new Error('no button ' + text); b.click(); };
  window.$text = () => document.body.innerText;`,
});
const report = [];
const check = async (label, expr, ms) => report.push(`${(await until(expr, ms)) ? 'PASS' : 'FAIL'} ${label}`);
const go = async (hash) => {
  await ev(`location.hash = ${JSON.stringify(hash)}`);
  await sleep(1000);
};
const login = async (user, pw, secret) => {
  const code = await freshCode(user, secret);
  await ev(`$fill('#l-name', ${JSON.stringify(user)}); $fill('#l-pw', ${JSON.stringify(pw)}); $fill('#l-totp', '${code}');
            document.querySelector('form').requestSubmit();`);
};

const t0 = Date.now();
await cdp('Page.navigate', { url: BASE });
await sleep(1500);
await shot('01-login');
await login('admin', sec.ADMIN_PW, sec.ADMIN_TOTP);
await check('admin: dashboard', `return $text().includes('Protection status')`);
await check('admin: dashboard lists both guests', `return $text().includes('vm-100') && $text().includes('ct-200')`, 10000);
await shot('02-dashboard');
await go('#/snapshots');
await check('admin: snapshots of vm-100 and ct-200', `return $text().includes('vm-100') && $text().includes('ct-200')`, 10000);
await shot('03-snapshots');
await go('#/audit');
await check(
  'admin: audit newest first',
  `const s = [...document.querySelectorAll('tbody tr td:first-child')].map(td => Number(td.textContent));
   return s.length > 5 && s.every((v, i) => i === 0 || s[i - 1] > v)`,
  10000,
);
await ev(`$click('Verify chain')`);
await check('admin: audit chain intact', `return $text().includes('Chain intact')`, 10000);
await shot('04-audit');
await ev(`$click('Sign out')`);
await sleep(1000);

await login('op', sec.OP_PW, sec.OP_TOTP);
await check('operator: logged in', `return $text().includes('Protection status')`);
const snaps = await ev(`return await (await fetch('/api/v1/snapshots?tenant=lab&source=ct-200')).json()`);
const time = snaps.find((s) => s.local).time;
await go(`#/files?tenant=lab&source=ct-200&time=${time}&path=/`);
await check('operator: CT root listed', `return $text().includes('etc/')`, 180000);
await shot('05-files-root');
await ev(`$click('etc/')`);
await check('operator: /etc listed', `return !!document.querySelector('input[aria-label$=" hostname"]')`, 180000);
await ev(`document.querySelector('input[aria-label$=" hostname"]').click()`);
await sleep(300);
await ev(`$click('Prepare download')`);
await check('operator: download ready', `return !!document.querySelector('a[href^="/api/v1/downloads/"]')`, 180000);
await shot('06-files-download');
const content = await ev(`const a = document.querySelector('a[href^="/api/v1/downloads/"]'); const r = await fetch(a.href);
  if (!r.ok) return 'HTTP ' + r.status;
  const b = new Uint8Array(await r.arrayBuffer()), td = new TextDecoder(), str = (o, n) => td.decode(b.slice(o, o + n)).replace(/\\0.*$/s, '');
  for (let o = 0; o + 512 <= b.length && b[o]; ) { // ustar: 512-byte header, data padded to 512
    const name = str(o, 100), size = parseInt(str(o + 124, 12).trim() || '0', 8);
    if (name.endsWith('hostname')) return td.decode(b.slice(o + 512, o + 512 + size));
    o += 512 + Math.ceil(size / 512) * 512;
  }
  return 'hostname not in archive'`);
report.push(`${/ct200/.test(content) ? 'PASS' : 'FAIL'} operator: downloaded etc/hostname = ${JSON.stringify(content.trim())}`);

console.log(report.join('\n'));
console.log(`--- ${((Date.now() - t0) / 1000).toFixed(0)} s, problems (${problems.length})`);
console.log(problems.join('\n'));
ws.close();
chrome.kill();
process.exit(report.some((l) => l.startsWith('FAIL')) || problems.length ? 1 : 0);
