// NFS/SMB share views of the real SPA in headless Chrome (CDP), after lab/nas/e2e.sh against the
// same control plane: dashboard rows per share, source dialogs (write-only SMB password), groups
// without guests, share- snapshots without a restore button, file browser, consistency banner.
//   node lab/nas/ui.mjs <out-dir>   (env: ROOT, PORT as for lab/nas/e2e.sh; `lab/nas/devcp.sh env`)
// TLS: Chrome trusts exactly the appliance certificate (SPKI pin), host nexus-m5 -> 127.0.0.1.
import { spawn, execSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';

const OUT = process.argv[2] ?? "target/nas-ui";
const { ROOT, PORT = '18443' } = process.env;
const env = (f) =>
  Object.fromEntries(
    readFileSync(f, 'utf8')
      .split('\n')
      .filter((l) => l.includes('='))
      .map((l) => l.split(/=(.*)/s).slice(0, 2).map((v) => v.replace(/^'|'$/g, ''))),
  );
const sec = env(`${ROOT}/secrets.env`);
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
  const f = `${ROOT}/run/nas/${user}.lastcode`;
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
    '--remote-debugging-port=9335',
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
const page = (await (await fetch('http://127.0.0.1:9335/json')).json()).find((t) => t.type === 'page');
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
await login('admin', sec.ADMIN_PW, sec.ADMIN_TOTP);
// the row of a table containing `name`, then a button in it
const rowClick = (name, button) =>
  ev(`const r = [...document.querySelectorAll('tbody tr')].find(r => r.innerText.includes(${JSON.stringify(name)}));
      if (!r) throw new Error('no row ' + ${JSON.stringify(name)});
      [...r.querySelectorAll('button')].find(b => b.textContent.trim() === ${JSON.stringify(button)}).click();`);

await check(
  'dashboard: one row per share group (source names)',
  `return ['nfs1', 'smb1', 'many1'].every(n => $text().includes(n))`,
  20000,
);
await shot('01-dashboard');
await go('#/sources');
await check(
  'sources: NFS and SMB shares listed',
  `return $text().includes('NFS share') && $text().includes('SMB share') && $text().includes('/srv/share')`,
  10000,
);
await rowClick('smb1', 'Edit');
await check(
  'SMB source dialog: share/user filled, password write-only (empty, "Stored")',
  `const pw = document.querySelector('#n-pw'); const h = document.querySelector('#n-pw-hint');
   return !!pw && pw.value === '' && !!h && h.innerText.includes('Stored') && document.querySelector('#n-share').value === 'share'
     && document.querySelector('#n-user').value === 'nexusbackup'`,
  10000,
);
await shot('02-smb-source');
await ev(`$click('Cancel')`);
await rowClick('nfs1', 'Edit');
await check(
  'NFS source dialog: export, version, no SMB fields',
  `return document.querySelector('#n-exp')?.value === '/srv/share' && document.querySelector('#n-ver')?.value === '4.2'
     && !document.querySelector('#n-pw') && !document.querySelector('#n-share')`,
  10000,
);
await shot('03-nfs-source');
await ev(`$click('Cancel')`);
await go('#/groups');
await rowClick('g-nfs1', 'Edit');
await check(
  'group dialog of a share source: whole share, no guest input',
  `return $text().includes('Backs up the whole share') && !document.querySelector('#g-guests')`,
  10000,
);
await shot('04-group');
await ev(`$click('Cancel')`);
await go('#/snapshots');
await check(
  'snapshots: share- rows with browse, without restore',
  `const rows = [...document.querySelectorAll('tbody tr')].filter(r => r.innerText.includes('share-'));
   return rows.length >= 3 && rows.every(r => r.innerText.includes('Browse files') && !/\\bRestore\\b/.test(r.innerText))`,
  20000,
);
await shot('05-snapshots');
const snaps = await ev(`return await (await fetch('/api/v1/snapshots?tenant=nas')).json()`);
const srcs = await ev(`return await (await fetch('/api/v1/sources')).json()`);
const nfs = srcs.find((x) => x.name === 'nfs1');
const s = snaps.filter((x) => x.source === `share-${nfs.id}`).sort((a, b) => b.time - a.time)[0];
await go(`#/files?tenant=nas&source=${s.source}&time=${s.time}&path=/docs`);
await check('files: /docs of the latest nfs1 snapshot', `return $text().includes('README.md') && $text().includes('new.txt')`, 180000);
await shot('06-files');
const jobs = await ev(`return await (await fetch('/api/v1/jobs?kind=backup&limit=50')).json()`);
const bad = jobs.find((j) => j.state === 'ok' && j.result?.consistent === false);
await go(`#/jobs/${bad.id}`);
await check('job detail: "not point-in-time consistent" banner', `return $text().includes('Not point-in-time consistent')`, 10000);
await shot('07-job');

console.log(report.join('\n'));
console.log(`--- ${((Date.now() - t0) / 1000).toFixed(0)} s, problems (${problems.length})`);
console.log(problems.join('\n'));
ws.close();
chrome.kill();
process.exit(report.some((l) => l.startsWith('FAIL')) || problems.length ? 1 : 0);
