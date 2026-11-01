#!/usr/bin/env node
// Screenshots of the plugin's tab for the README (#44): the real nexusbackup/ui.html served under PegaProx's
// plugin path by a small local server that answers its API (`clusters`, `vms`, `backup`) with demo data, captured
// by headless Chrome over CDP (Node's built-in WebSocket, no npm dependencies). No PegaProx and no lab needed, and
// nothing from a lab ends up in the pictures.
//   node integrations/pegaprox/tools/screenshots.mjs      -> integrations/pegaprox/images/*.png
// env: CHROME (google-chrome), W x H (1440 x 760)
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const ui = readFileSync(join(here, '../nexusbackup/ui.html'), 'utf8');
const out = join(here, '../images');
const CHROME = process.env.CHROME || 'google-chrome';
const W = Number(process.env.W || 1440);
const H = Number(process.env.H || 760);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const API = '/api/plugins/nexusbackup/api';

// demo guests: every state the tab knows, relative to now
const now = Math.floor(Date.now() / 1000);
const H1 = 3600;
const vms = [
  { vmid: 100, name: 'web01', type: 'qemu', state: 'ok', alerts: [],
    last_backup: { time: now - 2 * H1, age_s: 2 * H1, offsite: true, lock_until: now + 30 * 86400 },
    group: { name: 'production', policy: 'gold', next_backup: now + 20 * H1 },
    restore_test: { state: 'passed', finished: now - 26 * H1 } },
  { vmid: 101, name: 'db01', type: 'qemu', state: 'ok', alerts: [],
    last_backup: { time: now - 3 * H1, age_s: 3 * H1, offsite: true, lock_until: null },
    group: { name: 'production', policy: 'gold', next_backup: now + 20 * H1 },
    restore_test: { state: 'passed', finished: now - 50 * H1 } },
  { vmid: 102, name: 'files01', type: 'qemu', state: 'late', alerts: ['backup of group office failed: storage full on the node'],
    last_backup: { time: now - 76 * H1, age_s: 76 * H1, offsite: false, lock_until: null },
    group: { name: 'office', policy: 'silver', next_backup: now + 4 * H1 }, restore_test: null },
  { vmid: 103, name: 'build01', type: 'qemu', state: 'never', alerts: [], last_backup: null,
    group: { name: 'development', policy: 'bronze', next_backup: now + 6 * H1, paused: false }, restore_test: null },
  { vmid: 110, name: 'dns', type: 'lxc', state: 'ok', alerts: [],
    last_backup: { time: now - 5 * H1, age_s: 5 * H1, offsite: false, lock_until: null },
    group: { name: 'infrastructure', policy: 'silver', next_backup: now + 19 * H1 },
    restore_test: { state: 'failed', finished: now - 30 * H1 } },
  { vmid: 120, name: 'test-vm', type: 'qemu', state: 'unprotected', alerts: [], last_backup: null, group: null, restore_test: null },
];
const summary = vms.reduce((s, v) => ({ ...s, [v.state]: (s[v.state] || 0) + 1 }), {});

const server = createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const json = (v, code = 200) => {
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(JSON.stringify(v));
  };
  if (u.pathname === `${API}/ui`) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(ui);
  }
  if (u.pathname === `${API}/clusters`) return json({ allow_backup: true, clusters: [{ id: 'c1', name: 'pve-prod' }] });
  if (u.pathname === `${API}/vms`) return json({ summary, vms });
  if (u.pathname === `${API}/backup`) return json({ job: 4711, group: 'production' });
  json({ error: 'not found' }, 404);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

const free = () =>
  new Promise((r) => {
    const s = createServer().listen(0, () => {
      const p = s.address().port;
      s.close(() => r(p));
    });
  });
const tmp = mkdtempSync(join(tmpdir(), 'pegaprox-shots-'));
const port = await free();
const chrome = spawn(
  CHROME,
  ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${join(tmp, 'profile')}`, '--no-first-run',
    '--hide-scrollbars', '--force-device-scale-factor=1', '--lang=en-US', `--window-size=${W},${H}`, 'about:blank'],
  { stdio: 'ignore', env: { ...process.env, LANG: 'en_US.UTF-8', TZ: 'UTC' } },
);
let page;
for (let i = 0; !page; i++) {
  try {
    page = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((x) => x.type === 'page');
  } catch {
    if (i > 60) throw new Error('Chrome did not start');
    await sleep(250);
  }
}
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let seq = 0;
const waiting = new Map();
ws.addEventListener('message', (m) => {
  const d = JSON.parse(m.data);
  if (d.id && waiting.has(d.id)) {
    waiting.get(d.id)(d);
    waiting.delete(d.id);
  }
});
const cdp = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const id = ++seq;
    waiting.set(id, (d) => (d.error ? reject(new Error(`${method}: ${d.error.message}`)) : resolve(d.result)));
    ws.send(JSON.stringify({ id, method, params }));
  });
const shot = async (name) => {
  const r = await cdp('Page.captureScreenshot', { format: 'png' });
  writeFileSync(join(out, `${name}.png`), Buffer.from(r.data, 'base64'));
  console.log(`${name}.png`);
};
mkdirSync(out, { recursive: true });
await cdp('Page.enable');
await cdp('Page.navigate', { url: `${base}${API}/ui` });
await sleep(1500);
await shot('tab');
// "Back up now" on the first guest: the confirmation banner
await cdp('Runtime.evaluate', { expression: `document.querySelector('button[data-vmid="100"]').click()` });
await sleep(800);
await shot('tab-backup-started');
chrome.kill();
server.close();
rmSync(tmp, { recursive: true, force: true });
process.exit(0);
