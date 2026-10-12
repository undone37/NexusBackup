#!/usr/bin/env node
// Regenerates the manual's screenshots (manual/images/*.png) from the real web UI running
// against the seeded demo backend (web/mock/api.ts) — no appliance needed.
//
//   node manual/tools/screenshots.mjs                 all screenshots
//   node manual/tools/screenshots.mjs dashboard jobs  only the scenes with these names
//   KEEP=1 node manual/tools/screenshots.mjs          keep the browser profile + vite log (prints paths)
//   SKIP_BUILD=1 node manual/tools/screenshots.mjs    use the existing web/dist
//
// Requirements: `npm ci --ignore-scripts` in web/, Node 20.19+ and Google Chrome (CHROME=/path to override).
// It builds the UI (`vite build`, i.e. the bundle the appliance embeds), serves it with `vite preview` (the
// production CSP + the mock API) on a free port (never 5173), drives headless Chrome over the DevTools
// protocol with Node's built-in WebSocket (no npm dependencies), signs in as each role and writes PNGs at a
// fixed 1440×900 viewport (light theme, device scale factor 1, UTC, en-US; a few tall dialogs get a taller
// viewport). Chrome sees the app as https://backup.example.com/ (requests are answered through the DevTools
// Fetch domain), so links in the pictures show no local port. The mock clock and its random ids are fixed
// (NEXUS_MOCK_EPOCH / NEXUS_MOCK_SEED) and the browser clock follows the mock clock, so a re-run produces the
// same pictures except for seconds-level timing.
import { spawn, spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:net';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Node 20 has WebSocket only behind a flag: re-run with it.
if (typeof WebSocket === 'undefined') {
  const r = spawn(process.execPath, ['--experimental-websocket', '--no-warnings', ...process.argv.slice(1)], { stdio: 'inherit' });
  r.on('exit', (code) => process.exit(code ?? 1));
} else {
  await main();
}

async function main() {
  const HERE = dirname(fileURLToPath(import.meta.url));
  const REPO = resolve(HERE, '../..');
  const WEB = join(REPO, 'web');
  const OUT = join(REPO, 'manual/images');
  const CHROME = process.env.CHROME ?? '/usr/bin/google-chrome';
  // Demo clock: Wednesday 2026-10-14 09:30 UTC; fixed PRNG seed for ids, tokens, fingerprints.
  const EPOCH = 1791970200;
  const SEED = '20261014';
  const W = 1440;
  const H = 900;
  const only = new Set(process.argv.slice(2));
  const keep = !!process.env.KEEP;

  if (!existsSync(join(WEB, 'node_modules/vite/bin/vite.js'))) throw new Error('run `npm ci --ignore-scripts` in web/ first');
  if (!existsSync(CHROME)) throw new Error(`Chrome not found at ${CHROME} (set CHROME=)`);
  mkdirSync(OUT, { recursive: true });

  const freePort = () =>
    new Promise((res, rej) => {
      const s = createServer();
      s.once('error', rej);
      s.listen(0, '127.0.0.1', () => {
        const { port } = s.address();
        s.close(() => res(port));
      });
    });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---------------------------------------------------------------- vite + mock
  let port;
  do port = await freePort();
  while (port === 5173);
  const tmp = mkdtempSync(join(tmpdir(), 'nexus-manual-'));
  const VITE = join(WEB, 'node_modules/vite/bin/vite.js');
  if (!process.env.SKIP_BUILD) {
    console.log('building web/dist');
    const b = spawn(process.execPath, [VITE, 'build', '--logLevel', 'warn'], { cwd: WEB, stdio: 'inherit' });
    if ((await new Promise((r) => b.on('exit', r))) !== 0) throw new Error('vite build failed');
  }
  const t0 = Date.now();
  const vite = spawn(process.execPath, [VITE, 'preview', '--port', String(port), '--strictPort', '--host', '127.0.0.1'], {
    cwd: WEB,
    env: { ...process.env, NEXUS_MOCK_EPOCH: String(EPOCH), NEXUS_MOCK_SEED: SEED, NEXUS_API: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let viteLog = '';
  vite.stdout.on('data', (d) => (viteLog += d));
  vite.stderr.on('data', (d) => (viteLog += d));
  const LOCAL = `http://127.0.0.1:${port}`;
  const ORIGIN = 'https://backup.example.com';
  const BASE = `${ORIGIN}/`;
  for (let i = 0; ; i++) {
    try {
      if ((await fetch(LOCAL + '/api/v1/health')).ok) break;
    } catch {
      /* not up yet */
    }
    if (i > 120) throw new Error('vite did not start:\n' + viteLog);
    await sleep(250);
  }
  // browser clock = mock clock (the mock started its clock at about t0)
  const OFFSET = EPOCH * 1000 - t0;

  // ---------------------------------------------------------------- Chrome over CDP
  const cdpPort = await freePort();
  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      `--remote-debugging-port=${cdpPort}`,
      `--user-data-dir=${join(tmp, 'profile')}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--hide-scrollbars',
      '--force-device-scale-factor=1',
      '--force-color-profile=srgb',
      '--lang=en-US',
      '--disable-features=Translate,MediaRouter',
      // never resolve the demo host name for real (all its requests are answered by the Fetch handler)
      '--host-resolver-rules=MAP backup.example.com 127.0.0.1',
      `--window-size=${W},${H}`,
      'about:blank',
    ],
    { stdio: 'ignore' },
  );
  const cleanup = async () => {
    const gone = new Promise((r) => (chrome.exitCode !== null ? r() : chrome.once('exit', r)));
    chrome.kill();
    vite.kill();
    await Promise.race([gone, sleep(5000)]);
    if (keep) {
      writeFileSync(join(tmp, 'vite.log'), viteLog);
      console.log(`kept ${tmp}`);
    } else rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  };
  process.on('exit', () => {
    chrome.kill();
    vite.kill();
  });
  let page;
  for (let i = 0; !page; i++) {
    try {
      page = (await (await fetch(`http://127.0.0.1:${cdpPort}/json`)).json()).find((x) => x.type === 'page');
    } catch {
      if (i > 60) throw new Error('Chrome did not start');
      await sleep(250);
    }
  }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  let seq = 0;
  const waiting = new Map();
  const problems = [];
  // Requests to ORIGIN are answered from the local preview server; the session cookie is kept here.
  const jar = new Map();
  const proxy = async ({ requestId, request }) => {
    try {
      const u = new URL(request.url);
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([k]) => !/^(cookie|host|origin|referer)$/i.test(k)));
      if (jar.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
      const r = await fetch(LOCAL + u.pathname + u.search, { method: request.method, headers, body: request.postData, redirect: 'manual' });
      for (const c of r.headers.getSetCookie()) {
        const [kv, ...attrs] = c.split(';');
        const [k, v] = kv.split(/=(.*)/s);
        if (!v || attrs.some((a) => /max-age=0/i.test(a.trim()))) jar.delete(k.trim());
        else jar.set(k.trim(), v);
      }
      const responseHeaders = [...r.headers]
        .filter(([k]) => !/^(set-cookie|content-encoding|content-length|transfer-encoding|connection)$/i.test(k))
        .map(([name, value]) => ({ name, value }));
      const body = Buffer.from(await r.arrayBuffer()).toString('base64');
      ws.send(JSON.stringify({ id: ++seq, method: 'Fetch.fulfillRequest', params: { requestId, responseCode: r.status, responseHeaders, body } }));
    } catch (e) {
      problems.push(`proxy ${request.url}: ${e.message}`);
      ws.send(JSON.stringify({ id: ++seq, method: 'Fetch.failRequest', params: { requestId, errorReason: 'Failed' } }));
    }
  };
  ws.addEventListener('message', (m) => {
    const d = JSON.parse(m.data);
    if (d.id && waiting.has(d.id)) {
      waiting.get(d.id)(d);
      waiting.delete(d.id);
      return;
    }
    if (d.method === 'Fetch.requestPaused') return void proxy(d.params);
    if (d.method === 'Runtime.exceptionThrown') problems.push('exception: ' + (d.params.exceptionDetails.exception?.description ?? d.params.exceptionDetails.text));
    if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error')
      problems.push('console.error: ' + d.params.args.map((a) => a.value ?? a.description).join(' '));
  });
  const cdp = (method, params = {}) =>
    new Promise((r, rej) => {
      const i = ++seq;
      waiting.set(i, (d) => (d.error ? rej(new Error(`${method}: ${d.error.message}`)) : r(d.result)));
      ws.send(JSON.stringify({ id: i, method, params }));
    });
  const ev = async (body) => {
    const r = await cdp('Runtime.evaluate', { expression: `(async () => { ${body} })()`, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`${body.slice(0, 200)}\n -> ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    return r.result?.value;
  };
  const until = async (body, what, ms = 20000) => {
    for (const end = Date.now() + ms; Date.now() < end; await sleep(200)) if (await ev(body).catch(() => false)) return;
    throw new Error(`timeout waiting for ${what}`);
  };

  await cdp('Runtime.enable');
  await cdp('Page.enable');
  await cdp('Network.enable');
  await cdp('Fetch.enable', { patterns: [{ urlPattern: `${ORIGIN}/*`, requestStage: 'Request' }] });
  await cdp('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
  await cdp('Emulation.setEmulatedMedia', {
    features: [
      { name: 'prefers-color-scheme', value: 'light' },
      { name: 'prefers-reduced-motion', value: 'reduce' },
    ],
  });
  await cdp('Emulation.setTimezoneOverride', { timezoneId: 'UTC' });
  await cdp('Emulation.setLocaleOverride', { locale: 'en-US' });
  await cdp('Page.addScriptToEvaluateOnNewDocument', {
    source: `(() => {
      const RealDate = Date, off = ${OFFSET};
      class FixedDate extends RealDate {
        constructor(...a) { if (a.length) super(...a); else super(RealDate.now() + off); }
        static now() { return RealDate.now() + off; }
      }
      globalThis.Date = FixedDate;
      const vis = (e) => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
      const scope = () => [...document.querySelectorAll('dialog[open]')].pop() ?? document;
      window.$scope = scope;
      window.$fill = (sel, v) => {
        const el = scope().querySelector(sel) ?? document.querySelector(sel);
        if (!el) throw new Error('no field ' + sel);
        const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      };
      window.$check = (sel, on = true) => {
        const el = scope().querySelector(sel);
        if (!el) throw new Error('no checkbox ' + sel);
        if (el.checked !== on) el.click();
      };
      window.$button = (text, root) => {
        const r = root ?? scope();
        return [...r.querySelectorAll('button, a.button, a')].find((e) => vis(e) && !e.disabled && e.textContent.trim().replace(/\\s+/g, ' ').startsWith(text));
      };
      window.$click = (text, root) => {
        const b = window.$button(text, root);
        if (!b) throw new Error('no button ' + text);
        b.click();
      };
      window.$row = (text) => [...document.querySelectorAll('tbody tr')].find((tr) => vis(tr) && tr.textContent.includes(text));
      window.$rowClick = (rowText, text) => {
        const tr = window.$row(rowText);
        if (!tr) throw new Error('no row ' + rowText);
        window.$click(text, tr);
      };
      window.$idle = () => !document.querySelector('[aria-busy="true"]');
    })();`,
  });

  // ---------------------------------------------------------------- helpers
  const api = (method, path, body) =>
    ev(`if (!window.__csrf && '${method}' !== 'GET' && '${path}' !== '/auth/login') window.__csrf = (await (await fetch('/api/v1/auth/me')).json()).csrf;
        const r = await fetch('/api/v1${path}', { method: '${method}', headers: { 'content-type': 'application/json', 'x-csrf-token': window.__csrf ?? '' }, body: ${body ? JSON.stringify(JSON.stringify(body)) : 'undefined'} });
        const j = await r.json().catch(() => null); if (j?.csrf) window.__csrf = j.csrf; return { status: r.status, body: j };`);
  const settle = async (ms = 500) => {
    await until('return $idle()', 'page to load');
    await sleep(ms);
  };
  const dismissNotices = () => ev(`document.querySelectorAll('.notices .notice button.icon').forEach((b) => b.click()); return true;`);
  const go = async (hash, ms) => {
    await ev(`location.hash = ${JSON.stringify(hash)}; return true;`);
    await sleep(150);
    await settle(ms);
    await ev(`window.scrollTo(0, 0); return true;`);
  };
  /** Sign in through the API (any 6-digit code works in the mock), then reload so the SPA picks the session up. */
  const login = async (name) => {
    jar.clear();
    await cdp('Page.navigate', { url: BASE });
    await sleep(400);
    await ev(`window.__csrf = undefined; return true;`);
    const r = await api('POST', '/auth/login', { name, password: 'nexus', totp: totp('JBSWY3DPEHPK3PXP', Math.floor((Date.now() + OFFSET) / 30000)) });
    if (r.status !== 200) throw new Error(`login ${name}: ${JSON.stringify(r)}`);
    await cdp('Page.reload');
    await sleep(400);
    await until(`return !!document.querySelector('.topbar')`, `${name} signed in`);
    await settle();
  };
  const closeDialogs = async () => {
    await ev(`document.querySelectorAll('dialog[open]').forEach((d) => d.close()); return true;`);
    await sleep(200);
  };
  /** Captures the viewport. `height` enlarges the viewport for this shot only (tall dialogs). */
  const written = [];
  const shot = async (name, { height, notices = false, scrolled = false } = {}) => {
    if (!notices) await dismissNotices();
    if (height) await cdp('Emulation.setDeviceMetricsOverride', { width: W, height, deviceScaleFactor: 1, mobile: false });
    await ev(`document.activeElement?.blur?.(); ${scrolled ? '' : 'window.scrollTo(0, 0);'} return true;`);
    await sleep(height ? 500 : 250);
    const r = await cdp('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(OUT, `${name}.png`), Buffer.from(r.data, 'base64'));
    written.push(name);
    if (height) await cdp('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
    console.log(`  ${name}.png`);
  };
  // RFC 6238 TOTP (the real appliance needs it; the mock accepts any 6-digit code)
  function totp(secret, step) {
    const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const c of secret.replace(/=+$/, '')) bits += a.indexOf(c).toString(2).padStart(5, '0');
    const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
    const m = Buffer.alloc(8);
    m.writeBigUInt64BE(BigInt(step));
    const h = createHmac('sha1', key).update(m).digest();
    const o = h[h.length - 1] & 15;
    return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
  }
  const confirmOk = async () => {
    await until(`return !!$button('Confirm')`, 'confirmation dialog');
    await ev(`$click('Confirm'); return true;`);
    await sleep(500);
  };

  // ---------------------------------------------------------------- scenes
  // Each scene is a name (= image file, or a group of them) and a function; order matters because
  // later scenes change the demo state (new requests, approvals switched off, an account activated).
  const data = {};
  const scenes = [
    ['login', async () => {
      jar.clear();
      await cdp('Page.navigate', { url: BASE });
      await until(`return !!document.querySelector('#l-name')`, 'sign-in form');
      await ev(`$fill('#l-name', 'admin'); $fill('#l-pw', 'correct-horse-battery'); $fill('#l-totp', '492039'); return true;`);
      await shot('login');
    }],
    ['dashboard', async () => {
      await login('admin');
      const snaps = (await api('GET', '/snapshots')).body;
      const sources = (await api('GET', '/sources')).body;
      const agents = (await api('GET', '/agents')).body;
      const web01 = agents.find((a) => a.name === 'web01');
      const pg = sources.find((s) => s.name === 'pg-shop');
      const newest = (src) => snaps.filter((s) => s.source === src).sort((a, b) => b.time - a.time)[0];
      Object.assign(data, {
        vm100: newest('vm-100'),
        vm300: newest('vm-300'),
        host: newest(`host-${web01.id}`),
        pgCluster: newest(`plugin-postgresql-${pg.id}`),
        pgShop: newest(`plugin-postgresql-${pg.id}-shop`),
        pgId: pg.id,
        share: newest(`share-${sources.find((s) => s.kind === 'nfs').id}`),
        web01,
      });
      await go('/', 900);
      await shot('dashboard', { height: 1660 });
    }],
    ['dashboard-dark', async () => {
      await cdp('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }, { name: 'prefers-reduced-motion', value: 'reduce' }] });
      await go('/', 900);
      await shot('dashboard-dark', { height: 1660 });
      await cdp('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }, { name: 'prefers-reduced-motion', value: 'reduce' }] });
      await sleep(300);
    }],
    // Phase 13c: the "Not in a group" drill-down (guests from the inventory no group protects)
    ['dashboard-unprotected', async () => {
      await go('/', 900);
      await until(`return !!document.querySelector('.open-list details')`, 'not-in-a-group list');
      await ev(`const d = document.querySelector('.open-list details'); d.open = true; window.scrollTo(0, d.getBoundingClientRect().top + window.scrollY - 80); return true;`);
      await shot('dashboard-unprotected', { scrolled: true });
    }],
    ['jobs', async () => {
      await go('/jobs');
      await shot('jobs');
      const jobs = (await api('GET', '/jobs')).body;
      const failed = jobs.find((j) => j.kind === 'backup' && j.state === 'failed' && j.params.group_id && !j.retry_of);
      const smb = jobs.filter((j) => j.kind === 'backup' && j.tenant === 'acme' && j.state === 'ok').find((j) => j.params.group_id);
      const running = jobs.find((j) => j.state === 'running') ?? jobs.find((j) => j.state === 'queued');
      await go(`/jobs/${running.id}`, 2500);
      await shot('job-running');
      await go(`/jobs/${failed.id}`);
      await shot('job-failed');
      const all = await Promise.all(jobs.filter((j) => j.kind === 'backup' && j.state === 'ok').map(async (j) => (await api('GET', `/jobs/${j.id}`)).body));
      const torn = all.find((j) => j.result?.snapshots?.some((x) => x.consistent === false)) ?? smb;
      await go(`/jobs/${torn.id}`);
      await shot('job-inconsistent');
    }],
    ['alerts', async () => {
      await go('/alerts');
      await ev(`$row('store capacity').querySelector('details').open = true; return true;`);
      await shot('alerts');
      await ev(`$click('All'); return true;`);
      await settle();
      await shot('alerts-all');
      await ev(`$click('Open'); return true;`);
      await settle();
      await ev(`$rowClick('store capacity', 'Resolve'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #al-note')`, 'resolve dialog');
      await ev(`$fill('#al-note', 'Old daily snapshots of initech pruned, GC ran: 61 % used.'); return true;`);
      await shot('alert-resolve');
      await closeDialogs();
    }],
    ['audit', async () => {
      await go('/audit');
      await ev(`$click('Verify chain'); return true;`);
      await until(`return document.body.innerText.includes('Chain intact')`, 'audit verification');
      await shot('audit');
    }],
    ['forwarding', async () => {
      await go('/settings?tab=forwarding');
      await until(`return !!document.querySelector('#fw-host')`, 'forwarding settings');
      await shot('settings-forwarding', { height: 1300 });
    }],
    ['snapshots', async () => {
      await go('/snapshots?tenant=initech');
      await shot('snapshots');
      await go(`/snapshots?source=vm-100`);
      await ev(`$rowClick('vm-100', 'Restore'); return true;`);
      await until(`return !!$button('Full restore')`, 'restore menu');
      await shot('snapshot-restore-menu');
      await ev(`$click('Full restore'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #r-target')`, 'restore dialog');
      await ev(`$fill('#r-target', '9100'); $fill('#r-storage', 'local-lvm'); $fill('#r-pool', 'dr-test'); $check('#r-start'); $check('#r-linkdown'); return true;`);
      await shot('snapshot-restore-vm', { height: 1300 });
      // Phase 15a: replace the original (approval restore.replace)
      await ev(`$check('#r-linkdown', false); $fill('#r-pool', ''); $check('#r-replace'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #r-keeplinks')`, 'replace options');
      await shot('snapshot-restore-replace', { height: 1400 });
      await closeDialogs();
      await ev(`$rowClick('vm-100', 'Restore'); return true;`);
      await until(`return !!$button('Instant recover')`, 'restore menu');
      await ev(`$click('Instant recover'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #r-target')`, 'instant recover dialog');
      await ev(`$fill('#r-target', '9101'); $fill('#r-storage', 'local-lvm'); $fill('#r-prefix', 'ir-'); return true;`);
      await shot('snapshot-instant-recover', { height: 1200 });
      await closeDialogs();
      // Phase 15a: several guests of one group in one dialog
      await go('/snapshots?tenant=acme');
      await ev(`$click('Restore several'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #m-group option:nth-child(2)')`, 'restore several dialog');
      await ev(`const o = document.querySelector('dialog[open] #m-group option:nth-child(2)'); $fill('#m-group', o.value); $fill('#m-base', '9200'); $fill('#m-storage', 'local-lvm'); return true;`);
      await shot('snapshots-restore-many', { height: 1300 });
      await closeDialogs();
      await go('/snapshots?tenant=globex');
      await shot('snapshots-replicated');
      // an unlocked snapshot of a guest in no group (Phase 13a): Delete asks first
      await go('/snapshots?source=vm-103');
      await ev(`$rowClick('vm-103', 'Delete'); return true;`);
      await until(`return !!$button('Confirm')`, 'confirmation dialog');
      await shot('snapshot-delete');
      await closeDialogs();
    }],
    ['files', async () => {
      const s = data.vm100;
      await go(`/files?tenant=${s.tenant}&source=${s.source}&time=${s.time}&path=/`);
      await until(`return !!$button('etc/')`, 'file listing', 30000);
      await ev(`$click('etc/'); return true;`);
      await until(`return !!document.querySelector('input[aria-label="Select hostname"]')`, '/etc listing', 30000);
      await ev(`document.querySelector('input[aria-label="Select hostname"]').click(); document.querySelector('input[aria-label="Select nginx"]').click(); $fill('#fmt', 'zip'); return true;`);
      await ev(`$click('Prepare download'); return true;`);
      await until(`return !!$button('Download ')`, 'download ready', 30000);
      await settle();
      await shot('files-download');
    }],
    ['restore-to-path', async () => {
      const s = data.host;
      await go(`/files?tenant=${s.tenant}&source=${s.source}&time=${s.time}&path=/`);
      await until(`return !!$button('var/')`, 'host listing', 30000);
      await ev(`$click('var/'); return true;`);
      await until(`return !!$button('www/')`, '/var listing', 30000);
      await ev(`document.querySelector('input[aria-label="Select www"]').click(); return true;`);
      await ev(`$click('Restore to path'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[placeholder="/srv/restore"]')`, 'restore-to-path dialog');
      await ev(`$fill('input[placeholder="/srv/restore"]', '/srv/restore'); $fill('dialog[open] select', 'if_older'); return true;`);
      await ev(`const i = [...$scope().querySelectorAll('input.mono')].pop(); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(i, 'web01'); i.dispatchEvent(new Event('input', { bubbles: true })); return true;`);
      await shot('restore-to-path', { height: 1000 });
      await closeDialogs();
    }],
    // Phase 15b: a NAS share snapshot and VM files onto a host with an agent
    ['restore-to-host', async () => {
      const confirmAgent = `const sel = $scope().querySelector('select[id$="-agent"]'); const name = sel.selectedOptions[0].textContent.split(' (')[0].trim();
        const i = [...$scope().querySelectorAll('input.mono')].pop(); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(i, name); i.dispatchEvent(new Event('input', { bubbles: true })); return true;`;
      await go(`/snapshots?source=${data.share.source}`);
      await ev(`$rowClick('${data.share.source}', 'Restore'); return true;`);
      await until(`return !!$button('Restore to a host')`, 'restore menu');
      await ev(`$click('Restore to a host'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[placeholder="/srv/restore"]')`, 'restore-to-host dialog');
      await ev(`$fill('input[placeholder="/srv/restore"]', '/srv/restore/projects'); return true;`);
      await ev(confirmAgent);
      await shot('restore-to-host', { height: 1100 });
      await closeDialogs();
      const s = data.vm300; // acme: the tenant with enrolled agents
      await go(`/files?tenant=${s.tenant}&source=${s.source}&time=${s.time}&path=/`);
      await until(`return !!$button('etc/')`, 'file listing', 30000);
      await ev(`$click('etc/'); return true;`);
      await until(`return !!document.querySelector('input[aria-label="Select hostname"]')`, '/etc listing', 30000);
      await ev(`document.querySelector('input[aria-label="Select nginx"]').click(); return true;`);
      await ev(`$click('Restore to a host'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[placeholder="/srv/restore"]')`, 'VM files dialog');
      await ev(`$fill('input[placeholder="/srv/restore"]', '/srv/restore/vm-300'); return true;`);
      await ev(confirmAgent);
      await shot('restore-vm-files-to-host', { height: 1100 });
      await closeDialogs();
    }],
    ['plugin-restores', async () => {
      await go(`/snapshots?source=plugin-postgresql-${data.pgId}`);
      await ev(`$rowClick('plugin-postgresql-${data.pgId}', 'Restore'); return true;`);
      await until(`return !!$button('Point-in-time restore')`, 'restore menu');
      await ev(`$click('Point-in-time restore'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input')`, 'PITR dialog');
      await ev(`const ins = $scope().querySelectorAll('input'); const set = (i, v) => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(i, v); i.dispatchEvent(new Event('input', { bubbles: true })); };
        set(ins[0], '/var/lib/postgresql/18/restore-1013'); set(ins[1], '2026-10-13 21:40:00+00'); return true;`);
      await shot('snapshot-pg-pitr');
      await closeDialogs();
      await go(`/snapshots?source=plugin-postgresql-${data.pgId}-shop`);
      await ev(`$rowClick('plugin-postgresql-${data.pgId}-shop', 'Restore'); return true;`);
      await until(`return !!$button('Restore database dump')`, 'restore menu');
      await ev(`$click('Restore database dump'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input')`, 'dump restore dialog');
      await ev(`const i = $scope().querySelector('input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(i, 'shop_restored'); i.dispatchEvent(new Event('input', { bubbles: true })); return true;`);
      await shot('snapshot-pg-to-target');
      await closeDialogs();
    }],
    ['storage', async () => {
      await go('/storage');
      await until(`return !!document.querySelector('#s-group-table')`, 'storage page');
      await shot('storage', { height: 1500 });
      await go('/settings?tab=anomaly');
      await until(`return !!document.querySelector('#an-f')`, 'anomaly settings');
      await shot('settings-anomaly');
    }],
    ['reports', async () => {
      await go('/reports');
      await until(`return !!document.querySelector('#r-sched') && document.body.innerText.includes('weekly-ops')`, 'reports page');
      await ev(`document.querySelector('input[name="report-type"][value="failed"]').click(); return true;`);
      await settle();
      await shot('reports', { height: 1300 });
      await ev(`$rowClick('weekly-ops', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #rs-to')`, 'scheduled report dialog');
      await shot('report-schedule', { height: 1150 });
      await closeDialogs();
    }],
    ['tenants', async () => {
      await go('/tenants');
      await shot('tenants');
      await ev(`$rowClick('acme', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #t-ep')`, 'tenant dialog');
      await shot('tenant-s3', { height: 1250 });
      await closeDialogs();
      await ev(`$rowClick('initech', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #t-host')`, 'tenant dialog');
      await shot('tenant-sftp');
      await closeDialogs();
    }],
    ['sources', async () => {
      await go('/sources');
      await ev(`$rowClick('pg-shop', 'Validate connection'); return true;`);
      await until(`return document.body.innerText.includes('Connection OK')`, 'validation', 30000);
      await shot('sources');
      const edit = async (name, file, height) => {
        await ev(`$rowClick(${JSON.stringify(name)}, 'Edit'); return true;`);
        await until(`return !!document.querySelector('dialog[open] form')`, `${name} dialog`);
        await sleep(300);
        await shot(file, { height });
        await closeDialogs();
      };
      await edit('pve-cluster', 'source-pve', 1150);
      await edit('web01-files', 'source-agent', 1000);
      await edit('nas01', 'source-truenas', 1700);
      await edit('filer-projects', 'source-nfs', 1150);
      await edit('fs01-data', 'source-smb', 1250);
      await edit('pg-shop', 'source-postgresql', 2000);
      // Phase 13c: guest inventory of the PVE cluster
      await ev(`$rowClick('pve-cluster', 'Inventory'); return true;`);
      await until(`return document.querySelector('dialog[open]')?.innerText.includes('build-runner')`, 'inventory');
      await shot('source-inventory');
      await closeDialogs();
    }],
    ['agents', async () => {
      await go('/agents');
      await shot('agents');
      await ev(`$rowClick('db01', 'New token'); return true;`);
      await confirmOk();
      await until(`return document.body.innerText.includes('One-time token')`, 'token dialog');
      await shot('agent-token');
      await closeDialogs();
    }],
    ['replication', async () => {
      await go('/replication');
      await shot('replication');
      await ev(`$click('New peer'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #p-name')`, 'peer dialog');
      await ev(`$fill('#p-name', 'branch-office'); $check('dialog[open] input[value="initech"]'); return true;`);
      await ev(`$click('Create'); return true;`);
      await until(`return document.body.innerText.includes('Enrollment code for branch-office')`, 'enrollment code');
      await shot('replication-peer-code', { notices: true });
      await closeDialogs();
      await ev(`$click('New replication source'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #s-url')`, 'source dialog');
      await ev(`$fill('#s-name', 'branch-primary'); $fill('#s-url', 'backup-branch.example.net:8443'); $fill('#s-code', '5e6f708192a3b4c5.ABCDEFGHIJKLMNOPQRSTUVWXYZ');
        $fill('#s-fp', '9c4f1e2d7a0b3c5d6e8f9a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5'); $fill('#s-tenants', 'umbrella'); $fill('#s-sched', 'daily 05:00'); return true;`);
      await shot('replication-source-new', { height: 1150 });
      await closeDialogs();
    }],
    ['policies', async () => {
      await go('/policies');
      await shot('policies');
      await ev(`$rowClick('gold', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #p-sched')`, 'policy dialog');
      await ev(`$fill('#p-daily', '7'); return true;`);
      await shot('policy-edit', { height: 1500 });
      await closeDialogs();
      // run control (Phase 13b): weekday schedule, retries, a blackout window with abort
      await ev(`$rowClick('bronze', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #bw-from-0')`, 'policy dialog with blackout window');
      await shot('policy-runcontrol', { height: 1600 });
      await closeDialogs();
    }],
    ['groups', async () => {
      await go('/groups');
      await shot('groups');
      await ev(`$rowClick('acme-databases', 'Edit'); return true;`);
      await until(`return !!$button('Load Databases')`, 'group dialog');
      await ev(`$click('Load Databases'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[value="analytics"]')`, 'database list', 30000);
      await shot('group-postgresql');
      await closeDialogs();
      await ev(`$rowClick('acme-nas01', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[value="tank/home"]')`, 'TrueNAS group dialog');
      await shot('group-truenas');
      await closeDialogs();
      await ev(`$rowClick('production', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #g-guests')`, 'PVE group dialog');
      await shot('group-pve');
      await closeDialogs();
      // Phase 13c: auto-protect by PVE pool with one exclusion
      await ev(`$rowClick('development', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[value="105"]')`, 'auto-protect group dialog');
      await shot('group-auto', { height: 1250 });
      await closeDialogs();
      // run control (Phase 13b): back up now (inside a blackout window), pause
      await ev(`$rowClick('development', 'Back up now'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[value="failed"]')`, 'back up now dialog');
      await shot('group-backup-now');
      await closeDialogs();
      await ev(`$rowClick('production', 'Back up now'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[value="some"]')`, 'back up now dialog');
      await ev(`$check('dialog[open] input[value="some"]'); return true;`);
      await until(`return !!document.querySelector('dialog[open] input[type="checkbox"][value="101"]')`, 'guest list');
      await ev(`$check('dialog[open] input[type="checkbox"][value="101"]'); return true;`);
      await shot('group-backup-guests');
      await closeDialogs();
      await ev(`$rowClick('acme-vms', 'Pause'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #pause-for')`, 'pause dialog');
      await ev(`$fill('#pause-for', '14'); return true;`);
      await shot('group-pause');
      await closeDialogs();
    }],
    ['users', async () => {
      await go('/users');
      await shot('users');
      await ev(`$click('New user'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #u-name')`, 'user dialog');
      await ev(`$fill('#u-name', 'jdoe'); $fill('#u-role', 'operator'); return true;`);
      await shot('user-new');
      await ev(`$click('Create'); return true;`);
      await until(`return document.body.innerText.includes('Activation code for jdoe')`, 'activation code');
      await shot('user-activation-code');
      await closeDialogs();
      await ev(`$click('New user'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #u-name')`, 'user dialog');
      await ev(`$fill('#u-name', 'mmeyer'); $fill('#u-role', 'security_officer'); return true;`);
      await ev(`$click('Create'); return true;`);
      await until(`return document.body.innerText.includes('FIRST HALF')`, 'first half of the activation code');
      await shot('user-activation-part1', { notices: true });
      await closeDialogs();
    }],
    ['plugins', async () => {
      await go('/plugins');
      await shot('plugins');
      await ev(`[...document.querySelectorAll('section.card')].find((s) => s.textContent.includes('PostgreSQL'))?.querySelectorAll('tbody tr').forEach((tr) => { if (tr.textContent.includes('1.0.0')) $click('Details', tr); }); return true;`);
      await until(`return !!document.querySelector('dialog[open] dl')`, 'plugin details');
      await shot('plugin-details', { height: 1300 });
      await closeDialogs();
      await ev(`$click('Install plugin'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #pi-sig')`, 'install dialog');
      await shot('plugin-install');
      await closeDialogs();
    }],
    ['settings', async () => {
      await go('/settings?tab=approvals');
      await shot('settings-approvals');
      await go('/settings?tab=alerts');
      await ev(`$rowClick('acme-chat', 'Send test'); return true;`);
      await until(`return !!document.querySelector('.test-result')`, 'alert test result');
      await shot('settings-alerts', { height: 1250 });
      await ev(`$rowClick('acme-chat', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] textarea.mono')`, 'rule editor');
      await shot('settings-alert-rule', { height: 1400 });
      await closeDialogs();
      await go('/settings?tab=sso');
      await shot('settings-sso', { height: 1500 });
      await go('/settings?tab=ssh');
      await shot('settings-ssh-keys');
      await go('/settings?tab=updates');
      await shot('settings-updates');
      // Phase 14b: self-checks (seeded run) and a support bundle the mock finishes after ~3 s
      await go('/settings?tab=diagnostics');
      await until(`return !!document.querySelector('#diag-checks-h') && document.querySelectorAll('tbody tr').length > 10`, 'diagnostics checks');
      await ev(`$click('Create bundle'); return true;`);
      await until(`return [...document.querySelectorAll('.chip')].some((c) => c.textContent.trim() === 'Ready')`, 'support bundle ready');
      await shot('settings-diagnostics', { height: 1700 });
    }],
    ['console', async () => {
      // emergency console root access (14c): request, approval, the code shown once, the banner while the shell runs
      const r = await api('POST', '/console/unlock', { hours: 2, reason: 'Storage driver debugging with the vendor (case 5120)' });
      if (r.status === 202) {
        await login('so');
        await api('POST', `/quorum/${r.body.quorum_id}/approve`);
        await login('admin');
      }
      await go('/settings?tab=console');
      await until(`return !!$button('Show code')`, 'console access requests');
      await shot('settings-console');
      await ev(`$rowClick('Storage driver debugging', 'Show code'); return true;`);
      await confirmOk();
      await until(`return !!document.querySelector('dialog[open] .console-code')`, 'console code');
      const code = await ev(`return document.querySelector('dialog[open] .console-code').textContent;`);
      await shot('console-code');
      await closeDialogs();
      // the mock stands in for the gate on tty2
      await api('POST', '/mock/console-gate', { code });
      await go('/', 900);
      await shot('console-shell-banner');
      await api('POST', '/mock/console-gate', { end: true });
    }],
    // Phase 14d: API tokens (My account, Users) and the web certificate
    ['tokens', async () => {
      await go('/account');
      await shot('account-tokens');
      await ev(`$click('New token'); return true;`);
      await until(`return !!document.querySelector('dialog[open] select')`, 'token dialog');
      await ev(`$fill('input[maxlength="64"]', 'grafana'); $fill('input[type=password]', 'nexus'); $fill('input[inputmode=numeric]', '492039'); return true;`);
      await shot('token-new', { height: 1000 });
      await ev(`$click('Create', document.querySelector('dialog[open]')); return true;`);
      await until(`return document.body.innerText.includes('shown only once')`, 'token shown once');
      await shot('token-created');
      await closeDialogs();
      await go('/users');
      await ev(`[...document.querySelectorAll('section.card')].pop()?.scrollIntoView(); return true;`);
      await shot('users-tokens', { scrolled: true });
    }],
    ['certificate', async () => {
      await go('/settings?tab=certificate');
      await until(`return document.body.innerText.includes('SHA-256 fingerprint')`, 'certificate tab');
      await shot('settings-certificate', { height: 1400 });
      await ev(`$click('Generate request'); return true;`);
      await until(`return document.body.innerText.includes('Pending request')`, 'pending CSR');
      await ev(`document.querySelector('textarea[placeholder^="-----BEGIN"]').scrollIntoView(); return true;`);
      await shot('certificate-csr', { height: 1400, scrolled: true });
    }],
    // Phase 14d: Settings → Security, My account → Sessions, download privilege / expiry, the viewer role
    ['access', async () => {
      await go('/settings?tab=security');
      await shot('settings-security', { height: 2000 });
      await go('/account');
      await shot('account-sessions');
      await go('/users');
      await ev(`$rowClick('contractor', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #u-expires')`, 'user dialog');
      await shot('user-edit-access', { height: 1100 });
      await closeDialogs();
      await login('auditor');
      await go('/', 900);
      await shot('dashboard-viewer');
      await login('admin');
    }],
    ['approvals', async () => {
      await go('/quorum');
      await shot('approvals-admin', { height: 1400 });
      await login('so');
      await go('/quorum');
      await shot('approvals', { height: 1600 });
      await ev(`[...document.querySelectorAll('article.card')].find((a) => a.textContent.includes('policy update')).scrollIntoView(); window.scrollBy(0, -70); return true;`);
      await shot('approvals-diff', { scrolled: true });
      // approve the new security officer: the approver receives the second half of the code
      await ev(`const card = [...document.querySelectorAll('article.card')].find((a) => a.textContent.includes('mmeyer')); $click('Approve', card); return true;`);
      await confirmOk();
      await until(`return document.body.innerText.includes('SECOND HALF')`, 'second half of the activation code');
      await shot('approvals-second-half');
      await closeDialogs();
    }],
    ['roles', async () => {
      await login('op');
      await go('/', 900);
      await shot('dashboard-operator');
      await login('acme');
      await go('/snapshots?source=vm-300');
      await shot('tenant-user-snapshots');
    }],
    // Phase 15c: legal hold (security officer): from the anomaly alert, for a time range, release request
    ['legal-hold', async () => {
      await login('so');
      await go('/alerts');
      await ev(`$rowClick('change-rate anomaly', 'Hold last good snapshot'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #hold-reason')`, 'hold dialog');
      await shot('alert-hold-last-good');
      await ev(`$click('Put on hold', document.querySelector('dialog[open]')); return true;`);
      await settle();
      await go('/snapshots?tenant=initech');
      await ev(`$click('Hold a time range'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #hold-from')`, 'hold range dialog');
      await ev(`$fill('#hold-source', 'vm-101'); $fill('#hold-reason', 'Incident 2026-031: suspected intrusion on app01'); return true;`);
      await shot('snapshot-hold-range');
      await closeDialogs();
      await go('/snapshots?held=true');
      await ev(`$rowClick('initech', 'Release hold'); return true;`);
      await confirmOk();
      await settle();
      await shot('snapshots-held');
      await login('admin');
    }],
    ['approvals-off', async () => {
      // switch approvals off (a request by admin, approved by a security officer) for the remaining pictures
      await login('admin');
      await go('/settings?tab=approvals');
      await ev(`$click('Disable approvals'); return true;`);
      await confirmOk();
      await login('so');
      const q = (await api('GET', '/quorum')).body.find((x) => x.action === 'approvals.disable' && x.state === 'pending');
      await api('POST', `/quorum/${q.id}/approve`);
      await login('admin');
      await ev(`sessionStorage.removeItem('nexus.approvalsBannerDismissed'); return true;`);
      await go('/', 900);
      await shot('dashboard-approvals-off');
      await go('/quorum');
      await ev(`const c = document.querySelector('.page-head input[type=checkbox]'); if (c?.checked) c.click(); return true;`);
      await sleep(300);
      await shot('approvals-disabled');
    }],
    ['login-sso', async () => {
      jar.clear();
      // a real IdP redirect is a full page load: a hash change alone keeps the old session state
      await cdp('Page.navigate', { url: 'about:blank' });
      await sleep(200);
      await cdp('Page.navigate', { url: BASE + '#/login?oidc_error=denied' });
      await until(`return !!document.querySelector('#l-name') && !!document.querySelector('a.sso') && !!document.querySelector('.banner.error')`, 'sign-in form with the single sign-on error');
      await shot('login-sso-error');
      // the mock has no identity provider: the button signs in as the single-sign-on user lwagner
      await ev(`document.querySelector('a.sso').click(); return true;`);
      await until(`return !!document.querySelector('.topbar') && document.body.innerText.includes('lwagner')`, 'single sign-on');
      await settle();
      await login('admin');
      await go('/users');
      await ev(`$rowClick('lwagner', 'Edit'); return true;`);
      await until(`return !!document.querySelector('dialog[open] #u-role')`, 'user dialog');
      await shot('user-sso');
      await closeDialogs();
    }],
    ['activate', async () => {
      jar.clear();
      await cdp('Page.navigate', { url: BASE + '#/activate?name=newop' });
      await until(`return !!document.querySelector('#a-code')`, 'activation form');
      await ev(`$fill('#a-code', 'DEMO-ACTIVATE-NEWOP-2026'); return true;`);
      await shot('activate-code');
      await ev(`$click('Continue'); return true;`);
      await until(`return !!document.querySelector('#a-pw')`, 'password step');
      await ev(`$fill('#a-pw', 'a-long-demo-passphrase'); $fill('#a-pw2', 'a-long-demo-passphrase'); return true;`);
      await shot('activate-password');
      await ev(`$click('Continue'); return true;`);
      await until(`return !!document.querySelector('#a-totp')`, 'authenticator step');
      const secret = await ev(`return document.querySelector('code.secret').textContent.trim();`);
      await ev(`$fill('#a-totp', '${totp(secret, Math.floor((Date.now() + OFFSET) / 30000))}'); return true;`);
      await shot('activate-authenticator');
      await ev(`$click('Activate'); return true;`);
      await until(`return document.body.innerText.includes('Your account is active')`, 'activation done');
      await shot('activate-done');
    }],
  ];

  let failed = 0;
  try {
    for (const [name, run] of scenes) {
      if (only.size && !only.has(name)) {
        // scenes later in the list rely on 'dashboard' having collected ids
        if (name === 'dashboard' && [...only].some((x) => x !== 'login' && x !== 'activate')) await run().catch(() => {});
        continue;
      }
      console.log(name);
      try {
        await run();
      } catch (e) {
        failed++;
        console.error(`FAILED ${name}: ${e.message}`);
        await cdp('Page.captureScreenshot', { format: 'png' }).then((r) => writeFileSync(join(tmp, `failed-${name}.png`), Buffer.from(r.data, 'base64')));
        await closeDialogs().catch(() => {});
      }
    }
  } finally {
    ws.close();
    await cleanup();
  }
  // lossless recompression when optipng is installed (about 20 % smaller); skipped otherwise
  if (written.length && !spawnSync('optipng', ['-quiet', '-o2', ...written.map((n) => join(OUT, `${n}.png`))], { stdio: 'inherit' }).error)
    console.log('optimized with optipng');
  const stale = only.size ? [] : readdirSync(OUT).filter((f) => f.endsWith('.png') && !written.includes(f.slice(0, -4)));
  if (stale.length) console.log(`not produced by this run (stale?): ${stale.join(', ')}`);
  if (problems.length) console.log(`browser problems:\n  ${[...new Set(problems)].join('\n  ')}`);
  console.log(`${written.length} screenshots in ${OUT}${failed ? `, ${failed} scene(s) FAILED` : ''}`);
  process.exit(failed ? 1 : 0);
}
