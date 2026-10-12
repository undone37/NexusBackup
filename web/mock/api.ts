// In-memory mock of the /api/v1 contract (docs/control-plane.md) for `npm run dev`
// and `npm run preview`. Vite server middleware only — never part of the build output.
//
// Users (password "nexus", any 6-digit TOTP code): admin, so, so2, op, acme (tenant_user of "acme").
// "newop" is pending activation: sign-in page → "Activate account", code DEMO-ACTIVATE-NEWOP-2026
// (any 6-digit authenticator code is accepted). Approvals start enabled with pending requests.
//
// The seed is a fictional demo appliance (also used for the manual's screenshots): tenants acme
// (S3 Object Lock offsite, replicated to the peer "dr-site"), initech (Storage Box offsite) and globex
// (replicated from the primary "hq-primary"). Only example domains (example.com/.net) and
// documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are used.

import type { Plugin } from 'vite';
// The real manifests of the shipped plugins, so the demo's forms and restores match them.
import pgManifest from '../../plugins/postgresql/manifest.json' with { type: 'json' };
import truenasManifest from '../../plugins/truenas/manifest.json' with { type: 'json' };

interface Req {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  on(ev: string, cb: (chunk?: Uint8Array) => void): void;
}
interface Res {
  statusCode: number;
  setHeader(k: string, v: string): void;
  end(body?: string): void;
}

type Role = 'admin' | 'security_officer' | 'operator' | 'tenant_user';
type Json = Record<string, any>;

class HttpError extends Error {
  constructor(
    public status: number,
    msg: string,
  ) {
    super(msg);
  }
}

// Reproducible demo (manual screenshots, manual/tools/screenshots.mjs):
//   NEXUS_MOCK_EPOCH=<unix seconds>  the mock clock starts there and runs at real speed
//   NEXUS_MOCK_SEED=<integer>        ids, tokens, fingerprints and codes come from a seeded PRNG
const EPOCH = Number(process.env.NEXUS_MOCK_EPOCH) || 0;
const STARTED = Date.now();
const now = () => Math.floor((EPOCH ? EPOCH * 1000 + (Date.now() - STARTED) : Date.now()) / 1000);
const SEED = process.env.NEXUS_MOCK_SEED;
let prng = (Number(SEED) || 1) >>> 0;
/** mulberry32: deterministic bytes when NEXUS_MOCK_SEED is set, else crypto randomness */
function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  if (SEED === undefined) {
    crypto.getRandomValues(b);
    return b;
  }
  for (let i = 0; i < n; i++) {
    prng = (prng + 0x6d2b79f5) >>> 0;
    let x = prng;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    b[i] = ((x ^ (x >>> 14)) >>> 0) & 0xff;
  }
  return b;
}
const rand = (n: number) => Array.from(randomBytes(n), (x) => x.toString(16).padStart(2, '0')).join('');
const b32 = (n = 32) => {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  return Array.from(randomBytes(n), (x) => a[x & 31]).join('');
};
const totpUri = (name: string, secret: string) =>
  `otpauth://totp/NexusBackup:${encodeURIComponent(name)}?secret=${secret}&issuer=NexusBackup&algorithm=SHA1&digits=6&period=30`;
async function sha256(s: string | Uint8Array) {
  const data = typeof s === 'string' ? new TextEncoder().encode(s) : s;
  const d = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource);
  return Array.from(new Uint8Array(d), (x) => x.toString(16).padStart(2, '0')).join('');
}
/** Dotted numeric version compare ("1.10.0" > "1.9.0"). */
function cmpVersion(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

// ---------------------------------------------------------------- state

interface User {
  id: number;
  name: string;
  role: Role;
  tenant: string | null;
  disabled: boolean;
  created: number;
  password: string;
  totp_secret: string;
  /** pending activation: the code parts the user must enter (plain in the mock;
   *  web-api stores only hashes), `null` while the second part is not issued yet */
  act?: { parts: (string | null)[]; expires: number | null; failures: number } | null;
  /** Phase 12: `oidc` = signs in through the IdP only (no password / TOTP here) */
  auth?: 'local' | 'oidc';
  oidc_sub?: string;
}
interface Agent {
  id: string;
  tenant: string;
  name: string;
  host: string;
  port: number;
  enrolled_at: number | null;
  cert_sha256: string | null;
  token_expires: number | null;
  last_seen: number | null;
  version: string | null;
  os: string | null;
  /** like web-api: only the hash of the one-time token is kept */
  token_hash: string | null;
}
interface Job {
  id: number;
  kind: string;
  tenant: string;
  params: Json;
  state: string;
  requested_by: string;
  created: number;
  started: number | null;
  finished: number | null;
  log: string;
  result: Json | null;
  plan: string[];
  duration: number;
  fail?: string;
}

const db = {
  users: [] as User[],
  tenants: [] as { name: string; offsite: Json; quota_bytes?: number | null }[],
  /** kind: pve | linux | nfs | smb | plugin:<kind> */
  sources: [] as { id: number; tenant: string; kind: string; name: string; config: Json }[],
  agents: [] as Agent[],
  replPeers: [] as Json[],
  replSources: [] as Json[],
  policies: [] as { id: number; name: string; schedule: string; gfs: Json; offsite: boolean }[],
  groups: [] as { id: number; tenant: string; source_id: number; policy_id: number; name: string; guests: (number | string)[] }[],
  jobs: [] as Job[],
  snapshots: [] as Json[],
  quorum: [] as Json[],
  audit: [] as Json[],
  alerts: [] as Json[],
  sessions: new Map<string, { userId: number; csrf: string; created: number; last: number }>(),
  downloads: new Map<string, { owner: string; filename: string; body: string; expires: number }>(),
  failures: new Map<string, { count: number; until: number }>(),
  quorumSecrets: new Map<number, Json>(),
  /** one entry per (plugin id, version), like GET /plugins */
  plugins: [] as Json[],
  pluginKeys: [] as Json[],
  approvals: false,
  gcPending: [] as Json[],
  seq: 100,
  /** Phase 12 settings (docs/phase12-contract.md) */
  oidc: {} as Json,
  alertSettings: {} as Json,
  sshKeys: [] as Json[],
  updates: {} as Json,
  /** Phase 13e setting `anomaly` */
  anomaly: { enabled: true, factor: 3, history: 14, floor_bytes: 2 ** 30 } as Json,
};
const nextId = () => ++db.seq;

async function audit(actor: string, action: string, target: string, details: Json = {}, at?: number) {
  const prev = db.audit.length ? db.audit[db.audit.length - 1].hash : '0'.repeat(64);
  const seq = db.audit.length + 1;
  const ts = at ?? now();
  const d = JSON.stringify(details);
  const hash = await sha256(prev + seq + ts + actor + action + target + d);
  db.audit.push({ seq, ts, actor, action, target, details, prev_hash: prev, hash });
}

function addJob(kind: string, tenant: string, params: Json, by: string, opts: Partial<Job> = {}): Job {
  const j: Job = {
    id: nextId(),
    kind,
    tenant,
    params,
    state: 'queued',
    requested_by: by,
    created: now(),
    started: null,
    finished: null,
    log: '',
    result: null,
    plan: planFor(kind, params),
    duration:
      { files_list: 3, files_get: 5, backup: 12, restore: 16, restore_ct: 12, instant_recover: 10, restore_files: 8, agent_enroll: 5, agent_update: 6 }[kind] ?? 8,
    ...opts,
  };
  db.jobs.push(j);
  return j;
}

function planFor(kind: string, p: Json): string[] {
  const ag = db.agents.find((a) => a.id === p.agent_id);
  const agName = ag ? `${ag.name} (${ag.host}:${ag.port})` : String(p.agent_id ?? '');
  const src = p.source ?? (p.vmid ? `vm-${p.vmid}` : p.agent_id ? `host-${p.agent_id}` : p.group_id ? `group ${p.group_id}` : '');
  const group = db.groups.find((g) => g.id === p.group_id);
  const hostAgent = ag ?? db.agents.find((a) => a.id === group?.guests[0]);
  if (kind === 'backup' && hostAgent)
    return [
      `starting backup of host-${hostAgent.id} via agent ${hostAgent.name} (${hostAgent.host}:${hostAgent.port})`,
      'pre-backup hooks ok',
      'walking /etc /home /var/www: 18,422 files, 2.1 GiB',
      'chunks: 214 new, 9,180 known (plain BLAKE3, mapped on the appliance)',
      'post-backup hooks ok',
      'index written, snapshot committed',
    ];
  const psrc = db.sources.find((s) => s.id === Number(p.source_id));
  switch (kind) {
    case 'plugin_validate':
      return [`starting nexus-pluginhost for ${psrc?.kind} (source ${psrc?.name})`, 'sandbox: landlock + seccomp active', 'Validate: connecting to the endpoint', 'done'];
    case 'plugin_guests':
      return [`starting nexus-pluginhost for ${psrc?.kind} (source ${psrc?.name})`, 'ListGuests', 'done'];
    case 'plugin_restore':
      return [`starting nexus-pluginhost: restore ${p.restore} of ${p.source} @ ${p.time}`, 'plugin requested 3 streams', 'streaming data to the plugin', `restore ${p.restore} finished`];
    case 'plugin_mount':
      return [`starting nexus-pluginhost: mount ${p.source} @ ${p.time} for ${p.minutes} min`, 'plugin answered MountReady', 'mounted'];
    case 'replica_sync': {
      const rs = db.replSources.find((x) => x.id === p.replication_source_id);
      return [`connecting to ${rs?.url} (pinned certificate, client certificate)`, `tenant ${p.tenant}: keys up to date`, 'fetching new snapshots, every chunk verified before import', 'replicated 1 snapshot'];
    }
    case 'replica_enroll':
      return ['creating client key + CSR', 'connecting with the enrollment ALPN, primary certificate pinned', 'proofs exchanged, client certificate received', 'enrolled'];
    case 'restore_files':
      return [
        `connecting to agent ${agName} over mTLS`,
        `RestoreBegin target=${p.target} overwrite=${p.overwrite} confirm="${p.confirm}"`,
        `reading ${src} @ ${p.time}: ${(p.paths ?? []).join(', ')}`,
        'restored 1,284 files (48.2 MiB), skipped 3 existing files',
        `restore to ${p.target} finished`,
      ];
    case 'agent_enroll':
      return [
        `connecting to ${agName} with the one-time token`,
        'token proof verified (bound to the TLS session)',
        'issued client certificate, pinned agent certificate',
        'agent enrolled',
      ];
    case 'agent_update':
      return [
        `sending signed release 0.9.1 to ${agName}`,
        'agent verified the release signature',
        'agent restarted',
        'agent reports version 0.9.1',
      ];
    case 'backup':
      return [
        `starting backup of ${src}`,
        'fleecing image created on fleecing storage',
        'dirty bitmap valid: incremental',
        'reading 12.4 GiB dirty of 64 GiB',
        'chunks: 3172 new, 12871 deduplicated',
        'index written, snapshot committed',
        'backup finished: 1.9 GiB stored (compressed+encrypted)',
      ];
    case 'files_list':
      return [`mounting ${src} @ ${p.time} read-only in restore micro-VM`, `listing ${p.path}`, 'done'];
    case 'files_get':
      return [`mounting ${src} @ ${p.time}`, `packing ${(p.paths ?? []).length} path(s) as ${p.format}`, 'archive ready'];
    case 'instant_recover':
      return [
        `exporting ${src} @ ${p.time} via NBD over SSH to ${p.node}`,
        `creating qcow2 overlay, VM ${p.target}`,
        'VM started from backup',
        `live disk move to ${p.storage}: 25%`,
        `live disk move to ${p.storage}: 100%`,
        'instant recovery complete',
      ];
    default:
      return [`${kind} started ${src}`, 'working…', 'working…', `${kind} finished`];
  }
}

function tick() {
  const t = now();
  for (const j of db.jobs) {
    if (j.state === 'queued' && t - j.created >= 1) {
      j.state = 'running';
      j.started = t;
    }
    if (j.state !== 'running' || j.started === null) continue;
    const frac = Math.min(1, (t - j.started) / j.duration);
    const n = Math.ceil(frac * j.plan.length);
    j.log = j.plan
      .slice(0, n)
      .map((l, i) => `${new Date((j.started! + Math.round((i / j.plan.length) * j.duration)) * 1000).toISOString()} ${l}`)
      .join('\n');
    if (frac >= 1) {
      j.finished = t;
      if (j.fail) {
        j.state = 'failed';
        j.log += `\nERROR: ${j.fail}`;
        continue;
      }
      j.state = 'ok';
      // Like the scheduler: structured results in `job.result`.
      if (j.kind === 'files_list') j.result = { entries: listDir(String(j.params.path ?? '/'), String(j.params.source ?? '')) };
      if (j.kind.startsWith('plugin_')) pluginResult(j, t);
      const ag = db.agents.find((a) => a.id === j.params.agent_id);
      if (j.kind === 'agent_enroll' && ag) {
        Object.assign(ag, { enrolled_at: t, cert_sha256: rand(32), token_expires: null, token_hash: null, last_seen: t });
        Object.assign(ag, { version: '0.9.0', os: 'Debian GNU/Linux 13 (trixie)' });
      }
      const rs = j.kind.startsWith('replica_') ? db.replSources.find((x) => x.id === j.params.replication_source_id) : undefined;
      if (rs && j.kind === 'replica_enroll') Object.assign(rs, { state: 'enrolled', cert_sha256: rand(32), keyd_fingerprint: keydFp() });
      if (rs && j.kind === 'replica_sync') {
        rs.last_sync = t;
        rs.status = { ...rs.status, [j.params.tenant]: { ...(rs.status?.[j.params.tenant] ?? {}), last_ok: t, last_error: null } };
      }
      if (j.kind === 'agent_update' && ag) Object.assign(ag, { version: '0.9.1', last_seen: t });
      if (j.kind === 'restore_files' && ag) ag.last_seen = t;
      if (j.kind === 'files_get') {
        j.result = { download_token: j.params.download_token, format: j.params.format, entries: (j.params.paths ?? []).length };
        db.downloads.set(String(j.params.download_token), {
          owner: j.requested_by,
          filename: `${j.params.source}-${j.params.time}.${j.params.format}`,
          body: `mock archive of ${(j.params.paths ?? []).join(', ')}\n`,
          expires: t + 86400,
        });
      }
      const pgroup = j.kind === 'backup' ? db.groups.find((g) => g.id === j.params.group_id) : undefined;
      const psrc = db.sources.find((s) => s.id === pgroup?.source_id && s.kind.startsWith('plugin:'));
      if (psrc && pgroup) {
        const pid = pluginKind(psrc.kind)?.plugin.id ?? 'unknown';
        const names = pgroup.guests.length ? pgroup.guests.map((g) => `plugin-${pid}-${psrc.id}-${g}`) : [`plugin-${pid}-${psrc.id}`];
        for (const n of names) db.snapshots.push(snap(j.tenant, n, t, 300 << 20, true, false, null));
        continue;
      }
      if (j.kind === 'backup') {
        // snapshot names per source kind: vm-/ct-<id>, host-<agent>, nas-<source>-<pool.dataset>, share-<source>
        const g = db.groups.find((x) => x.id === j.params.group_id);
        const gsrc = db.sources.find((x) => x.id === g?.source_id);
        const names =
          gsrc?.kind === 'nfs' || gsrc?.kind === 'smb'
            ? [`share-${gsrc.id}`]
            : gsrc?.kind === 'truenas'
              ? (g!.guests.length ? g!.guests : gsrc.config.datasets).map((d: string) => `nas-${gsrc.id}-${String(d).replaceAll('/', '.')}`)
              : (j.params.vmid ? [j.params.vmid] : j.params.agent_id ? [j.params.agent_id] : (g?.guests ?? [])).map(guestName);
        for (const n of names) db.snapshots.push(snap(j.tenant, n, t, 64 << 30, true, false, null));
        for (const a of db.agents) if (names.includes(`host-${a.id}`)) a.last_seen = t;
      }
    }
  }
}

/** Structured results of the plugin job kinds. */
function pluginResult(j: Job, t: number) {
  const p = j.params;
  const src = db.sources.find((s) => s.id === Number(p.source_id));
  if (j.kind === 'plugin_validate') {
    const host = String(src?.config.host ?? '');
    j.result = /bad|invalid/.test(host) ? { valid: false, field: 'host', message: `connection to ${host}:${src?.config.port} refused` } : { valid: true };
    j.log += j.result.valid ? '\nValid' : `\nInvalid: ${j.result.field}: ${j.result.message}`;
  } else if (j.kind === 'plugin_guests' && src?.kind === 'plugin:truenas') {
    j.result = {
      guests: [
        { id: 'tank.media', title: 'tank/media (/mnt/tank/media)' },
        { id: 'tank.archive', title: 'tank/archive (/mnt/tank/archive)' },
        { id: 'tank.vm-images', title: 'tank/vm-images (/mnt/tank/vm-images)' },
      ],
    };
  } else if (j.kind === 'plugin_guests') {
    j.result = {
      guests: [
        { id: 'shop', title: 'shop', size: 1_480 << 20 },
        { id: 'crm', title: 'crm', size: 402 << 20 },
        { id: 'analytics', title: 'analytics (reporting)', size: 9_830 * 2 ** 20 },
      ],
    };
  } else if (j.kind === 'plugin_restore') {
    j.result = { restore: p.restore, summary: `restored ${p.source} @ ${new Date(p.time * 1000).toISOString()} (${p.restore}): 3 streams, 1.4 GiB` };
  } else if (j.kind === 'plugin_mount') {
    const until = new Date((t + p.minutes * 60) * 1000).toISOString();
    j.result = { info: `postgresql://nexus_ro@appliance.example.com:15432/${p.params?.database || 'postgres'} (read-only)`, summary: `mounted until ${until}` };
  }
}

function listDir(path: string, source: string): Json[] {
  const t = now() - 86400 * 3;
  if (source.startsWith('host-')) {
    const win = db.agents.find((a) => `host-${a.id}` === source)?.os?.startsWith('Windows');
    if (!win) return hostDir(path, t);
    // Windows agent: volumes as top-level directories (/C, /D), docs/agent-windows.md
    const wd = (name: string) => ({ name, kind: 'dir', size: 0, mode: 0o40755, mtime: t, uid: 0, gid: 0, link: null });
    const wf = (name: string, size: number) => ({ name, kind: 'file', size, mode: 0o100644, mtime: t, uid: 0, gid: 0, link: null });
    const tree: Record<string, Json[]> = {
      '/': [wd('C'), wd('D')],
      '/C': [wd('Users')],
      '/C/Users': [wd('alice'), wd('bob')],
      '/C/Users/alice': [wd('Documents'), wf('NTUSER.DAT', 2_621_440)],
      '/C/Users/alice/Documents': [wf('contract-draft.docx', 88_412), wf('travel-expenses.xlsx', 41_207)],
      '/D': [wd('Shares')],
      '/D/Shares': [wd('Finance'), wd('Sales')],
      '/D/Shares/Finance': [wf('ledger-2026.xlsx', 1_204_221)],
      '/D/Shares/Sales': [wf('pricelist.pdf', 512_004)],
    };
    return tree[path] ?? [];
  }
  const f = (name: string, size: number) => ({ name, kind: 'file', size, mtime: t });
  const d = (name: string) => ({ name, kind: 'dir', size: 0, mtime: t });
  if (source.startsWith('plugin-postgresql-')) {
    // plugins/postgresql: a database snapshot holds the stream `<db>.sql`; the cluster snapshot data/ + wal/
    const db_ = /^plugin-postgresql-\d+-(.+)$/.exec(source)?.[1];
    const tree: Record<string, Json[]> = db_
      ? { '/': [d('.nexus-streams')], '/.nexus-streams': [f(`${db_}.sql`, db_ === 'shop' ? 1_503_238_553 : 398_458_880)] }
      : {
          '/': [d('data'), d('wal')],
          '/data': [d('base'), d('global'), d('pg_wal'), f('PG_VERSION', 3), f('backup_manifest', 412_771), f('postgresql.auto.conf', 88)],
          '/wal': [f('00000001000000A200000041', 16 << 20), f('00000001000000A200000042', 16 << 20), f('00000001000000A200000043', 16 << 20)],
        };
    return tree[path] ?? [];
  }
  if (source.startsWith('nas-') || source.startsWith('share-') || source.startsWith('plugin-truenas-')) {
    const tree: Record<string, Json[]> = {
      '/': [d('2026'), d('templates'), f('README.txt', 1_204)],
      '/2026': [d('Q3'), d('Q4')],
      '/2026/Q3': [f('budget-2026-q3.xlsx', 482_133), f('roadmap.pdf', 2_811_204)],
      '/2026/Q4': [f('budget-2026-q4.xlsx', 501_877), f('kickoff-slides.pdf', 7_340_032)],
      '/templates': [f('letter.docx', 38_211), f('invoice.odt', 22_870)],
    };
    return tree[path] ?? [];
  }
  const tree: Record<string, Json[]> = {
    '/': [
      { name: 'etc', kind: 'dir', size: 0, mtime: t },
      { name: 'home', kind: 'dir', size: 0, mtime: t },
      { name: 'var', kind: 'dir', size: 0, mtime: t },
      { name: 'vmlinuz', kind: 'symlink', size: 0, mtime: t, link: 'boot/vmlinuz-6.12.0' },
    ],
    '/etc': [
      { name: 'hostname', kind: 'file', size: 12, mtime: t },
      { name: 'fstab', kind: 'file', size: 812, mtime: t },
      { name: 'nginx', kind: 'dir', size: 0, mtime: t },
    ],
    '/etc/nginx': [{ name: 'nginx.conf', kind: 'file', size: 2_431, mtime: t }],
    '/home': [{ name: 'alice', kind: 'dir', size: 0, mtime: t }],
    '/home/alice': [
      { name: 'report-2026.pdf', kind: 'file', size: 1_843_221, mtime: t },
      { name: 'notes.txt', kind: 'file', size: 4_096, mtime: t },
    ],
    '/var': [{ name: 'log', kind: 'dir', size: 0, mtime: t }],
    '/var/log': [{ name: 'syslog', kind: 'file', size: 23_456_789, mtime: t }],
  };
  return tree[path] ?? [];
}

// Host snapshot tree (agent entry format: name, kind, size, mode, mtime, uid, gid, link).
function hostDir(path: string, t: number): Json[] {
  const d = (name: string, uid = 0, gid = 0) => ({ name, kind: 'dir', size: 0, mode: 0o40755, mtime: t, uid, gid, link: null });
  const f = (name: string, size: number, mode = 0o100644, uid = 0, gid = 0) => ({ name, kind: 'file', size, mode, mtime: t, uid, gid, link: null });
  const l = (name: string, link: string) => ({ name, kind: 'symlink', size: 0, mode: 0o120777, mtime: t, uid: 0, gid: 0, link });
  const tree: Record<string, Json[]> = {
    '/': [d('etc'), d('home'), d('var')],
    '/etc': [f('hostname', 6), f('fstab', 640), d('nginx'), d('ssl'), f('shadow', 1_204, 0o100640, 0, 42)],
    '/etc/nginx': [f('nginx.conf', 1_486), d('sites-enabled')],
    '/etc/nginx/sites-enabled': [l('default', '/etc/nginx/sites-available/default'), f('shop.conf', 2_210)],
    '/etc/ssl': [d('private', 0, 0)],
    '/etc/ssl/private': [f('shop.key', 3_272, 0o100600)],
    '/home': [d('deploy', 1000, 1000)],
    '/home/deploy': [f('.bashrc', 3_771, 0o100644, 1000, 1000), f('release.tar.gz', 18_874_368, 0o100644, 1000, 1000)],
    '/var': [d('www', 33, 33)],
    '/var/www': [d('shop', 33, 33)],
    '/var/www/shop': [f('index.php', 4_812, 0o100644, 33, 33), d('uploads', 33, 33)],
    '/var/www/shop/uploads': [f('logo.png', 48_211, 0o100644, 33, 33), f('catalog-2026.pdf', 2_418_022, 0o100644, 33, 33)],
  };
  return tree[path] ?? [];
}

const guestName = (g: number | string) =>
  typeof g === 'string' ? `host-${g}` : g >= 200 && g < 300 ? `ct-${g}` : `vm-${g}`;
const snap = (tenant: string, source: string, time: number, size: number, local: boolean, offsite: boolean, verified: number | null) => ({
  tenant,
  source,
  time,
  size,
  local,
  offsite,
  lock_until: time + 14 * 86400,
  verified,
});

// ---------------------------------------------------------------- plugins (docs/plugin-system.md)

const FILES_KIND = {
  kind: 'files',
  title: 'Files (example plugin)',
  config_schema: {
    type: 'object',
    required: ['path'],
    properties: {
      path: { type: 'string', title: 'Directory', description: 'Absolute path the plugin backs up.', pattern: '^/', minLength: 1, maxLength: 4096 },
      excludes: { type: 'array', title: 'Exclude patterns', description: 'Glob patterns, e.g. *.tmp.', items: { type: 'string', minLength: 1, maxLength: 256 } },
    },
  },
  secret_fields: [],
  endpoints: [],
  guests: null,
  backup: { incremental: true, consistent: 'none' },
  restores: [
    { id: 'download', title: 'Download (tar/zip)' },
    {
      id: 'to_dir',
      title: 'Restore to directory',
      params_schema: {
        type: 'object',
        required: ['target'],
        properties: { target: { type: 'string', title: 'Target directory', description: 'Absolute path; must not exist yet.', pattern: '^/' } },
      },
    },
  ],
};
const manifestOf = (id: string, name: string, version: string, kinds: Json[], sandbox: Json) => ({
  id,
  name,
  version,
  publisher: 'nexusbackup',
  api: 1,
  kinds: structuredClone(kinds),
  sandbox,
});
const BUILTIN_KEY = {
  fingerprint: 'sha256:6f1c0a8e2b4d93f7c5a1e0b29d8c47f3a6e5d4c3b2a1908f7e6d5c4b3a291807',
  publisher: 'nexusbackup',
  public_key: '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmockmockmockmockmockmockmockmo\nckmockmockmockmockmockmockmockmockmockmockmockmockmockmockmockmo==\n-----END PUBLIC KEY-----\n',
  name: 'TEST-KEY-DO-NOT-SHIP.pub',
  builtin: true,
};
function pluginEntry(m: Json, by: string, at: number, extra: Json = {}): Json {
  return {
    id: m.id,
    name: m.name,
    version: m.version,
    publisher: m.publisher,
    state: 'installed',
    current: true,
    enabled: true,
    signer: BUILTIN_KEY.name,
    sha256: rand(32),
    bin_sha256: rand(32),
    size: 4_812_288,
    manifest: m,
    uploaded_by: by,
    uploaded_at: at,
    installed_at: at + 3600,
    error: null,
    quorum_id: null,
    ...extra,
  };
}
const SANDBOX = { network: 'endpoints', tmp_mb: 1024, memory_mb: 1024, cpu_quota: 200 };
/** Current installed version providing a source kind ("plugin:<kind>" or "<kind>"). */
function pluginKind(kind: string): { plugin: Json; kind: Json } | null {
  const k = kind.replace(/^plugin:/, '');
  for (const p of db.plugins) {
    if (!p.current || p.state !== 'installed') continue;
    const def = p.manifest.kinds.find((x: Json) => x.kind === k);
    if (def) return { plugin: p, kind: def };
  }
  return null;
}
const pointerGet = (o: Json, ptr: string) => (ptr ? ptr.replace(/^\//, '').split('/').reduce((a: any, k) => a?.[k], o) : undefined);

/** Validates a value against the JSON-Schema subset (like the web-api; throws 400 "<path>: …"). */
function schemaCheck(schema: Json | undefined, v: Json, prefix: string) {
  const props: Json = schema?.properties ?? {};
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, `${prefix}: object required`);
  for (const k of Object.keys(v)) if (!(k in props)) throw new HttpError(400, `${prefix}.${k}: unknown field`);
  for (const r of schema?.required ?? []) if (v[r] === undefined) throw new HttpError(400, `${prefix}.${r}: required`);
  const one = (path: string, p: Json, x: unknown) => {
    const bad = (m: string) => {
      throw new HttpError(400, `${path}: ${m}`);
    };
    if (p.type === 'string' && typeof x !== 'string') bad('string expected');
    if (p.type === 'integer' && !Number.isInteger(x)) bad('integer expected');
    if (p.type === 'boolean' && typeof x !== 'boolean') bad('boolean expected');
    if (p.enum && !p.enum.includes(x)) bad(`one of ${p.enum.join(', ')}`);
    if (typeof x === 'number') {
      if (p.minimum !== undefined && x < p.minimum) bad(`minimum ${p.minimum}`);
      if (p.maximum !== undefined && x > p.maximum) bad(`maximum ${p.maximum}`);
      if (p.format === 'port' && (x < 1 || x > 65535)) bad('port 1-65535');
    }
    if (typeof x === 'string') {
      if (p.minLength !== undefined && x.length < p.minLength) bad(`at least ${p.minLength} characters`);
      if (p.maxLength !== undefined && x.length > p.maxLength) bad(`at most ${p.maxLength} characters`);
      if (p.pattern && !new RegExp(p.pattern, 'u').test(x)) bad(`does not match ${p.pattern}`);
      if (p.format === 'hostname' && !/^[A-Za-z0-9.:\[\]-]{1,253}$/.test(x)) bad('host name expected');
    }
  };
  for (const [k, p] of Object.entries(props) as [string, Json][]) {
    const x = v[k];
    if (x === undefined) continue;
    if (p.type === 'array') {
      if (!Array.isArray(x)) throw new HttpError(400, `${prefix}.${k}: array expected`);
      x.forEach((item, i) => one(`${prefix}.${k}[${i}]`, { type: 'string', ...(p.items ?? {}) }, item));
    } else one(`${prefix}.${k}`, p, x);
  }
}

/** Plugin source config: schema-checked; omitted secrets keep the stored ones unless an endpoint moved. */
function pluginSourceConfig(kind: string, cfg: Json, old?: Json): Json {
  const pk = pluginKind(kind);
  if (!pk) throw new HttpError(400, `kind: no installed plugin provides ${kind}`);
  const out = { ...(cfg ?? {}) };
  const moved = (pk.kind.endpoints ?? []).some((ep: Json) =>
    [ep.host, ep.port].some((ptr) => ptr && old && JSON.stringify(pointerGet(old, ptr)) !== JSON.stringify(pointerGet(out, ptr))),
  );
  for (const f of pk.kind.secret_fields ?? []) {
    if ((out[f] === undefined || out[f] === '') && old?.[f] !== undefined) {
      if (moved) throw new HttpError(400, `config.${f}: required (the endpoint changed)`);
      out[f] = old[f];
    }
  }
  schemaCheck(pk.kind.config_schema, out, 'config');
  return out;
}

/** manifest.json of a .nxplugin (tar) bundle, or null. */
function tarManifest(b: Uint8Array): Json | null {
  const dec = new TextDecoder();
  const str = (x: Uint8Array) => dec.decode(x).replace(/\0[\s\S]*$/, '');
  for (let off = 0; off + 512 <= b.length; ) {
    const hdr = b.subarray(off, off + 512);
    if (hdr.every((x) => x === 0)) break;
    const name = str(hdr.subarray(0, 100)).replace(/^\.\//, '');
    const size = parseInt(str(hdr.subarray(124, 136)).trim() || '0', 8);
    if (!Number.isFinite(size)) return null;
    if (name === 'manifest.json') {
      try {
        return JSON.parse(dec.decode(b.subarray(off + 512, off + 512 + size)));
      } catch {
        return null;
      }
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return null;
}

/** Manifest v1.4 `applies_to` (docs/phase12-contract.md §6), added when the shipped manifest lacks it. */
function withAppliesTo(m: Json): Json {
  const def: Record<string, string> = { to_target: 'guest', pitr: 'source' };
  for (const k of m.kinds ?? []) for (const r of k.restores ?? []) if (!r.applies_to && def[r.id]) r.applies_to = def[r.id];
  return m;
}

/** keyd replication key fingerprint format (crates/replication key_fingerprint): 8 groups of 4 hex */
const keydFp = () => rand(16).replace(/(.{4})(?=.)/g, '$1:');
const DEMO_HOST_KEY = (n: string) => `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${n}DemoKeyForTheManual${'0'.repeat(Math.max(0, 20 - n.length))}`;

function seed() {
  const t = now();
  /** midnight UTC `d` days ago + `hh` hours */
  const day = (d: number, hh = 1) => Math.floor(t / 86400 - d) * 86400 + hh * 3600;
  const mk = (name: string, role: Role, tenant: string | null = null, created = t - 86400 * 60): User => ({
    id: nextId(),
    name,
    role,
    tenant,
    disabled: false,
    created,
    password: 'nexus',
    totp_secret: b32(),
  });
  db.users.push(
    mk('admin', 'admin', null, t - 86400 * 90),
    mk('so', 'security_officer', null, t - 86400 * 90),
    mk('so2', 'security_officer'),
    mk('op', 'operator'),
    mk('acme', 'tenant_user', 'acme'),
  );
  const newop = mk('newop', 'operator');
  Object.assign(newop, { created: t - 3600, password: '', totp_secret: '', act: { parts: [normCode('DEMO-ACTIVATE-NEWOP-2026')], expires: t + 71 * 3600, failures: 0 } });
  const former = mk('former-op', 'operator', null, t - 86400 * 200);
  former.disabled = true;
  db.users.push(newop, former);

  // Tenants: acme → S3 with Object Lock, initech → Storage Box (SFTP), globex → replicated from hq-primary.
  db.tenants.push(
    {
      name: 'acme',
      offsite: {
        remote: {
          type: 's3', endpoint: 'https://s3.eu-central.example.net', region: 'eu-central-1', bucket: 'nexus-acme', prefix: 'appliance1',
          access_key: 'NXDEMOACCESSKEY0ACME', secret_key: 'sealed:demo', storage_class_packs: 'STANDARD_IA', path_style: false, lock: true,
        },
        bwlimit: null,
        uploaders: 4,
      },
    },
    {
      name: 'initech',
      offsite: {
        remote: { type: 'sftp', host: 'u123456.storagebox.example.net', port: 23, user: 'u123456', host_key: DEMO_HOST_KEY('box'), base_dir: 'nexus', key_file: '/etc/nexus/offsite/initech.key' },
        bwlimit: 20480 * 1024,
        uploaders: 4,
      },
      quota_bytes: 32 * 2 ** 40,
    },
    { name: 'globex', offsite: {} },
  );

  const pve = (tenant: string, name: string, host: string, nodes: Record<string, string>, storage: string) => ({
    id: nextId(),
    tenant,
    kind: 'pve' as const,
    name,
    config: {
      host, port: 8006, ca_pem: '-----BEGIN CERTIFICATE-----\n(PVE cluster CA, demo)\n-----END CERTIFICATE-----\n', token_id: 'nexus@pve!backup', token_secret: 'SECRET',
      nodes: Object.fromEntries(Object.entries(nodes).map(([n, h]) => [n, { host: h, port: 22, key: '/etc/nexus/ssh/pve.key', known_hosts: '/etc/nexus/ssh/known_hosts' }])),
      storage, fleecing_storage: 'local-lvm',
    } as Json,
  });
  // `storage` = ID of the NexusBackup storage on the cluster (pvesm add nexusbackup nexus …)
  const sInitech = pve('initech', 'pve-cluster', '192.0.2.10', { pve1: '192.0.2.11', pve2: '192.0.2.12' }, 'nexus');
  const sAcme = pve('acme', 'acme-pve', '198.51.100.10', { 'acme-pve1': '198.51.100.11' }, 'nexus');
  // globex takes no local backups (replicated tenant): its DR cluster is only a restore target.
  const sGlobex = pve('globex', 'globex-dr-pve', '203.0.113.20', { 'dr-pve1': '203.0.113.21' }, 'nexus');
  db.sources.push(sInitech, sAcme, sGlobex);

  const gold = { id: nextId(), name: 'gold', schedule: 'daily 01:00', gfs: { daily: 14, weekly: 8, monthly: 12, yearly: 3 }, offsite: true };
  const silver = { id: nextId(), name: 'silver', schedule: 'daily 22:00', gfs: { daily: 14, weekly: 4, monthly: 6, yearly: 2 }, offsite: true };
  const bronze = { id: nextId(), name: 'bronze', schedule: 'daily 03:30', gfs: { daily: 7, weekly: 4, monthly: 0, yearly: 0 }, offsite: false };
  const hourly = { id: nextId(), name: 'databases-hourly', schedule: 'hourly 15', gfs: { daily: 14, weekly: 4, monthly: 6, yearly: 1 }, offsite: true };
  db.policies.push(gold, silver, bronze, hourly);

  // Agents: web01 (Linux) and fs02 (Windows) enrolled in acme; db01 waits for enrollment, build01's token expired.
  const agent = (tenant: string, name: string, host: string, state: 'enrolled' | 'pending' | 'expired', os: string | null = null): Agent => ({
    id: rand(8),
    tenant,
    name,
    host,
    port: 7444,
    enrolled_at: state === 'enrolled' ? t - 86400 * 20 : null,
    cert_sha256: state === 'enrolled' ? rand(32) : null,
    token_expires: state === 'pending' ? t + 86400 - 3600 : state === 'expired' ? t - 86400 * 2 : null,
    last_seen: state === 'enrolled' ? t - 240 : null,
    version: state === 'enrolled' ? '0.9.0' : null,
    os: state === 'enrolled' ? os : null,
    token_hash: state === 'enrolled' ? null : rand(32),
  });
  const web01 = agent('acme', 'web01', '198.51.100.31', 'enrolled', 'Debian GNU/Linux 13 (trixie)');
  const fs02 = agent('acme', 'fs02', 'fs02.acme.example.com', 'enrolled', 'Windows Server 2022 Standard (10.0.20348)');
  db.agents.push(web01, fs02, agent('initech', 'db01', 'db01.initech.example.com', 'pending'), agent('initech', 'build01', '192.0.2.40', 'expired'));
  const sWeb01 = {
    id: nextId(),
    tenant: 'acme',
    kind: 'linux' as const,
    name: 'web01-files',
    config: { agent_id: web01.id, paths: ['/etc', '/home', '/var/www'], excludes: ['*.tmp', '/var/www/shop/cache/**'], hooks: true } as Json,
  };
  const sFs02 = {
    id: nextId(),
    tenant: 'acme',
    kind: 'linux' as const,
    name: 'fs02-files',
    config: { agent_id: fs02.id, paths: ['/C/Users', '/D/Shares'], excludes: ['C:\\Users\\*\\AppData\\Local\\Temp', '*.tmp'], hooks: false } as Json,
  };
  // TrueNAS (built-in connector, docs/truenas-connector.md)
  const sNas01 = {
    id: nextId(),
    tenant: 'acme',
    kind: 'truenas' as const,
    name: 'nas01',
    config: {
      host: 'nas01.acme.example.com', port: 443, ca_pem: '-----BEGIN CERTIFICATE-----\n(TrueNAS certificate, demo)\n-----END CERTIFICATE-----\n', user: 'nexusbackup', token_secret: 'SECRET',
      ssh: { host: 'nas01.acme.example.com', port: 22, user: 'nexusbackup', host_key: DEMO_HOST_KEY('nas01'), key_pem: 'SECRET', public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIApplianceDemoPublicKey000000000000 nexus-appliance', from: '198.51.100.5' },
      datasets: ['tank/projects', 'tank/home'], recursive: false, sudo: true, zfs_sudo: true,
    } as Json,
  };
  // NFS/SMB shares (docs/nas-connector.md): one share per source, groups without guests.
  const sNfs = {
    id: nextId(),
    tenant: 'acme',
    kind: 'nfs' as const,
    name: 'filer-projects',
    config: { host: 'filer.acme.example.com', port: 2049, version: '4.2', export: '/export/projects', snapshot_dir: '.snapshot', snapshot_prefix: 'nightly.', snapshot_order: 'name', excludes: ['*.tmp'], threads: 16, xattrs: true, timeout_secs: 60 } as Json,
  };
  const sSmb = {
    id: nextId(),
    tenant: 'acme',
    kind: 'smb' as const,
    name: 'fs01-data',
    config: { host: 'fs01.acme.example.com', port: 445, version: '3.1.1', share: 'Data', user: 'svc-backup', domain: 'ACME', sec: 'ntlmssp', sign: true, seal: true, password: 'SECRET', excludes: [], threads: 16, xattrs: true, timeout_secs: 60 } as Json,
  };
  db.sources.push(sWeb01, sFs02, sNas01, sNfs, sSmb);

  // Plugins: PostgreSQL 1.0.0 installed, 1.1.0 uploaded and waiting for approval; TrueNAS plugin 1.0.0.
  db.pluginKeys.push(BUILTIN_KEY, {
    fingerprint: 'sha256:0b7e5f1d93a2c4e8f6a1b3d5c7e9f0a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2',
    publisher: 'example-labs',
    public_key: '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexampleexampleexampleexampleexam\npleexampleexampleexampleexampleexampleexampleexampleexampleexample==\n-----END PUBLIC KEY-----\n',
    added_by: 'admin',
    approved_by: 'so',
    added_at: t - 86400 * 40,
    builtin: false,
  });
  const pgM = (v: string): Json => withAppliesTo({ ...structuredClone(pgManifest), version: v });
  const pg110 = pluginEntry(pgM('1.1.0'), 'admin', t - 1500, { state: 'pending', current: false, enabled: false, installed_at: null });
  db.plugins.push(pluginEntry(pgM('1.0.0'), 'admin', t - 86400 * 25), pg110, pluginEntry(structuredClone(truenasManifest) as Json, 'admin', t - 86400 * 12));
  const sPg = {
    id: nextId(),
    tenant: 'acme',
    kind: 'plugin:postgresql',
    name: 'pg-shop',
    config: {
      host: 'db1.acme.example.com', port: 5432, user: 'nexus_backup', password: 'SECRET', sslmode: 'verify-full', ca_cert: '-----BEGIN CERTIFICATE-----\n(demo CA)\n-----END CERTIFICATE-----\n',
      slot: 'nexusbackup', full_every_days: 7, restore_host: 'db2.acme.example.com', restore_port: 5432, restore_user: 'nexus_restore', restore_password: 'SECRET',
      ssh_host: 'db2.acme.example.com', ssh_port: 22, ssh_user: 'postgres', ssh_key: 'SECRET', ssh_host_key: DEMO_HOST_KEY('db2'),
    } as Json,
  };
  const sNas02 = {
    id: nextId(),
    tenant: 'acme',
    kind: 'plugin:truenas',
    name: 'nas02',
    config: {
      host: 'nas02.acme.example.com', port: 443, ca_pem: '-----BEGIN CERTIFICATE-----\n(TrueNAS certificate, demo)\n-----END CERTIFICATE-----\n', user: 'nexusbackup', api_key: 'SECRET',
      ssh_host: 'nas02.acme.example.com', ssh_port: 22, ssh_user: 'nexusbackup', ssh_host_key: DEMO_HOST_KEY('nas02'), ssh_private_key: 'SECRET', datasets: ['tank/media'], recursive: false, sudo: true, zfs_sudo: true,
    } as Json,
  };
  db.sources.push(sPg, sNas02);

  const grp = (tenant: string, source_id: number, policy_id: number, name: string, guests: (number | string)[]) => ({ id: nextId(), tenant, source_id, policy_id, name, guests });
  const gProd = grp('initech', sInitech.id, gold.id, 'production', [100, 101, 200]);
  const gDev = grp('initech', sInitech.id, bronze.id, 'development', [102]);
  const gAcmeVms = grp('acme', sAcme.id, silver.id, 'acme-vms', [300, 301]);
  const gSmb = grp('acme', sSmb.id, bronze.id, 'acme-fs01', []);
  const gDbs = grp('acme', sPg.id, hourly.id, 'acme-databases', ['shop', 'crm']);
  db.groups.push(
    gProd,
    gDev,
    gAcmeVms,
    grp('acme', sWeb01.id, silver.id, 'acme-web01', [web01.id]),
    grp('acme', sFs02.id, silver.id, 'acme-fs02', [fs02.id]),
    grp('acme', sNas01.id, silver.id, 'acme-nas01', ['tank/projects', 'tank/home']),
    grp('acme', sNfs.id, silver.id, 'acme-filer', []),
    gSmb,
    gDbs,
    grp('acme', sPg.id, silver.id, 'acme-pg-cluster', []),
    grp('acme', sNas02.id, silver.id, 'acme-nas02', ['tank.media']),
  );

  // Snapshots: up to 10 days of history; vm-101 has failed for two days.
  const series = (tenant: string, source: string, gib: number, opts: { skip?: number; offsite?: boolean; hh?: number; origin?: string; days?: number } = {}) => {
    const { skip = 0, offsite = true, hh = 1, origin, days = 9 } = opts;
    for (let d = days; d >= skip; d--) {
      const time = day(d, hh);
      if (time > t) continue;
      const s = snap(tenant, source, time, Math.round(gib * 2 ** 30 * (1 + (d % 3) * 0.01)), true, offsite && d > 0, d > 1 ? time + 7200 : null);
      db.snapshots.push(origin ? { ...s, origin } : s);
    }
  };
  series('initech', 'vm-100', 40);
  series('initech', 'vm-101', 120, { skip: 2 });
  series('initech', 'ct-200', 8);
  series('initech', 'vm-102', 30, { offsite: false, hh: 3 });
  series('acme', 'vm-300', 60, { hh: 22, skip: 1 });
  series('acme', 'vm-301', 25, { hh: 22, skip: 1 });
  series('acme', `host-${web01.id}`, 0.4, { hh: 22, skip: 1 });
  series('acme', `host-${fs02.id}`, 210, { hh: 22, skip: 1, days: 6 });
  series('acme', `nas-${sNas01.id}-tank.projects`, 1_800, { hh: 22, skip: 1, days: 5 });
  series('acme', `nas-${sNas01.id}-tank.home`, 640, { hh: 22, skip: 1, days: 5 });
  series('acme', `share-${sNfs.id}`, 3, { hh: 22, skip: 1, days: 5 });
  series('acme', `share-${sSmb.id}`, 0.9, { hh: 3, offsite: false, days: 3 });
  series('acme', `plugin-truenas-${sNas02.id}-tank.media`, 2_400, { hh: 22, skip: 1, days: 3 });
  series('acme', `plugin-postgresql-${sPg.id}`, 14, { hh: 22, skip: 1, days: 4 });
  for (const dbName of ['shop', 'crm']) {
    for (let h = 0; h < 4; h++) {
      const time = Math.floor(t / 3600 - h) * 3600 + 15 * 60;
      if (time > t) continue;
      db.snapshots.push(snap('acme', `plugin-postgresql-${sPg.id}-${dbName}`, time, (dbName === 'shop' ? 1_400 : 380) << 20, true, h > 1, h > 2 ? time + 1800 : null));
    }
  }
  // replicated from hq-primary (origin = replication source name), own retention on this appliance
  for (const [g, gib] of [['vm-500', 80], ['vm-501', 35], ['ct-250', 6]] as [string, number][])
    series('globex', g, gib, { hh: 4, origin: 'hq-primary', offsite: false });

  // Jobs: finished history + one running offsite upload. `L` stamps log lines like the scheduler does.
  const old = (j: Job, start: number, state: string, lines: string[], secs = 600, result: Json | null = null) => {
    const log = lines.map((l, i) => `${new Date((start + 2 + Math.round((i * secs) / lines.length)) * 1000).toISOString()} ${l}`).join('\n');
    Object.assign(j, { created: start, started: start + 2, finished: start + secs, state, log, plan: [], result });
    return j;
  };
  const fleecing = 'vm-101: fleecing storage local-lvm on pve2 is full (98 %)';
  const nightly = old(addJob('backup', 'initech', { group_id: gProd.id }, 'scheduler'), day(0, 1), 'failed', [
    'starting backup of vm-100 via node pve1',
    'dirty bitmap valid: incremental',
    'reading 2.1 GiB dirty of 64 GiB',
    'chunks: 512 new, 15,820 deduplicated',
    'index written, snapshot committed',
    'starting backup of vm-101 via node pve2',
    `ERROR: ${fleecing}`,
    'starting backup of ct-200 via node pve1',
    'tar stream: 679 MB, 0 new chunks',
    'index written, snapshot committed',
    'backup finished: 2 of 3 guests ok',
  ], 1460);
  old(addJob('backup', 'initech', { group_id: gDev.id }, 'scheduler'), day(0, 3), 'ok', ['starting backup of vm-102', 'dirty bitmap valid: incremental', 'index written, snapshot committed', 'backup finished: 1 guest'], 300);
  old(addJob('retention', 'initech', {}, 'scheduler'), day(0, 3) + 400, 'ok', ['GFS retention per group policy', 'kept 31 snapshots, locks extended', 'deleted 3 unlocked snapshots'], 20);
  old(addJob('offsite', 'initech', {}, 'scheduler'), day(0, 2), 'ok', ['uploading to sftp u123456.storagebox.example.net:23', 'uploaded 412 chunks in 3 packs (1.2 GiB)', 'manifests uploaded', 'inventory check: 0 missing, 0 unknown'], 900);
  old(addJob('verify', 'initech', {}, 'scheduler'), day(0, 5), 'ok', ['verifying chunk store part 3 of 7 (rolling)', 'verified 15,912 chunks: 0 missing, 0 corrupt', 'offsite: 3 sampled packs verified'], 1200);
  old(addJob('backup', 'acme', { group_id: gAcmeVms.id }, 'scheduler'), day(1, 22), 'ok', ['starting backup of vm-300', 'index written, snapshot committed', 'starting backup of vm-301', 'index written, snapshot committed', 'backup finished: 2 guests'], 900);
  const smbJob = old(addJob('backup', 'acme', { group_id: gSmb.id }, 'scheduler'), day(0, 3), 'ok', [
    'mounting //fs01.acme.example.com/Data read-only (SMB 3.1.1, signed + encrypted)',
    'no NAS snapshot directory configured: reading the live share',
    'scan: 48,211 files, 921 MiB, 12 changed',
    `inconsistent share-${sSmb.id}`,
    'snapshot committed',
  ], 640, { snapshots: [{ source: `share-${sSmb.id}`, time: day(0, 3), consistent: false }] });
  old(addJob('replica_sync', 'globex', { replication_source_id: 1, tenant: 'globex' }, 'scheduler'), day(0, 4), 'ok', [
    'connecting to backup-hq.example.com:8443 (pinned certificate, client certificate)',
    'keys: up to date (version 1)',
    '3 new snapshots on the primary, 3 kept by the local GFS',
    'fetched 1,214 chunks (734 MB), every chunk verified before import',
    'replicated 3 snapshots',
  ], 480);
  old(addJob('files_get', 'acme', { source: `host-${web01.id}`, time: day(2, 22), paths: ['/etc/nginx'], format: 'zip' }, 'acme'), t - 86400 - 7200, 'ok', ['reading the host snapshot', 'packing 1 path(s) as zip', 'archive ready'], 8);
  const pitrTime = new Date((day(2, 22) + 3 * 3600) * 1000).toISOString().slice(0, 19).replace('T', ' ') + '+00';
  old(addJob('plugin_restore', 'acme', { source: `plugin-postgresql-${sPg.id}`, time: day(2, 22), restore: 'pitr', params: { directory: '/var/lib/postgresql/restore-demo', target_time: pitrTime } }, 'admin'), t - 86400 - 3600, 'ok', [
    'starting nexus-pluginhost: restore pitr (sandbox: landlock + seccomp)',
    'streaming base backup data/ and 42 WAL segments to the plugin',
    'restore host db2.acme.example.com: SSH host key matches the pinned key',
    `recovery_target_time ${pitrTime} reached, server promoted`,
    'restore pitr finished',
  ], 260, { restore: 'pitr', summary: `new data directory /var/lib/postgresql/restore-demo on db2.acme.example.com, recovered to ${pitrTime}` });
  const retry = old(addJob('backup', 'initech', { vmid: 101 }, 'admin'), t - 5400, 'failed', ['starting backup of vm-101 via node pve2', `ERROR: ${fleecing}`], 40);
  old(addJob('backup', 'acme', { group_id: gDbs.id }, 'scheduler'), Math.floor(t / 3600) * 3600 + 15 * 60 > t ? Math.floor(t / 3600 - 1) * 3600 + 15 * 60 : Math.floor(t / 3600) * 3600 + 15 * 60, 'ok', [
    'starting nexus-pluginhost: postgresql 1.0.0 (sandbox: landlock + seccomp)',
    'database shop: consistent logical dump, 1.4 GiB',
    'database crm: consistent logical dump, 380 MiB',
    `snapshot committed: plugin-postgresql-${sPg.id}-shop`,
    `snapshot committed: plugin-postgresql-${sPg.id}-crm`,
  ], 120);
  const running = addJob('offsite', 'acme', {}, 'scheduler', { duration: 240 });
  running.plan = [
    'uploading to s3 nexus-acme/appliance1 (Object Lock, compliance mode)',
    'packs 1–4 of 11 uploaded, locked until their snapshots may be deleted',
    'packs 5–8 of 11 uploaded',
    'packs 9–11 of 11 uploaded',
    'manifests uploaded',
    'offsite copy complete',
  ];
  running.created = t - 5;

  // Alerts (messages as the scheduler writes them)
  db.alerts.push(
    { id: nextId(), ts: nightly.finished, severity: 'critical', kind: 'job_failed', message: `backup job ${nightly.id} (initech) failed: ${fleecing}`, acked_by: null },
    { id: nextId(), ts: retry.finished, severity: 'critical', kind: 'job_failed', message: `backup job ${retry.id} (initech) failed: ${fleecing}`, acked_by: null },
    { id: nextId(), ts: t - 3 * 3600, severity: 'warning', kind: 'capacity', message: 'store capacity above 75 % (now 78 %)', acked_by: null },
    {
      id: nextId(), ts: smbJob.finished, severity: 'warning', kind: 'backup_inconsistent',
      message: `share-${sSmb.id} — read without a NAS snapshot: not point-in-time consistent (backup job ${smbJob.id}, tenant acme, snapshot share-${sSmb.id})`, acked_by: null,
    },
    { id: nextId(), ts: t - 86400 * 3, severity: 'warning', kind: 'offsite_lag', message: 'offsite copy of tenant acme lags by 49 h (oldest snapshot not offsite: vm-300)', acked_by: 'op' },
    { id: nextId(), ts: t - 86400 * 6, severity: 'warning', kind: 'replication_lag', message: 'replication of tenant globex from hq-primary lags: no successful sync for 50 h', acked_by: 'admin' },
  );

  // Approvals are enabled. Pending: a large GC, deleting a group, weakening a policy, a plugin upgrade.
  db.approvals = true;
  const q = (action: string, params: Json, by: string, created: number, state = 'pending', decider: string | null = null) => {
    const x = { id: nextId(), action, params, requested_by: by, created, decided_by: decider, decided_at: decider ? created + 900 : null, state };
    db.quorum.push(x);
    return x;
  };
  const peerId = 'a1b2c3d4e5f60718';
  const peerKeyd = '8576:219c:4e1a:0b7d:9f32:c5e8:61aa:d403';
  q('plugin_key.add', { publisher: 'example-labs', fingerprint: db.pluginKeys[1].fingerprint }, 'admin', t - 86400 * 41, 'executed', 'so');
  q('replication_peer.create', { id: peerId, name: 'dr-site', tenants: ['acme'] }, 'admin', t - 86400 * 21, 'executed', 'so');
  q('replication.key_export', { peer: peerId, keyd_fingerprint: peerKeyd, tenants: ['acme'] }, 'admin', t - 86400 * 20, 'executed', 'so2');
  q('source.delete', { id: 42, name: 'old-esx-import' }, 'admin', t - 86400 * 9, 'rejected', 'so');
  const gcq = q('gc_large', { tenant: 'initech', job: 4711, reason: 'GC would delete 34 % of the stored chunks (limit 20 %)' }, 'scheduler', t - 2 * 3600);
  db.alerts.push({
    id: nextId(), ts: gcq.created, severity: 'warning', kind: 'gc_quorum',
    message: `GC for tenant initech needs approval by an admin or security officer (quorum request ${gcq.id}): GC would delete 34 % of the stored chunks (limit 20 %)`, acked_by: null,
  });
  q('group.delete', { id: gDev.id, name: 'development' }, 'admin', t - 1800);
  q('policy.update', { ...gold, gfs: { ...gold.gfs, daily: 7, yearly: 1 }, offsite: false, old: { ...gold, gfs: { ...gold.gfs } } }, 'admin', t - 600);
  const pq = q('plugin.install', { id: 'postgresql', version: '1.1.0', publisher: 'nexusbackup', sha256: pg110.sha256, signer: pg110.signer, upgrade_from: '1.0.0' }, 'admin', t - 1500);
  pg110.quorum_id = pq.id;
  // With approvals disabled, the scheduler would instead hold the large GC for an admin's confirmation.
  db.gcPending.push({ tenant: 'initech', job: 4711, reason: 'GC would delete 34 % of the stored chunks (limit 20 %)', created: t - 2 * 3600 });

  // Replication: this appliance is the primary for acme (peer dr-site) and the secondary for globex.
  db.replPeers.push({
    id: peerId, name: 'dr-site', tenants: ['acme'], state: 'enrolled', cert_sha256: rand(32),
    keyd_fingerprint: peerKeyd, token_expires: null, enrolled_at: t - 86400 * 20, last_seen: t - 1800,
    revoked: null, created: t - 86400 * 21, created_by: 'admin', keys: { acme: { versions: [1], created: t - 86400 * 20 } },
    enroll_failures: 0,
  });
  db.replSources.push({
    id: 1, name: 'hq-primary', url: 'backup-hq.example.com:8443', peer_id: '0f1e2d3c4b5a6978', cert_pin: rand(32),
    tenants: ['globex'], schedule: 'daily 04:00', gfs: { daily: 14, weekly: 4, monthly: 6, yearly: 2 }, bwlimit: 50_000_000,
    state: 'enrolled', cert_sha256: rand(32), keyd_fingerprint: keydFp(), created: t - 86400 * 30, last_sync: day(0, 4) + 480,
    status: { globex: { last_ok: day(0, 4) + 480, last_error: null, imported: 3, bytes: 734003200, remote: 41, key_versions: [1] } },
  });
  seedPhase12(t);
  seedPhase13a(t);
}

// ---------------------------------------------------------------- helpers

const pub = (u: User) => ({
  id: u.id,
  name: u.name,
  role: u.role,
  tenant: u.tenant,
  disabled: u.disabled,
  created: u.created,
  pending_activation: !!u.act,
  activation_expires: u.act?.expires ?? null,
  auth: u.auth ?? 'local',
});
const PRIV: Role[] = ['admin', 'security_officer'];
const ACT_SECS = 72 * 3600;
const normCode = (s: string) => s.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
const newCode = () => b32(26).replace(/(.{4})(?=.)/g, '$1-');
/** Admins and security officers that are enabled and activated: they can approve requests. */
const approvers = (except?: (u: User) => boolean) => db.users.filter((u) => PRIV.includes(u.role) && !u.disabled && !u.act && !except?.(u));
const activationPath = (name: string) => `/#/activate?name=${encodeURIComponent(name)}`;
/** Starts (or restarts) the activation of `x`: old credentials stop working. Returns the code to show. */
function startActivation(x: User, split: boolean): Json {
  const code = newCode();
  x.password = '';
  x.totp_secret = '';
  x.act = { parts: split ? [normCode(code), null] : [normCode(code)], expires: split ? null : now() + ACT_SECS, failures: 0 };
  for (const [sid, s] of db.sessions) if (s.userId === x.id) db.sessions.delete(sid);
  return { code, parts: split ? 2 : 1, part: 1, expires: x.act.expires, path: activationPath(x.name) };
}

function need(u: User | null, ...roles: Role[]): User {
  if (!u) throw new HttpError(401, 'not signed in');
  if (roles.length && !roles.includes(u.role)) throw new HttpError(403, `requires role ${roles.join(' or ')}`);
  return u;
}
const byTenant = <T extends { tenant: string }>(u: User, xs: T[]) => (u.tenant ? xs.filter((x) => x.tenant === u.tenant) : xs);
function find<T>(xs: T[], pred: (x: T) => boolean, what: string): T {
  const x = xs.find(pred);
  if (!x) throw new HttpError(404, `${what} not found`);
  return x;
}

// approved requests the scheduler executes (state stays `approved` until it has)
const SCHEDULER_ACTIONS = ['replication.key_export', 'gc_large'];
// 202 {quorum_id, ...extra} like web-api's `accepted()`; with approvals disabled the
// action runs at once (200 {approvals: "disabled", executed}).
async function quorum(u: User, action: string, params: Json, extra: Json = {}): Promise<[number, Json]> {
  if (!db.approvals) {
    if (SCHEDULER_ACTIONS.includes(action)) {
      const q = { id: nextId(), action, params, requested_by: u.name, created: now(), decided_by: u.name, decided_at: now(), state: 'approved' };
      db.quorum.push(q);
      await audit(u.name, action, `quorum/${q.id}`, { approvals: 'disabled', params });
      return [200, { approvals: 'disabled', executed: false, quorum_id: q.id, state: 'approved', ...extra }];
    }
    execute(0, action, params);
    await audit(u.name, action, action, { approvals: 'disabled', params });
    return [200, { approvals: 'disabled', executed: true, ...extra }];
  }
  const q = { id: nextId(), action, params, requested_by: u.name, created: now(), decided_by: null, decided_at: null, state: 'pending' };
  db.quorum.push(q);
  await audit(u.name, 'quorum.request', `quorum/${q.id}`, { action, params });
  return [202, { quorum_id: q.id, ...extra }];
}

function stripSource(s: (typeof db.sources)[number]) {
  if (s.kind === 'linux') return s;
  if (s.kind.startsWith('plugin:')) {
    const secrets: string[] = pluginKind(s.kind)?.kind.secret_fields ?? Object.keys(s.config).filter((k) => /password|secret|key/.test(k));
    const config: Json = {};
    for (const [k, v] of Object.entries(s.config)) {
      if (secrets.includes(k)) config[`${k}_set`] = v !== undefined && v !== '';
      else config[k] = v;
    }
    for (const f of secrets) config[`${f}_set`] ??= false;
    return { ...s, config };
  }
  if (s.kind === 'nfs' || s.kind === 'smb') {
    const { password, keytab, ...config } = s.config;
    return s.kind === 'nfs' ? { ...s, config } : { ...s, config: { ...config, password_set: !!password, keytab_set: !!keytab } };
  }
  if (s.kind === 'truenas') {
    const { token_secret, ssh, ...rest } = s.config;
    const { key_pem, ...sshPub } = ssh ?? {};
    return { ...s, config: { ...rest, token_secret_set: !!token_secret, ssh: { ...sshPub, key_pem_set: !!key_pem }, authorized_keys: truenasKeyLine(s.config) } };
  }
  const { token_secret, ...config } = s.config;
  return { ...s, config: { ...config, token_secret_set: !!token_secret } };
}
/** The authorized_keys line the web-api returns for a TrueNAS source (crates/truenas fc.rs, shortened script). */
function truenasKeyLine(c: Json): string | undefined {
  const pk = String(c.ssh?.public_key ?? '').trim();
  if (!pk) return undefined;
  const from = c.ssh?.from ? `,from="${c.ssh.from}"` : '';
  const sudo = (b: boolean) => (b ? '/usr/bin/sudo -n' : '');
  const script = `A=\\"${(c.datasets ?? []).join(' ')}\\" R=\\"${c.recursive ? 1 : ''}\\" S=\\"${sudo(c.sudo)}\\" Z=\\"${sudo(c.zfs_sudo)}\\"; case \\"$SSH_ORIGINAL_COMMAND\\" in …`;
  return `restrict${from},command="${script}" ${pk}`;
}
/** truenas source config (docs/truenas-connector.md); secrets omitted on PUT keep the stored ones. */
function truenasConfig(cfg: Json, old?: Json): Json {
  const c = structuredClone(cfg ?? {});
  if (!c.host) throw new HttpError(400, 'host: required');
  if (!Array.isArray(c.datasets) || !c.datasets.length || c.datasets.length > 64) throw new HttpError(400, 'datasets: 1 to 64 dataset names required');
  if (!String(c.ca_pem ?? '').includes('BEGIN CERTIFICATE')) throw new HttpError(400, 'ca_pem: PEM certificate required');
  if (!c.token_secret) {
    if (!old?.token_secret) throw new HttpError(400, 'token_secret (API key): required');
    c.token_secret = old.token_secret;
  }
  c.ssh = { ...(c.ssh ?? {}) };
  if (!c.ssh.key_pem) {
    if (!old?.ssh?.key_pem) throw new HttpError(400, 'ssh.key_pem: required');
    c.ssh.key_pem = old.ssh.key_pem;
  }
  return c;
}
const weakens = (a: Json, b: Json) =>
  ['daily', 'weekly', 'monthly', 'yearly'].some((k) => Number(b.gfs?.[k]) < Number(a.gfs?.[k])) || (a.offsite && !b.offsite);
// web-api refuses inline secrets in opaque JSON blobs (secrets live in files).
function noInlineSecrets(v: unknown) {
  if (v && typeof v === 'object')
    for (const [k, x] of Object.entries(v)) {
      if (/secret|password|passphrase|private/i.test(k)) throw new HttpError(400, `inline secret "${k}" not allowed; reference a file`);
      noInlineSecrets(x);
    }
}

// tenants.offsite: an S3 remote may carry its secret_key (write-only, "sealed" here); omitted on PUT = keep
function tenantOffsite(body: Json, old?: Json): Json {
  const o = structuredClone(body ?? {});
  const r = o.remote;
  if (r?.type !== 's3') {
    noInlineSecrets(o);
    return o;
  }
  const { secret_key, secret_key_set: _set, ...rest } = r;
  noInlineSecrets({ ...o, remote: rest });
  if (!/^https:\/\/[^/?#@ ]+\/?$/.test(String(r.endpoint ?? ''))) throw new HttpError(400, 'offsite.remote.endpoint: expected https://host[:port]');
  const keep = old?.remote?.type === 's3' && ['endpoint', 'region', 'bucket', 'access_key'].every((k) => old.remote[k] === r[k]);
  if (!secret_key && !keep) throw new HttpError(400, 'offsite.remote.secret_key: required');
  o.remote = { ...rest, secret_key: secret_key ? `sealed:${secret_key.length}` : old!.remote.secret_key };
  return o;
}

function publicOffsite(o: Json): Json {
  if (!o?.remote?.secret_key) return o;
  const { secret_key: _s, ...r } = o.remote;
  return { ...o, remote: { ...r, secret_key_set: true } };
}

function execute(qid: number, action: string, p: Json, by = '', decider = ''): Json | void {
  const { old: _old, ...next } = p;
  const versions = (id: string) => db.plugins.filter((x) => x.id === id);
  switch (action) {
    case 'plugin.install': {
      const e = find(db.plugins, (x) => x.id === p.id && x.version === p.version, 'plugin version');
      const prev = versions(p.id).find((x) => x.current);
      for (const x of versions(p.id)) x.current = false;
      Object.assign(e, { state: 'installed', current: true, enabled: prev ? prev.enabled : true, installed_at: now(), quorum_id: null });
      break;
    }
    case 'plugin.disable':
      for (const x of versions(p.id)) x.enabled = false;
      break;
    case 'plugin.activate': {
      const e = find(db.plugins, (x) => x.id === p.id && x.version === p.version && x.state === 'installed', 'installed plugin version');
      const prev = versions(p.id).find((x) => x.current);
      for (const x of versions(p.id)) x.current = false;
      Object.assign(e, { current: true, enabled: prev ? prev.enabled : true });
      break;
    }
    case 'plugin.remove':
      for (const x of versions(p.id)) Object.assign(x, { state: 'removed', current: false, enabled: false, quorum_id: null });
      break;
    case 'plugin_key.add':
      db.pluginKeys.push({ fingerprint: p.fingerprint, publisher: p.publisher, public_key: p.public_key, added_by: by, approved_by: decider, added_at: now(), builtin: false });
      break;
    case 'plugin_key.remove':
      db.pluginKeys = db.pluginKeys.filter((k) => k.builtin || k.fingerprint !== p.fingerprint);
      break;
    case 'group.delete':
      db.groups = db.groups.filter((g) => g.id !== p.id);
      break;
    case 'agent.delete':
      db.agents = db.agents.filter((a) => a.id !== p.id);
      break;
    case 'source.delete':
      db.sources = db.sources.filter((g) => g.id !== p.id);
      break;
    case 'policy.delete':
      db.policies = db.policies.filter((g) => g.id !== p.id);
      break;
    case 'tenant.update':
      find(db.tenants, (x) => x.name === p.name, 'tenant').offsite = structuredClone(p.offsite);
      break;
    case 'tenant.delete':
      db.tenants = db.tenants.filter((g) => g.name !== p.name);
      break;
    case 'settings.anomaly':
      db.anomaly = structuredClone(p.anomaly);
      break;
    case 'policy.update':
      Object.assign(find(db.policies, (x) => x.id === p.id, 'policy'), next);
      break;
    case 'group.update':
      Object.assign(find(db.groups, (x) => x.id === p.id, 'group'), next);
      break;
    case 'approvals.disable':
      db.approvals = false;
      break;
    case 'oidc.update':
      db.oidc = { ...db.oidc, ...next, client_secret: db.quorumSecrets.get(qid)?.client_secret ?? db.oidc.client_secret };
      db.quorumSecrets.delete(qid);
      break;
    case 'ssh_key.rotate':
      rotateSshKey(p.name);
      break;
    case 'snapshot.delete': {
      // the scheduler's `snapshot_delete` job; an offsite copy stays (offsite retention)
      const x = find(db.snapshots, (y) => y.tenant === p.tenant && y.source === p.source && y.time === p.time, 'snapshot');
      if (x.offsite) x.local = false;
      else db.snapshots = db.snapshots.filter((y) => y !== x);
      break;
    }
    case 'update.apply':
      if (db.updates.available) Object.assign(db.updates, { staged: { ...db.updates.available, since: now() }, status: 'staged' });
      break;
    case 'user.update': {
      const { name: _n, id: _i, activation, ...fields } = next;
      const x = find(db.users, (y) => y.id === p.id, 'user');
      if (activation === 'split') {
        // the approver gets the second half of the activation code
        const code = newCode();
        if (x.act && x.act.parts.length === 2 && x.act.parts[1] === null) {
          x.act.parts[1] = normCode(code);
          x.act.expires = now() + ACT_SECS;
        } else {
          Object.assign(x, { password: '', totp_secret: '' });
          x.act = { parts: [db.quorumSecrets.get(qid)?.part1 ?? '', normCode(code)], expires: now() + ACT_SECS, failures: 0 };
          for (const [sid, s] of db.sessions) if (s.userId === x.id) db.sessions.delete(sid);
        }
        db.quorumSecrets.delete(qid);
        Object.assign(x, fields);
        return { activation: { name: x.name, code, parts: 2, part: 2, expires: x.act.expires, path: activationPath(x.name) } };
      }
      const secrets = Object.fromEntries(Object.entries(db.quorumSecrets.get(qid) ?? {}).filter(([, v]) => v !== undefined));
      Object.assign(find(db.users, (x) => x.id === p.id, 'user'), fields, secrets);
      db.quorumSecrets.delete(qid);
      break;
    }
  }
}

// ---------------------------------------------------------------- routes

type Ctx = {
  method: string;
  path: string;
  query: URLSearchParams;
  body: Json;
  /** POST /plugins: the raw request body */
  raw: Uint8Array | null;
  headers: Req['headers'];
  user: User | null;
  sid: string | null;
  res: Res;
};
type Handler = (c: Ctx, m: string[]) => Promise<[number, unknown]> | [number, unknown];
const routes: [string, RegExp, Handler][] = [];
const on = (method: string, path: string, h: Handler) =>
  routes.push([method, new RegExp('^' + path.replace(/:\w+/g, '([^/]+)') + '$'), h]);

on('GET', '/health', () => [200, { ok: true }]);

on('POST', '/auth/login', async (c) => {
  const { name = '', password = '', totp = '' } = c.body;
  const f = db.failures.get(name);
  if (f && f.until > now()) throw new HttpError(429, 'too many failed sign-ins; try again in 15 minutes');
  const u = db.users.find((x) => x.name === name);
  if (!u || u.disabled || u.act || !u.password || u.password !== password || !/^\d{6}$/.test(String(totp))) {
    const g = f && f.until === 0 ? f : { count: 0, until: 0 };
    g.count++;
    if (g.count >= 5) g.until = now() + 900;
    db.failures.set(name, g);
    await audit(name || '-', 'auth.login_failed', 'session', {});
    throw new HttpError(401, 'invalid name, password or code');
  }
  db.failures.delete(name);
  const sid = rand(32);
  const csrf = rand(16);
  db.sessions.set(sid, { userId: u.id, csrf, created: now(), last: now() });
  c.res.setHeader('Set-Cookie', `nx_session=${sid}; HttpOnly; SameSite=Strict; Path=/`);
  await audit(u.name, 'auth.login', 'session', {});
  return [200, { csrf, user: pub(u) }];
});
on('POST', '/auth/logout', (c) => {
  if (c.sid) db.sessions.delete(c.sid);
  c.res.setHeader('Set-Cookie', 'nx_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  return [200, { ok: true }];
});
on('GET', '/auth/me', (c) => {
  const u = need(c.user);
  return [200, { user: pub(u), csrf: db.sessions.get(c.sid!)!.csrf }];
});

// tenants
const NAME_RE = /^(?!\.)[A-Za-z0-9._-]{1,64}$/;
on('GET', '/tenants', (c) => [200, db.tenants.filter((t) => !need(c.user).tenant || t.name === c.user!.tenant).map((t) => ({ ...t, offsite: publicOffsite(t.offsite) }))]);
on('POST', '/tenants', async (c) => {
  const u = need(c.user, 'admin');
  const name = String(c.body.name ?? '').trim();
  if (!NAME_RE.test(name)) throw new HttpError(400, 'invalid tenant name');
  if (db.tenants.some((t) => t.name === name)) throw new HttpError(409, 'tenant exists');
  const offsite = tenantOffsite(c.body.offsite);
  db.tenants.push({ name, offsite });
  await audit(u.name, 'tenant.create', `tenant/${name}`, {});
  return [201, { name, offsite: publicOffsite(offsite) }];
});
on('PUT', '/tenants/:name', async (c, [name]) => {
  const u = need(c.user, 'admin');
  const t = find(db.tenants, (x) => x.name === decodeURIComponent(name), 'tenant');
  const next = tenantOffsite(c.body.offsite, t.offsite);
  if (Object.keys(t.offsite ?? {}).length && JSON.stringify(next) !== JSON.stringify(t.offsite))
    return quorum(u, 'tenant.update', { name: t.name, offsite: publicOffsite(next), old: { name: t.name, offsite: publicOffsite(t.offsite) } });
  t.offsite = next;
  await audit(u.name, 'tenant.update', `tenant/${t.name}`, {});
  return [200, { ...t, offsite: publicOffsite(t.offsite) }];
});
on('DELETE', '/tenants/:name', (c, [name]) => quorum(need(c.user, 'admin'), 'tenant.delete', { name: decodeURIComponent(name) }));

// sources
on('GET', '/sources', (c) => [200, byTenant(need(c.user), db.sources).map(stripSource)]);
// linux source config: {agent_id, paths (absolute, 1..=64), excludes (0..=256), hooks}; unknown fields refused.
function linuxConfig(tenant: string, cfg: Json): Json {
  for (const k of Object.keys(cfg ?? {}))
    if (!['agent_id', 'paths', 'excludes', 'hooks'].includes(k)) throw new HttpError(400, `config: unknown field "${k}"`);
  find(db.agents, (a) => a.id === cfg.agent_id && a.tenant === tenant, 'agent in tenant');
  const paths = cfg.paths;
  if (!Array.isArray(paths) || paths.length < 1 || paths.length > 64 || paths.some((p) => typeof p !== 'string' || !p.startsWith('/')))
    throw new HttpError(400, 'config.paths: 1 to 64 absolute paths required');
  const excludes = cfg.excludes ?? [];
  if (!Array.isArray(excludes) || excludes.length > 256 || excludes.some((p) => typeof p !== 'string' || !p))
    throw new HttpError(400, 'config.excludes: at most 256 non-empty patterns');
  return { agent_id: cfg.agent_id, paths, excludes, hooks: !!cfg.hooks };
}

// nfs/smb source config: NFS and SMB fields must not be mixed (deny_unknown_fields in the web-api).
function shareConfig(kind: string, cfg: Json): Json {
  const common = ['host', 'port', 'version', 'snapshot_dir', 'snapshot_prefix', 'snapshot_order', 'excludes', 'threads', 'xattrs', 'timeout_secs'];
  const own = kind === 'nfs' ? ['export', 'mount_port'] : ['share', 'user', 'domain', 'sec', 'sign', 'seal', 'password', 'keytab', 'principal'];
  for (const k of Object.keys(cfg ?? {})) if (![...common, ...own].includes(k)) throw new HttpError(400, `config: unknown field "${k}"`);
  if (!cfg?.host) throw new HttpError(400, 'host: required');
  if (kind === 'nfs' && !String(cfg.export ?? '').startsWith('/')) throw new HttpError(400, 'export: absolute path required');
  if (kind === 'smb' && !cfg.share) throw new HttpError(400, 'share: required');
  return { ...cfg };
}

on('POST', '/sources', async (c) => {
  const u = need(c.user, 'admin');
  const { tenant, name, config, kind = 'pve' } = c.body;
  find(db.tenants, (t) => t.name === tenant, 'tenant');
  if (!NAME_RE.test(name ?? '')) throw new HttpError(400, 'invalid name');
  if (String(kind).startsWith('plugin:')) {
    const pk = pluginKind(kind);
    if (!pk || !pk.plugin.enabled) throw new HttpError(400, `kind: no enabled plugin provides ${kind}`);
    const s = { id: nextId(), tenant, kind, name, config: pluginSourceConfig(kind, config) };
    db.sources.push(s);
    await audit(u.name, 'source.create', `source/${s.id}`, { name, kind });
    return [201, stripSource(s)];
  }
  if (!['pve', 'linux', 'truenas', 'nfs', 'smb'].includes(kind)) throw new HttpError(400, 'kind: must be pve, linux, truenas, nfs, smb or plugin:<kind>');
  if (kind === 'truenas') {
    const s = { id: nextId(), tenant, kind: 'truenas' as const, name, config: truenasConfig(config) };
    db.sources.push(s);
    await audit(u.name, 'source.create', `source/${s.id}`, { name, kind });
    return [201, stripSource(s)];
  }
  if (kind === 'nfs' || kind === 'smb') {
    const cfg = shareConfig(kind, config);
    if (kind === 'smb' && !cfg.password && !cfg.keytab) throw new HttpError(400, 'config.password (or keytab): required');
    const s = { id: nextId(), tenant, kind: kind as 'nfs' | 'smb', name, config: cfg };
    db.sources.push(s);
    await audit(u.name, 'source.create', `source/${s.id}`, { name, kind });
    return [201, stripSource(s)];
  }
  if (kind === 'linux') {
    const s = { id: nextId(), tenant, kind: 'linux' as const, name, config: linuxConfig(tenant, config) };
    db.sources.push(s);
    await audit(u.name, 'source.create', `source/${s.id}`, { name, kind });
    return [201, stripSource(s)];
  }
  if (!config?.token_secret) throw new HttpError(400, 'token_secret required');
  noInlineSecrets(config.nodes);
  const s = { id: nextId(), tenant, kind: 'pve' as const, name, config: config ?? {} };
  db.sources.push(s);
  await audit(u.name, 'source.create', `source/${s.id}`, { name });
  return [201, stripSource(s)];
});
on('PUT', '/sources/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const s = find(db.sources, (x) => x.id === Number(id), 'source');
  if (s.kind.startsWith('plugin:')) {
    Object.assign(s, { name: c.body.name ?? s.name, config: pluginSourceConfig(s.kind, c.body.config, s.config) });
    await audit(u.name, 'source.update', `source/${s.id}`, {});
    return [200, stripSource(s)];
  }
  if (s.kind === 'linux') {
    const cfg = linuxConfig(s.tenant, c.body.config);
    // Groups of this source back up exactly its agent.
    for (const g of db.groups) if (g.source_id === s.id) g.guests = [cfg.agent_id];
    Object.assign(s, { name: c.body.name ?? s.name, config: cfg });
    await audit(u.name, 'source.update', `source/${s.id}`, {});
    return [200, stripSource(s)];
  }
  if (s.kind === 'truenas') {
    Object.assign(s, { name: c.body.name ?? s.name, config: truenasConfig(c.body.config, s.config) });
    await audit(u.name, 'source.update', `source/${s.id}`, {});
    return [200, stripSource(s)];
  }
  if (s.kind === 'nfs' || s.kind === 'smb') {
    const cfg = shareConfig(s.kind, c.body.config);
    if (!cfg.password && !cfg.keytab) Object.assign(cfg, { password: s.config.password, keytab: s.config.keytab });
    Object.assign(s, { name: c.body.name ?? s.name, config: cfg });
    await audit(u.name, 'source.update', `source/${s.id}`, {});
    return [200, stripSource(s)];
  }
  const cfg = { ...(c.body.config ?? {}) };
  if (!cfg.token_secret) cfg.token_secret = s.config.token_secret;
  Object.assign(s, { name: c.body.name ?? s.name, config: cfg });
  await audit(u.name, 'source.update', `source/${s.id}`, {});
  return [200, stripSource(s)];
});
on('DELETE', '/sources/:id', (c, [id]) => {
  const s = find(db.sources, (x) => x.id === Number(id), 'source');
  if (db.groups.some((g) => g.source_id === s.id)) throw new HttpError(409, 'source is still used by groups');
  return quorum(need(c.user, 'admin'), 'source.delete', { id: s.id, name: s.name });
});

// policies
on('GET', '/policies', (c) => (need(c.user), [200, db.policies]));
on('POST', '/policies', async (c) => {
  const u = need(c.user, 'admin');
  const p = { id: nextId(), name: c.body.name, schedule: c.body.schedule, gfs: c.body.gfs, offsite: !!c.body.offsite };
  if (!/^(daily \d{2}:\d{2}|hourly \d{2})$/.test(p.schedule ?? '')) throw new HttpError(400, 'invalid schedule');
  db.policies.push(p);
  await audit(u.name, 'policy.create', `policy/${p.id}`, p);
  return [201, p];
});
on('PUT', '/policies/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const p = find(db.policies, (x) => x.id === Number(id), 'policy');
  const after = { name: c.body.name, schedule: c.body.schedule, gfs: c.body.gfs, offsite: !!c.body.offsite };
  if (weakens(p, after)) return quorum(u, 'policy.update', { id: p.id, ...after, old: structuredClone(p) });
  Object.assign(p, after);
  await audit(u.name, 'policy.update', `policy/${p.id}`, after);
  return [200, p];
});
on('DELETE', '/policies/:id', (c, [id]) => {
  const p = find(db.policies, (x) => x.id === Number(id), 'policy');
  return quorum(need(c.user, 'admin'), 'policy.delete', { id: p.id, name: p.name });
});

// groups
on('GET', '/groups', (c) => [200, byTenant(need(c.user), db.groups)]);
// pve: guests are VM/CT IDs; linux: exactly [source.config.agent_id].
function checkGuests(src: (typeof db.sources)[number], guests: unknown) {
  if (!Array.isArray(guests)) throw new HttpError(400, 'guests: array required');
  if (src.kind === 'linux') {
    if (guests.length !== 1 || guests[0] !== src.config.agent_id)
      throw new HttpError(400, 'guests: a linux source needs exactly [its agent_id]');
  } else if (src.kind.startsWith('plugin:')) {
    if (!pluginKind(src.kind)?.kind.guests?.list) {
      if (guests.length) throw new HttpError(400, 'guests: this plugin kind has no guests; must be []');
    } else if (guests.some((g) => typeof g !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(g)))
      throw new HttpError(400, 'guests: guest ids [A-Za-z0-9._-]{1,64} required');
  } else if (src.kind === 'truenas') {
    if (guests.some((g) => !src.config.datasets.includes(g))) throw new HttpError(400, 'guests: datasets of the source required');
  } else if (src.kind === 'nfs' || src.kind === 'smb') {
    if (guests.length) throw new HttpError(400, "guests: a share source's group lists no guests");
  } else if (guests.some((g) => !Number.isInteger(g) || g < 100)) throw new HttpError(400, 'guests: VM/CT IDs required');
}
on('POST', '/groups', async (c) => {
  const u = need(c.user, 'admin');
  const g = { id: nextId(), tenant: c.body.tenant, source_id: Number(c.body.source_id), policy_id: Number(c.body.policy_id), name: c.body.name, guests: c.body.guests ?? [] };
  checkGuests(find(db.sources, (s) => s.id === g.source_id && s.tenant === g.tenant, 'source in tenant'), g.guests);
  db.groups.push(g);
  await audit(u.name, 'group.create', `group/${g.id}`, g);
  return [201, g];
});
on('PUT', '/groups/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const g = find(db.groups, (x) => x.id === Number(id), 'group');
  if ('tenant' in c.body) throw new HttpError(400, 'unknown field `tenant`');
  const next = { name: c.body.name, source_id: Number(c.body.source_id), policy_id: Number(c.body.policy_id), guests: c.body.guests };
  checkGuests(find(db.sources, (s) => s.id === next.source_id && s.tenant === g.tenant, 'source in tenant'), next.guests);
  const from = find(db.policies, (p) => p.id === g.policy_id, 'policy');
  const to = find(db.policies, (p) => p.id === next.policy_id, 'policy');
  if (weakens(from, to)) return quorum(u, 'group.update', { id: g.id, tenant: g.tenant, ...next, old: structuredClone(g) });
  Object.assign(g, next);
  await audit(u.name, 'group.update', `group/${g.id}`, g);
  return [200, g];
});
on('DELETE', '/groups/:id', (c, [id]) => {
  const g = find(db.groups, (x) => x.id === Number(id), 'group');
  return quorum(need(c.user, 'admin'), 'group.delete', { id: g.id, name: g.name });
});

// replication (docs/replication.md): this appliance as primary (peers) and as secondary (sources)
const findPeer = (id: string) => find(db.replPeers, (p) => p.id === id, 'peer');
const findRs = (id: string) => find(db.replSources, (r) => String(r.id) === id, 'replication source');
on('GET', '/replication/peers', (c) => (need(c.user), [200, db.replPeers]));
on('GET', '/replication/sources', (c) => (need(c.user), [200, db.replSources]));
on('POST', '/replication/peers', async (c) => {
  const u = need(c.user, 'admin');
  const { name, tenants = [] } = c.body;
  if (!NAME_RE.test(name ?? '')) throw new HttpError(400, 'invalid name');
  if (!Array.isArray(tenants) || !tenants.length) throw new HttpError(400, 'tenants: at least one');
  const peer = {
    id: rand(8), name, tenants, state: 'pending', cert_sha256: null, keyd_fingerprint: null, token_expires: now() + 86400,
    enrolled_at: null, last_seen: null, revoked: null, created: now(), created_by: u.name, keys: {}, enroll_failures: 0,
  };
  db.replPeers.push(peer);
  const [st, q] = await quorum(u, 'replication_peer.create', { id: peer.id, name, tenants });
  return [st, { ...q, peer, code: `${peer.id}.${b32(26)}`, primary_cert_sha256: '9c4f1e2d7a0b3c5d6e8f9a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5' }];
});
on('POST', '/replication/peers/:id/export-keys', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const p = findPeer(id);
  if (p.state !== 'enrolled') throw new HttpError(409, 'peer is not enrolled');
  return quorum(u, 'replication.key_export', { peer: p.id, keyd_fingerprint: p.keyd_fingerprint, tenants: p.tenants });
});
on('DELETE', '/replication/peers/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const p = findPeer(id);
  if (p.state === 'revoked') throw new HttpError(409, 'the peer is already revoked');
  if (p.state === 'pending') {
    Object.assign(p, { state: 'revoked', revoked: now(), token_expires: null });
    await audit(u.name, 'replication_peer.delete', `replication_peer/${p.id}`, { name: p.name, state: 'pending' });
    return [200, { id: p.id, state: 'revoked' }];
  }
  return quorum(u, 'replication_peer.delete', { id: p.id, name: p.name });
});
// like web-api: {name, url, code, fingerprint, tenants, schedule, gfs?, bwlimit?} → 201 + replica_enroll job
on('POST', '/replication/sources', async (c) => {
  const u = need(c.user, 'admin');
  const { name, url, code, fingerprint, tenants = [], schedule = 'daily 04:00', gfs = { daily: 14, weekly: 4, monthly: 6, yearly: 2 }, bwlimit = null } = c.body;
  if (!NAME_RE.test(name ?? '')) throw new HttpError(400, 'invalid name');
  if (!/^[A-Za-z0-9.-]+:\d{1,5}$/.test(url ?? '')) throw new HttpError(400, 'url: host:port');
  const pin = String(fingerprint ?? '').replace(/:/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(pin)) throw new HttpError(400, "fingerprint: SHA-256 of the primary's certificate (64 hex characters)");
  if (!/^[0-9a-f]{16}\.[A-Z2-7]{26}$/.test(code ?? '')) throw new HttpError(400, 'code: expected <peer-id>.<token>');
  if (!Array.isArray(tenants) || !tenants.length) throw new HttpError(400, 'tenants: at least one');
  for (const tn of tenants) {
    if (db.groups.some((g) => g.tenant === tn) || db.agents.some((a) => a.tenant === tn))
      throw new HttpError(409, `tenant ${tn} has local groups or agents: replicated tenants take no local backups`);
    if (!db.tenants.some((x) => x.name === tn)) db.tenants.push({ name: tn, offsite: {} });
  }
  const r = {
    id: nextId(), name, url, peer_id: code.split('.')[0], cert_pin: pin, tenants, schedule, gfs, bwlimit, state: 'enrolling',
    cert_sha256: null, keyd_fingerprint: null, created: now(), last_sync: null, status: {},
  };
  db.replSources.push(r);
  const j = addJob('replica_enroll', tenants[0], { replication_source_id: r.id }, u.name);
  await audit(u.name, 'replication_source.create', `replication_source/${r.id}`, { name, url, tenants });
  return [201, { ...r, job: j.id }];
});
on('POST', '/replication/sources/:id/sync', async (c, [id]) => {
  const u = need(c.user, 'admin', 'operator');
  const r = findRs(id);
  if (r.state !== 'enrolled') throw new HttpError(409, 'replication source is not enrolled');
  const jobs = (r.tenants as string[]).map((tn) => addJob('replica_sync', tn, { replication_source_id: r.id, tenant: tn }, u.name).id);
  await audit(u.name, 'job.create', `replication_source/${r.id}`, { kind: 'replica_sync', jobs });
  return [202, { jobs }];
});
on('POST', '/replication/sources/:id/enroll', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const r = findRs(id);
  if (!/^[0-9a-f]{16}\.[A-Z2-7]{26}$/.test(c.body.code ?? '')) throw new HttpError(400, 'code: <peer-id>.<token>');
  r.peer_id = c.body.code.split('.')[0];
  await audit(u.name, 'replication_source.enroll', `replication_source/${r.id}`, {});
  return [202, { job: nextId() }];
});
on('PUT', '/replication/sources/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const r = findRs(id);
  if (c.body.schedule) r.schedule = c.body.schedule;
  await audit(u.name, 'replication_source.update', `replication_source/${r.id}`, c.body);
  return [200, r];
});
on('DELETE', '/replication/sources/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const r = findRs(id);
  return quorum(u, 'replication_source.delete', { id: r.id, name: r.name });
});

// agents
const pubAgent = ({ token_hash: _h, ...a }: Agent) => a;
const AGENT_ID_RE = /^[0-9a-f]{16}$/;
const findAgent = (u: User, id: string) => find(byTenant(u, db.agents), (a) => AGENT_ID_RE.test(id) && a.id === id, 'agent');
// 128-bit one-time token, base32 (26 chars), valid 24 h; only its hash is stored.
async function issueToken(a: Agent) {
  const token = b32(26);
  a.token_hash = await sha256(token);
  a.token_expires = now() + 86400;
  return { token, install_command: 'sudo /usr/local/sbin/nexus-agent init --token -', token_expires: a.token_expires };
}
on('GET', '/agents', (c) => [200, byTenant(need(c.user), db.agents).map(pubAgent)]);
on('POST', '/agents', async (c) => {
  const u = need(c.user, 'admin');
  const { tenant, name, host, port = 7444 } = c.body;
  find(db.tenants, (t) => t.name === tenant, 'tenant');
  if (!NAME_RE.test(name ?? '')) throw new HttpError(400, 'invalid name');
  if (!/^[A-Za-z0-9.:\[\]-]{1,253}$/.test(host ?? '')) throw new HttpError(400, 'invalid host');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HttpError(400, 'invalid port');
  if (db.agents.some((a) => a.tenant === tenant && a.name === name)) throw new HttpError(409, 'agent name exists in this tenant');
  const a: Agent = {
    id: rand(8),
    tenant,
    name,
    host,
    port,
    enrolled_at: null,
    cert_sha256: null,
    token_expires: null,
    last_seen: null,
    version: null,
    os: null,
    token_hash: null,
  };
  const tok = await issueToken(a);
  db.agents.push(a);
  await audit(u.name, 'agent.create', `agent/${a.id}`, { tenant, name, host, port });
  return [201, { ...pubAgent(a), ...tok }];
});
on('POST', '/agents/:id/token', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const a = findAgent(u, id);
  const tok = await issueToken(a);
  await audit(u.name, 'agent.token', `agent/${a.id}`, { token_expires: tok.token_expires });
  return [200, tok];
});
on('POST', '/agents/:id/enroll', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const a = findAgent(u, id);
  if (!a.token_hash || !a.token_expires || a.token_expires <= now()) throw new HttpError(409, 'no valid enrollment token; issue a new token first');
  if (db.jobs.some((j) => j.kind === 'agent_enroll' && j.params.agent_id === a.id && (j.state === 'queued' || j.state === 'running')))
    throw new HttpError(409, 'an enrollment job for this agent is already running');
  const j = addJob('agent_enroll', a.tenant, { agent_id: a.id }, u.name);
  await audit(u.name, 'job.create', `job/${j.id}`, { kind: 'agent_enroll', tenant: a.tenant, params: j.params });
  return [202, { id: j.id }];
});
on('DELETE', '/agents/:id', (c, [id]) => {
  const u = need(c.user, 'admin');
  const a = findAgent(u, id);
  const used = db.sources.find((s) => s.kind === 'linux' && s.config.agent_id === a.id);
  if (used) throw new HttpError(409, `agent is used by source "${used.name}"`);
  return quorum(u, 'agent.delete', { id: a.id, tenant: a.tenant, name: a.name });
});

// users
on('GET', '/users', (c) => (need(c.user, 'admin'), [200, db.users.map(pub)]));
on('POST', '/users', async (c) => {
  const u = need(c.user, 'admin');
  const { name, role, tenant } = c.body;
  if ('password' in c.body) throw new HttpError(400, 'unknown field `password`: users set their own password at activation');
  if (!NAME_RE.test(String(name ?? ''))) throw new HttpError(400, 'invalid user name');
  if (db.users.some((x) => x.name === name)) throw new HttpError(409, 'user exists');
  if (role === 'tenant_user' && !tenant) throw new HttpError(400, 'tenant users need a tenant');
  // With approvals on, privileged accounts are created disabled; the quorum request
  // enables them. The requester gets only the first half of the activation code.
  const priv = PRIV.includes(role);
  const gated = priv && db.approvals;
  const n: User = { id: nextId(), name, password: '', role, tenant: tenant || null, disabled: gated, created: now(), totp_secret: '' };
  db.users.push(n);
  const activation = startActivation(n, gated);
  await audit(u.name, 'user.create', `user/${n.id}`, { name, role });
  if (gated) return quorum(u, 'user.update', { id: n.id, name, role, disabled: false, activation: 'split' }, { user: pub(n), activation });
  return [201, { user: pub(n), activation }];
});
on('PUT', '/users/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const x = find(db.users, (y) => y.id === Number(id), 'user');
  const b = c.body;
  const own = x.id === u.id;
  if (x.auth === 'oidc' && (b.password || b.reset_totp || b.new_activation || (b.role !== undefined && b.role !== x.role) || (b.tenant !== undefined && (b.tenant || null) !== x.tenant)))
    throw new HttpError(409, 'single sign-on account: role and tenants come from the group mapping, credentials from the identity provider');
  if ((b.password || b.reset_totp) && !own)
    throw new HttpError(400, "password / reset_totp only for your own account; issue a new activation code (new_activation) for other users");
  if (b.new_activation && own) throw new HttpError(400, 'new_activation: not for your own account');
  // re-authentication of the acting user for credential changes
  if (b.password || b.reset_totp || b.new_activation) {
    if (!b.current_password || !b.current_totp)
      throw new HttpError(400, 'current_password and current_totp are required to change a password or authenticator');
    if (b.current_password !== u.password || !/^\d{6}$/.test(String(b.current_totp))) {
      await audit(u.name, 'auth.reauth_failed', `user/${u.id}`, {});
      throw new HttpError(403, 're-authentication failed: wrong current password or TOTP code');
    }
  }
  const p: Json = { id: x.id, name: x.name };
  if (b.role !== undefined && b.role !== x.role) p.role = b.role;
  if (b.tenant !== undefined) p.tenant = b.tenant || null;
  if (b.disabled !== undefined && !!b.disabled !== x.disabled) p.disabled = !!b.disabled;
  if (b.password) p.password = b.password;
  const extra: Json = {};
  if (b.reset_totp) {
    p.totp_secret = b32();
    extra.totp_uri = totpUri(x.name, p.totp_secret);
  }
  const isPriv = PRIV.includes(x.role);
  const removesApprover = isPriv && !x.disabled && !x.act && (p.disabled === true || (p.role && !PRIV.includes(p.role)) || (b.new_activation && db.approvals));
  if (db.approvals && removesApprover && approvers((y) => y.id === x.id).length < 2)
    throw new HttpError(409, 'approvals are enabled: this change would leave fewer than two people who can approve requests');
  if (p.role && PRIV.includes(p.role) && x.act) throw new HttpError(409, 'the account must be activated before it can get a privileged role');
  const gated =
    db.approvals &&
    ((p.role && PRIV.includes(p.role)) || // granting
      (isPriv && x.disabled && p.disabled === false) || // re-enabling
      (isPriv && b.new_activation)); // new credentials for another privileged user
  if (gated) {
    // Credentials are applied on approval but never shown in the quorum params.
    const { password, totp_secret, ...shown } = p;
    if (b.new_activation) {
      const code = newCode();
      shown.activation = 'split';
      extra.activation = { code, parts: 2, part: 1, expires: null, path: activationPath(x.name) };
      const q = await quorum(u, 'user.update', shown, extra);
      db.quorumSecrets.set(q[1].quorum_id, { part1: normCode(code) });
      return q;
    }
    const q = await quorum(u, 'user.update', shown, { ...extra, user: pub(x) });
    db.quorumSecrets.set(q[1].quorum_id, { password, totp_secret });
    return q;
  }
  const { id: _i, name: _n, ...fields } = p;
  Object.assign(x, fields);
  if (b.new_activation) extra.activation = startActivation(x, false);
  await audit(u.name, 'user.update', `user/${x.id}`, { ...fields, password: fields.password ? '***' : undefined, totp_secret: undefined, new_activation: b.new_activation || undefined, approvals: db.approvals ? undefined : 'disabled' });
  return [200, { user: pub(x), ...extra }];
});

// plugins
const PLUGIN_ID_RE = /^[a-z0-9-]{2,32}$/;
const pluginVersions = (id: string) => db.plugins.filter((x) => x.id === id);
const currentPlugin = (id: string) => find(pluginVersions(id), (x) => x.current && x.state === 'installed', 'installed plugin');
on('GET', '/plugins', (c) => (need(c.user), [200, [...db.plugins].sort((a, b) => a.id.localeCompare(b.id) || cmpVersion(b.version, a.version))]));
on('POST', '/plugins', async (c) => {
  const u = need(c.user, 'admin');
  if (!String(c.headers['content-type'] ?? '').startsWith('application/octet-stream'))
    throw new HttpError(415, 'Content-Type must be application/octet-stream');
  const raw = c.raw;
  if (!raw?.length) throw new HttpError(400, 'empty bundle');
  if (raw.length > 128 << 20) throw new HttpError(413, 'bundle larger than 128 MiB');
  const sig = String(c.headers['x-plugin-signature'] ?? '').trim();
  if (!sig) throw new HttpError(400, 'X-Plugin-Signature: required');
  if (!/^[A-Za-z0-9+/]+=*$/.test(sig) || sig.length < 16) throw new HttpError(400, 'X-Plugin-Signature: base64 signature expected');
  // Mock: a real manifest.json in the tar is used; anything else becomes a newer example-files version.
  const bumpExample = (): Json => {
    const ex = pluginVersions('example-files');
    const top = ex.map((x) => x.version).sort(cmpVersion).pop() ?? '0.9.0';
    const [a, b, p] = top.split('.').map(Number);
    const base = ex[0]?.manifest ?? manifestOf('example-files', 'Example files', '1.0.0', [FILES_KIND], SANDBOX);
    return { ...structuredClone(base), version: `${a}.${b}.${(p || 0) + 1}` };
  };
  const m: Json = tarManifest(raw) ?? bumpExample();
  if (!PLUGIN_ID_RE.test(String(m.id ?? ''))) throw new HttpError(400, 'manifest.id: [a-z0-9-]{2,32} required');
  if (m.api !== 1) throw new HttpError(400, `manifest.api: unsupported protocol version ${m.api}`);
  if (!Array.isArray(m.kinds) || !m.kinds.length) throw new HttpError(400, 'manifest.kinds: at least one kind required');
  // "verification": the publisher needs a trusted key; signatures starting with "bad" fail.
  const key = db.pluginKeys.find((k) => k.publisher === m.publisher);
  if (!key || /^bad/i.test(sig)) throw new HttpError(400, 'signature verification failed: no trusted key matches');
  const live = pluginVersions(m.id).filter((x) => !['removed', 'rejected', 'failed'].includes(x.state));
  if (live.some((x) => x.publisher !== m.publisher)) throw new HttpError(409, `plugin id ${m.id} belongs to another publisher`);
  if (live.some((x) => x.state === 'pending' || x.state === 'approved')) throw new HttpError(409, 'another version of this plugin is waiting for approval');
  const top = live.map((x) => x.version).sort(cmpVersion).pop();
  if (top && cmpVersion(m.version, top) <= 0) throw new HttpError(409, `version ${m.version} is not newer than ${top}`);
  for (const k of m.kinds) {
    const other = pluginKind(k.kind);
    if (other && other.plugin.id !== m.id) throw new HttpError(409, `kind ${k.kind} is provided by plugin ${other.plugin.id}`);
  }
  const upgrade_from = live.find((x) => x.current)?.version ?? null;
  const e = pluginEntry(m, u.name, now(), {
    state: 'pending',
    current: false,
    enabled: false,
    signer: key.builtin ? key.name : key.fingerprint,
    sha256: await sha256(raw),
    size: raw.length,
    installed_at: null,
  });
  db.plugins.push(e);
  const [status, body] = await quorum(u, 'plugin.install', { id: m.id, version: m.version, publisher: m.publisher, sha256: e.sha256, signer: e.signer, upgrade_from }, { plugin: e, upgrade_from });
  e.quorum_id = body.quorum_id;
  return [status, body];
});
on('POST', '/plugins/:id/enable', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const e = currentPlugin(id);
  e.enabled = true;
  await audit(u.name, 'plugin.enable', `plugin/${id}`, { version: e.version });
  return [200, e];
});
on('POST', '/plugins/:id/disable', (c, [id]) => {
  const u = need(c.user, 'admin');
  const e = currentPlugin(id);
  if (!e.enabled) throw new HttpError(409, 'plugin is already disabled');
  return quorum(u, 'plugin.disable', { id, version: e.version });
});
on('POST', '/plugins/:id/activate', (c, [id]) => {
  const u = need(c.user, 'admin');
  const e = find(pluginVersions(id), (x) => x.version === c.body.version && x.state === 'installed', 'installed plugin version');
  if (e.current) throw new HttpError(409, 'version is already current');
  return quorum(u, 'plugin.activate', { id, version: e.version, from: pluginVersions(id).find((x) => x.current)?.version ?? null });
});
on('DELETE', '/plugins/:id', (c, [id]) => {
  const u = need(c.user, 'admin');
  const vs = pluginVersions(id).filter((x) => x.state === 'installed');
  if (!vs.length) throw new HttpError(404, 'plugin not found');
  const kinds = new Set(vs.flatMap((x) => x.manifest.kinds.map((k: Json) => `plugin:${k.kind}`)));
  const used = db.sources.find((s) => kinds.has(s.kind));
  if (used) throw new HttpError(409, `plugin kinds are used by source "${used.name}"`);
  return quorum(u, 'plugin.remove', { id, versions: vs.map((x) => x.version) });
});
on('GET', '/plugin-keys', (c) => (need(c.user), [200, db.pluginKeys]));
on('POST', '/plugin-keys', async (c) => {
  const u = need(c.user, 'admin');
  const publisher = String(c.body.publisher ?? '').trim();
  const pem = String(c.body.public_key ?? '').trim();
  if (!publisher || publisher.length > 64) throw new HttpError(400, 'publisher: required');
  const m = /^-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END PUBLIC KEY-----$/.exec(pem);
  if (!m) throw new HttpError(400, 'public_key: PEM "PUBLIC KEY" (ECDSA P-256) expected');
  const fingerprint = `sha256:${await sha256(m[1].replace(/\n/g, ''))}`;
  if (db.pluginKeys.some((k) => k.fingerprint === fingerprint)) throw new HttpError(409, 'key already trusted');
  return quorum(u, 'plugin_key.add', { publisher, fingerprint, public_key: pem + '\n' });
});
on('DELETE', '/plugin-keys/:fp', (c, [fp]) => {
  const u = need(c.user, 'admin');
  const k = find(db.pluginKeys, (x) => x.fingerprint === decodeURIComponent(fp), 'plugin key');
  if (k.builtin) throw new HttpError(409, 'project keys are part of the appliance image');
  return quorum(u, 'plugin_key.remove', { fingerprint: k.fingerprint, publisher: k.publisher });
});
// self-enrollment (no session)
async function checkActivation(name: string, code: string): Promise<User> {
  const key = `act:${name}`;
  const f = db.failures.get(key);
  if (f && f.until > now()) throw new HttpError(429, 'too many failed activation attempts; try again in 15 minutes');
  const x = db.users.find((y) => y.name === name);
  const want = x?.act && !x.disabled && x.act.expires && x.act.expires > now() && !x.act.parts.includes(null) ? x.act.parts.join('') : null;
  if (!want || normCode(code) !== want) {
    const g = f && f.until === 0 ? f : { count: 0, until: 0 };
    g.count++;
    if (g.count >= 5) g.until = now() + 900;
    db.failures.set(key, g);
    await audit('anonymous', 'auth.activate_failed', `user/${name}`, {});
    throw new HttpError(401, 'invalid name or activation code (or the code has expired)');
  }
  return x!;
}
const pendingTotp = new Map<string, string>();
on('POST', '/auth/activate/begin', async (c) => {
  const x = await checkActivation(String(c.body.name ?? ''), String(c.body.code ?? ''));
  const secret = b32();
  pendingTotp.set(x.name, secret);
  await audit(x.name, 'user.activate_begin', `user/${x.id}`, {});
  return [200, { name: x.name, totp_uri: totpUri(x.name, secret), totp_secret: secret }];
});
on('POST', '/auth/activate/complete', async (c) => {
  const { name = '', code = '', password = '', totp = '' } = c.body;
  const x = await checkActivation(String(name), String(code));
  if (String(password).length < 12) throw new HttpError(400, 'password must have at least 12 characters');
  const secret = pendingTotp.get(x.name);
  if (!secret) throw new HttpError(409, 'start the activation first');
  if (!/^\d{6}$/.test(String(totp))) throw new HttpError(401, 'invalid authenticator code');
  Object.assign(x, { password, totp_secret: secret, act: null });
  pendingTotp.delete(x.name);
  db.failures.delete(`act:${x.name}`);
  await audit(x.name, 'user.activate', `user/${x.id}`, {});
  return [200, { ok: true }];
});

// approvals setting
const approvalsState = () => {
  const n = approvers().length;
  const pend = db.quorum.find((q) => q.action === 'approvals.disable' && q.state === 'pending');
  return { enabled: db.approvals, possible_approvers: n, recommend: !db.approvals && n >= 2, pending_disable: pend?.id ?? null };
};
on('GET', '/settings/approvals', (c) => (need(c.user), [200, approvalsState()]));
on('PUT', '/settings/approvals', async (c) => {
  const u = need(c.user, 'admin');
  const want = !!c.body.enabled;
  if (want === db.approvals) return [200, approvalsState()];
  if (want) {
    if (approvers((y) => y.id === u.id).length < 1)
      throw new HttpError(409, 'nobody besides you could approve requests: add a second administrator or security officer first');
    db.approvals = true;
    await audit(u.name, 'settings.approvals', 'settings/approvals', { enabled: true });
    return [200, approvalsState()];
  }
  if (approvalsState().pending_disable) throw new HttpError(409, 'a request to disable approvals is already pending');
  return quorum(u, 'approvals.disable', { enabled: false });
});

// large GC confirmation (approvals disabled)
on('GET', '/gc/pending', (c) => (need(c.user, 'admin', 'security_officer', 'operator'), [200, db.approvals ? [] : db.gcPending]));
on('POST', '/gc/approve-large', async (c) => {
  const u = need(c.user, 'admin');
  if (db.approvals) throw new HttpError(409, 'approvals are enabled: a large GC needs a quorum approval');
  const i = db.gcPending.findIndex((g) => g.tenant === c.body.tenant);
  if (i < 0) throw new HttpError(409, 'no GC waits for confirmation in this tenant');
  const [g] = db.gcPending.splice(i, 1);
  const j = addJob('gc', g.tenant, { approved: true, confirmed_by: u.name }, u.name);
  await audit(u.name, 'gc.approve_large', `tenant/${g.tenant}`, { job: j.id, approvals: 'disabled' });
  return [202, { job_id: j.id }];
});

// snapshots / jobs / downloads
on('DELETE', '/snapshots/:tenant/:source/:time', (c, [tenant, source, time]) => {
  const u = need(c.user, 'admin');
  const [tn, src, tm] = [decodeURIComponent(tenant), decodeURIComponent(source), Number(time)];
  if (u.tenant && u.tenant !== tn) throw new HttpError(403, 'forbidden');
  const x = find(db.snapshots as any[], (y) => y.tenant === tn && y.source === src && y.time === tm, 'snapshot');
  if (!x.local) throw new HttpError(409, 'only the offsite copy is left: it follows the offsite retention');
  if (x.origin) throw new HttpError(409, "replicated snapshot: it follows the replication source's retention");
  if (x.lock_until > now()) throw new HttpError(409, `snapshot is locked until ${x.lock_until} (unix time)`);
  return quorum(u, 'snapshot.delete', { tenant: tn, source: src, time: tm });
});
on('GET', '/snapshots', (c) => {
  const u = need(c.user);
  const tq = c.query.get('tenant');
  const sq = c.query.get('source');
  const xs = byTenant(u, db.snapshots as any[]).filter((s) => (!tq || s.tenant === tq) && (!sq || s.source === sq));
  return [200, xs.sort((a, b) => b.time - a.time)];
});
const pubJob = (j: Job, withLog: boolean) => {
  const { plan: _p, duration: _d, fail: _f, log, ...rest } = j;
  return withLog ? { ...rest, log } : rest;
};
on('GET', '/jobs', (c) => {
  const u = need(c.user);
  const s = c.query.get('state');
  const k = c.query.get('kind');
  const xs = byTenant(u, db.jobs).filter((j) => (!s || j.state === s) && (!k || j.kind === k));
  return [200, xs.sort((a, b) => b.id - a.id).slice(0, 100).map((j) => pubJob(j, false))];
});
on('GET', '/jobs/:id', (c, [id]) => {
  const u = need(c.user);
  return [200, pubJob(find(byTenant(u, db.jobs), (j) => j.id === Number(id), 'job'), true)];
});
const RESTORE_KINDS = ['restore', 'restore_ct', 'instant_recover', 'files_list', 'files_get', 'restore_files', 'plugin_restore', 'plugin_mount'];
/** Source + kind of a plugin snapshot name (plugin-<id>-<source id>[-<guest>]). */
function pluginSnapshotKind(tenant: string, name: string) {
  const parts = name.replace(/^plugin-/, '').split('-');
  const i = parts.findIndex((x) => /^\d+$/.test(x));
  const src = find(db.sources, (s) => s.id === Number(parts[i]) && s.tenant === tenant && s.kind.startsWith('plugin:'), 'plugin source');
  const pk = pluginKind(src.kind);
  if (!pk?.plugin.enabled) throw new HttpError(409, `plugin for ${src.kind} is not installed or disabled`);
  return pk.kind;
}
const OVERWRITE = ['never', 'if_older', 'always'];
function checkJob(u: User, kind: string, tenant: string, p: Json) {
  if (kind === 'agent_enroll') throw new HttpError(400, 'use POST /agents/{id}/enroll');
  if (kind === 'plugin_validate' || kind === 'plugin_guests' || kind === 'plugin_backup') {
    const src = find(db.sources, (s) => s.id === Number(p.source_id) && s.tenant === tenant && s.kind.startsWith('plugin:'), 'plugin source in tenant');
    const pk = pluginKind(src.kind);
    if (!pk?.plugin.enabled) throw new HttpError(409, `plugin for ${src.kind} is not installed or disabled`);
    if (kind === 'plugin_guests' && !pk.kind.guests?.list) throw new HttpError(400, 'this plugin kind has no guest list');
  }
  if (kind === 'plugin_restore' || kind === 'plugin_mount') {
    if (!String(p.source ?? '').startsWith('plugin-')) throw new HttpError(400, 'source: must be a plugin snapshot');
    if (!db.snapshots.some((s) => s.tenant === tenant && s.source === p.source && s.time === p.time)) throw new HttpError(404, 'snapshot not found');
    const k = pluginSnapshotKind(tenant, p.source);
    const rid = kind === 'plugin_mount' ? 'mount' : p.restore;
    if (rid === 'download') throw new HttpError(400, 'restore: use files_get for downloads');
    if (kind === 'plugin_restore' && rid === 'mount') throw new HttpError(400, 'restore: use plugin_mount');
    const r = find(k.restores as Json[], (x) => x.id === rid, `restore ${rid} of ${k.kind}`);
    const isGuest = /^plugin-.+?-\d+-.+$/.test(p.source);
    if ((r.applies_to === 'guest' && !isGuest) || (r.applies_to === 'source' && isGuest))
      throw new HttpError(400, `restore ${rid} applies to ${r.applies_to} snapshots only`);
    if (r.params_schema) schemaCheck(r.params_schema, p.params ?? {}, 'params');
    else if (Object.keys(p.params ?? {}).length) throw new HttpError(400, 'params: this restore takes none');
    if (kind === 'plugin_mount' && !(Number.isInteger(p.minutes) && p.minutes >= 1 && p.minutes <= 1440))
      throw new HttpError(400, 'minutes: 1..1440');
  }
  if (kind === 'agent_update') {
    if (u.role !== 'admin') throw new HttpError(403, 'requires role admin');
    const a = find(db.agents, (x) => x.id === p.agent_id && x.tenant === tenant, 'agent in tenant');
    if (a.enrolled_at === null) throw new HttpError(409, 'agent is not enrolled');
  }
  if (kind === 'restore_files') {
    if (!String(p.source ?? '').startsWith('host-')) throw new HttpError(400, 'source: must be a host snapshot (host-<agent id>)');
    if (!db.snapshots.some((s) => s.tenant === tenant && s.source === p.source && s.time === p.time))
      throw new HttpError(404, 'snapshot not found');
    if (!Array.isArray(p.paths) || !p.paths.length || p.paths.some((x: unknown) => typeof x !== 'string' || !x.startsWith('/')))
      throw new HttpError(400, 'paths: absolute paths required');
    if (!String(p.target ?? '').startsWith('/')) throw new HttpError(400, 'target: must be absolute');
    if (!OVERWRITE.includes(p.overwrite)) throw new HttpError(400, 'overwrite: never, if_older or always');
    const a = find(db.agents, (x) => x.id === p.agent_id && x.tenant === tenant, 'agent in tenant');
    if (a.enrolled_at === null) throw new HttpError(409, 'target agent is not enrolled');
    if (p.confirm !== a.name) throw new HttpError(400, 'confirm: must be the target agent name');
  }
}
on('POST', '/jobs', async (c) => {
  const u = need(c.user, 'admin', 'operator', 'tenant_user');
  const { kind, tenant, params = {} } = c.body;
  if (typeof kind === 'string' && kind.startsWith('plugin_') && !['plugin_validate', 'plugin_guests', 'plugin_backup', 'plugin_restore', 'plugin_mount'].includes(kind))
    throw new HttpError(400, `unknown job kind ${kind}`);
  if (u.role === 'tenant_user' && (!RESTORE_KINDS.includes(kind) || tenant !== u.tenant)) throw new HttpError(403, 'tenant users may only restore within their tenant');
  find(db.tenants, (t) => t.name === tenant, 'tenant');
  if (kind === 'files_list' && !String(params.path ?? '').startsWith('/')) throw new HttpError(400, 'path: must be absolute');
  checkJob(u, kind, tenant, params);
  // Like web-api: files_get gets a server-generated download token, returned in the 202 body.
  const p = kind === 'files_get' ? { ...params, download_token: rand(32) } : params;
  const j = addJob(kind, tenant, p, u.name, params.vmid === 999 ? { fail: 'guest not found on any node' } : {});
  if (kind.startsWith('plugin_')) j.duration = { plugin_validate: 3, plugin_guests: 3, plugin_restore: 14, plugin_mount: 6 }[kind as string] ?? 10;
  await audit(u.name, 'job.create', `job/${j.id}`, { kind, tenant, params: p });
  return [202, p.download_token ? { id: j.id, download_token: p.download_token } : { id: j.id }];
});
on('POST', '/jobs/:id/cancel', async (c, [id]) => {
  const u = need(c.user, 'admin', 'operator');
  const j = find(db.jobs, (x) => x.id === Number(id), 'job');
  if (j.state !== 'queued') throw new HttpError(409, 'only queued jobs can be cancelled');
  j.state = 'cancelled';
  j.finished = now();
  await audit(u.name, 'job.cancel', `job/${j.id}`, {});
  return [200, pubJob(j, true)];
});

// quorum
on('GET', '/quorum', (c) => {
  need(c.user, 'admin', 'security_officer', 'operator');
  for (const q of db.quorum) if (q.state === 'pending' && now() - q.created > 72 * 3600) q.state = 'expired';
  return [200, [...db.quorum].sort((a, b) => b.id - a.id).map((q) => ({ ...q, expires: q.created + 72 * 3600 }))];
});
for (const verb of ['approve', 'reject'] as const) {
  on('POST', `/quorum/:id/${verb}`, async (c, [id]) => {
    const u = need(c.user, 'admin', 'security_officer');
    const q = find(db.quorum, (x) => x.id === Number(id), 'quorum request');
    if (q.state !== 'pending') throw new HttpError(409, `request is ${q.state}`);
    if (q.requested_by === u.name) throw new HttpError(403, 'the requester cannot decide their own request');
    Object.assign(q, { decided_by: u.name, decided_at: now(), state: verb === 'approve' ? 'approved' : 'rejected' });
    await audit(u.name, `quorum.${verb}`, `quorum/${q.id}`, { action: q.action });
    if (verb === 'reject' && q.action === 'plugin.install') {
      const e = db.plugins.find((x) => x.id === q.params.id && x.version === q.params.version);
      if (e) Object.assign(e, { state: 'rejected', quorum_id: null });
    }
    let extra: Json = {};
    if (verb === 'approve') {
      if (SCHEDULER_ACTIONS.includes(q.action)) return [200, q];
      extra = execute(q.id, q.action, q.params, q.requested_by, u.name) ?? {};
      q.state = 'executed';
      await audit('system', q.action, `quorum/${q.id}`, q.params);
    }
    return [200, { ...q, ...extra }];
  });
}

// audit
on('GET', '/audit', (c) => {
  need(c.user, 'admin', 'security_officer');
  const after = Number(c.query.get('after') ?? 0);
  const before = c.query.get('before');
  const limit = Math.min(Number(c.query.get('limit') ?? 500), 1000);
  const desc = before !== null || c.query.get('order') === 'desc';
  const xs = db.audit.filter((e) => e.seq > after && (before === null || e.seq < Number(before)));
  return [200, (desc ? [...xs].reverse() : xs).slice(0, limit)];
});
on('GET', '/audit/verify', async (c) => {
  need(c.user, 'admin', 'security_officer');
  let prev = '0'.repeat(64);
  for (const e of db.audit) {
    const h = await sha256(prev + e.seq + e.ts + e.actor + e.action + e.target + JSON.stringify(e.details));
    if (e.prev_hash !== prev || e.hash !== h) return [200, { ok: false, error: `audit chain broken at seq ${e.seq}` }];
    prev = e.hash;
  }
  return [200, { ok: true, entries: db.audit.length }];
});

// alerts
// Alerts have no tenant column: tenant-scoped users get an empty list.
on('GET', '/alerts', (c) => [200, need(c.user).tenant ? [] : [...db.alerts].sort((a, b) => b.ts - a.ts)]);
on('POST', '/alerts/:id/ack', async (c, [id]) => {
  const u = need(c.user, 'admin', 'operator', 'security_officer');
  if (u.tenant) throw new HttpError(403, 'forbidden');
  const a = find(db.alerts, (x) => x.id === Number(id), 'alert');
  a.acked_by = u.name;
  await audit(u.name, 'alert.ack', `alert/${a.id}`, {});
  return [200, a];
});

// ---------------------------------------------------------------- Phase 12 (docs/phase12-contract.md)

const sshPub = (comment: string) => `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${b64(randomBytes(24))} ${comment}`;
function b64(b: Uint8Array): string {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    out += a[(n >> 18) & 63] + a[(n >> 12) & 63] + (i + 1 < b.length ? a[(n >> 6) & 63] : '') + (i + 2 < b.length ? a[n & 63] : '');
  }
  return out;
}
const sshKey = (name: string, purpose: string, created: number) => ({
  name,
  purpose,
  public_key: sshPub(`nexus-${name}@backup.example.com`),
  fingerprint: `SHA256:${b64(randomBytes(32))}`,
  created,
  previous: null as Json | null,
});
function rotateSshKey(name: string) {
  const k = find(db.sshKeys, (x) => x.name === name, 'ssh key');
  const fresh = sshKey(k.name, k.purpose, now());
  Object.assign(k, { ...fresh, previous: { public_key: k.public_key, fingerprint: k.fingerprint, created: k.created } });
}

/** Phase 13a: legacy-ftp (vm-103) left its group; its old snapshots are unlocked and pruned as orphans. */
function seedPhase13a(t: number) {
  for (const d of [100, 70, 40]) {
    const time = Math.floor(t / 86400 - d) * 86400 + 3 * 3600;
    db.snapshots.push(snap('initech', 'vm-103', time, 18 * 2 ** 30, true, d > 40, time + 3600));
  }
  db.alerts.push({
    id: nextId(), ts: t - 86400 * 2 + 3 * 3600, severity: 'info', kind: 'orphaned',
    message: 'initech/vm-103 is in no protection group; pruned with the default retention', acked_by: null,
  });
}

/** Runs after the main seed so the ids and random values of the older demo data stay the same. */
function seedPhase12(t: number) {
  db.oidc = {
    enabled: true,
    issuer: 'https://idp.example.com/realms/nexus',
    client_id: 'nexusbackup',
    client_secret: 'sealed:demo',
    scopes: ['openid', 'profile', 'email'],
    username_claim: 'preferred_username',
    groups_claim: 'groups',
    label: 'Sign in with Keycloak',
    mappings: [
      { group: 'nexus-admins', role: 'admin', tenants: [] },
      { group: 'nexus-security', role: 'security_officer', tenants: [] },
      { group: 'nexus-operators', role: 'operator', tenants: [] },
      { group: 'acme-backup-users', role: 'tenant_user', tenants: ['acme'] },
    ],
  };
  db.alertSettings = {
    webhook_url: 'https://hooks.example.com/services/nexus-backup',
    smtp: { host: 'mail.example.com', port: 587, starttls: true, from: 'nexus@example.com', to: ['ops@example.com', 'backup-team@example.com'], user: 'nexus', password: 'sealed:demo' },
    min_severity: 'warning',
  };
  db.sshKeys = [
    sshKey('pve', 'Proxmox VE nodes (forced command)', t - 86400 * 90),
    sshKey('truenas', 'TrueNAS systems (forced command, read-only)', t - 86400 * 70),
    sshKey('offsite', 'Offsite SFTP targets (Storage Box)', t - 86400 * 88),
  ];
  db.updates = {
    booted: { version: '0.0.2-alpha', digest: `sha256:${rand(32)}`, since: t - 86400 * 12 },
    staged: null,
    available: { version: '0.0.3-alpha', digest: `sha256:${rand(32)}` },
    channel: 'stable',
    window: 'Sun 03:00 120',
    last_check: t - 5 * 3600,
    status: 'idle',
    error: null,
    rollback: { version: '0.0.1-alpha', digest: `sha256:${rand(32)}` },
    checking_since: 0,
  };
  // a single-sign-on user (Keycloak group nexus-operators): no password, no TOTP on the appliance
  db.users.push({
    id: nextId(), name: 'lwagner', role: 'operator', tenant: null, disabled: false, created: t - 86400 * 6,
    password: '', totp_secret: '', auth: 'oidc', oidc_sub: 'f3c1a9e2-5b7d-4e08-9a61-2d4c8b0e7f15',
  });
  // the break-glass alert of an earlier console recovery, acknowledged (the UI banner shows open ones)
  db.alerts.push({
    id: nextId(), ts: t - 86400 * 58, severity: 'critical', kind: 'break_glass',
    message: 'administrator "admin" was reset to pending activation at the console (nexus-setup recover-admin).', acked_by: 'so',
  });
}

// ---- dashboard KPIs (§1). The job history before the seed is synthetic but deterministic.
const DAY = 86400;
const isoDay = (ts: number) => new Date(ts * 1000).toISOString().slice(0, 10);
const hash = (...xs: number[]) => xs.reduce((h, x) => Math.imul(h ^ x, 2654435761) >>> 0, 0x9e3779b9) >>> 0;
/** friendly names of the demo VMs / containers */
const GUEST_NAMES: Record<string, string> = {
  'initech/100': 'erp-app', 'initech/101': 'erp-db', 'initech/200': 'proxy', 'initech/102': 'dev-sandbox', 'initech/103': 'legacy-ftp',
  'acme/300': 'shop-web', 'acme/301': 'shop-api', 'acme/302': 'test-web',
};
interface Obj { source: string; name: string; kind: string; tenant: string; rpo_s: number; inGroup: boolean; names: string[] }

function protectedObjects(u: User): Obj[] {
  const out: Obj[] = [];
  for (const g of byTenant(u, db.groups)) {
    const src = db.sources.find((s) => s.id === g.source_id);
    const pol = db.policies.find((p) => p.id === g.policy_id);
    if (!src || !pol) continue;
    const rpo_s = pol.schedule.startsWith('hourly') ? 3600 : DAY;
    const add = (source: string, name: string, names = [source]) => out.push({ source, name, kind: src.kind, tenant: g.tenant, rpo_s, inGroup: true, names });
    if (src.kind === 'pve')
      for (const v of g.guests) add(guestName(v), `${GUEST_NAMES[`${g.tenant}/${v}`] ?? 'guest'} (${v})`, [`vm-${v}`, `ct-${v}`]);
    else if (src.kind === 'linux') for (const a of g.guests) add(`host-${a}`, db.agents.find((x) => x.id === a)?.name ?? String(a));
    else if (src.kind === 'truenas')
      for (const d of g.guests.length ? g.guests : src.config.datasets) add(`nas-${src.id}-${String(d).replaceAll('/', '.')}`, `${src.name}: ${d}`);
    else if (src.kind === 'nfs' || src.kind === 'smb') add(`share-${src.id}`, src.name);
    else if (src.kind.startsWith('plugin:')) {
      const pid = pluginKind(src.kind)?.plugin.id ?? src.kind.slice(7);
      if (g.guests.length) for (const x of g.guests) add(`plugin-${pid}-${src.id}-${x}`, `${src.name}: ${x}`);
      else add(`plugin-${pid}-${src.id}`, src.name);
    }
  }
  // known guests that are in no protection group (cached PVE / plugin guest lists)
  const extra: Obj[] = [
    { source: 'vm-103', name: 'legacy-ftp (103)', kind: 'pve', tenant: 'initech', rpo_s: DAY, inGroup: false, names: ['vm-103'] },
    { source: 'vm-302', name: 'test-web (302)', kind: 'pve', tenant: 'acme', rpo_s: DAY, inGroup: false, names: ['vm-302'] },
  ];
  const pg = db.sources.find((s) => s.kind === 'plugin:postgresql');
  if (pg) extra.push({ source: `plugin-postgresql-${pg.id}-analytics`, name: `${pg.name}: analytics`, kind: pg.kind, tenant: pg.tenant, rpo_s: DAY, inGroup: false, names: [] });
  return [...out, ...extra.filter((o) => !u.tenant || o.tenant === u.tenant)];
}

/** Synthetic daily job counts of one tenant (scheduler runs per group + offsite / verify / retention). */
function tenantDay(tenant: string, dayStart: number, t: number) {
  const groups = db.groups.filter((g) => g.tenant === tenant);
  const hourly = groups.filter((g) => db.policies.find((p) => p.id === g.policy_id)?.schedule.startsWith('hourly')).length;
  const tn = db.tenants.find((x) => x.name === tenant);
  const extra = (tn?.offsite?.remote ? 1 : 0) + (groups.length ? 2 : 0) + (db.replSources.some((r) => r.tenants.includes(tenant)) ? 1 : 0);
  const frac = Math.min(1, Math.max(0, (t - dayStart) / DAY));
  const base = Math.round((groups.length - hourly + hourly * 24 + extra) * frac);
  const kinds = [...new Set(groups.map((g) => db.sources.find((s) => s.id === g.source_id)?.kind ?? 'pve'))];
  const h = hash(dayStart / DAY, [...tenant].reduce((a, c) => a + c.charCodeAt(0), 0));
  let failed = groups.length && frac === 1 ? (h % 11 === 0 ? 2 : h % 4 === 0 ? 1 : 0) : 0;
  const fkind = kinds[(h >>> 7) % Math.max(1, kinds.length)] ?? 'pve';
  // acme backs up an SMB share without NAS snapshots daily: one "not point-in-time consistent" warning
  const warning = groups.some((g) => db.sources.find((s) => s.id === g.source_id)?.kind === 'smb') && frac > 0.15 ? 1 : 0;
  // the seeded vm-101 failures (initech): yesterday's nightly run, today's run and the manual retry
  const real = db.jobs.filter((j) => j.tenant === tenant && j.state === 'failed' && (j.finished ?? 0) >= dayStart && (j.finished ?? 0) < dayStart + DAY);
  if (tenant === 'initech' && t - dayStart >= DAY && t - dayStart < 2 * DAY) failed = Math.max(failed, 1);
  const byKind: Record<string, number> = {};
  if (real.length) byKind.pve = real.length;
  else if (failed) byKind[tenant === 'initech' && t - dayStart < 2 * DAY ? 'pve' : fkind] = failed;
  failed = real.length || failed;
  return { ok: Math.max(0, base - failed - warning), warning, failed, byKind };
}

function dashboard(u: User, days: number) {
  const t = now();
  const today = Math.floor(t / DAY) * DAY;
  const tenants = db.tenants.map((x) => x.name).filter((n) => !u.tenant || n === u.tenant);
  const snaps = byTenant(u, db.snapshots as any[]);

  // protection
  const objs = protectedObjects(u).map((o) => {
    const last = snaps.filter((s) => s.tenant === o.tenant && o.names.includes(s.source)).reduce((m, s) => Math.max(m, s.time), 0) || null;
    const age_s = last ? t - last : null;
    const sla = !last ? 'never' : (age_s as number) > o.rpo_s * 1.5 ? 'breach' : 'ok';
    return { ...o, last_ok: last, age_s, sla };
  });
  const inGroup = objs.filter((o) => o.inGroup);
  const prot = {
    objects: objs.length,
    protected: inGroup.filter((o) => o.sla !== 'never').length,
    unprotected: objs.length - inGroup.filter((o) => o.sla !== 'never').length,
    sla_ok: inGroup.filter((o) => o.sla === 'ok').length,
    sla_breach: inGroup.filter((o) => o.sla === 'breach').length,
    never: inGroup.filter((o) => o.sla === 'never').length,
    worst: inGroup
      .sort((a, b) => Number(b.sla !== 'ok') - Number(a.sla !== 'ok') || (b.age_s ?? Infinity) / b.rpo_s - (a.age_s ?? Infinity) / a.rpo_s)
      .slice(0, 10)
      .map(({ source, name, kind, tenant, last_ok, age_s, rpo_s, sla }) => ({ source, name, kind, tenant, last_ok, age_s, rpo_s, sla })),
  };

  // jobs per day
  const per_day = [];
  const byKind: Record<string, number> = {};
  for (let d = days - 1; d >= 0; d--) {
    const start = today - d * DAY;
    const row = { day: isoDay(start), ok: 0, warning: 0, failed: 0 };
    for (const tn of tenants) {
      const x = tenantDay(tn, start, t);
      row.ok += x.ok;
      row.warning += x.warning;
      row.failed += x.failed;
      for (const [k, v] of Object.entries(x.byKind)) byKind[k] = (byKind[k] ?? 0) + v;
    }
    per_day.push(row);
  }
  const sum = per_day.reduce((a, r) => ({ ok: a.ok + r.ok, warning: a.warning + r.warning, failed: a.failed + r.failed }), { ok: 0, warning: 0, failed: 0 });
  const total = sum.ok + sum.warning + sum.failed;

  // capacity: 64 TiB store, 78 % used today (see the capacity alert), growing ~0.11 %/day
  const TOTAL = 64 * 2 ** 40;
  const allBytes = (db.snapshots as any[]).reduce((a, s) => a + s.size, 0) || 1;
  const share = u.tenant ? snaps.reduce((a, s) => a + s.size, 0) / allBytes : 1;
  const usedAt = storeUsedAt;
  const sample = (n: number) => Array.from({ length: n }, (_, i) => n - 1 - i).map((d) => ({ d, used: usedAt(d) }));
  // forecast: linear regression over the last 30 days of the whole store (when the shared pool is full)
  const reg = sample(30);
  const mx = reg.reduce((a, p) => a - p.d, 0) / reg.length;
  const my = reg.reduce((a, p) => a + p.used, 0) / reg.length;
  const slope = reg.reduce((a, p) => a + (-p.d - mx) * (p.used - my), 0) / reg.reduce((a, p) => a + (-p.d - mx) ** 2, 0);
  const fit = my + slope * (0 - mx);
  const forecast = slope > 0 ? Math.round((TOTAL - fit) / slope) : null;
  const used = usedAt(0);
  // ratios from the (synthetic) backup statistics, as the real API does
  const st = storageStats(u).totals;
  const reduction = +(st.reduction ?? 1).toFixed(2);
  const capacity = {
    total: TOTAL,
    used: Math.round(used * share),
    free: TOTAL - used,
    logical: Math.round(used * share * 0.97 * reduction),
    physical: Math.round(used * share * 0.97),
    reduction,
    dedup: st.dedup,
    compression: st.compression,
    per_day: sample(days).map((p) => ({ day: isoDay(today - p.d * DAY), used: Math.round(p.used * share), logical: Math.round(p.used * share * 0.97 * reduction) })),
    forecast_full_days: forecast,
  };

  // offsite + replication
  const offT = tenants.filter((n) => db.tenants.find((x) => x.name === n)?.offsite?.remote);
  const lags = offT.map((n) => t - (snaps.filter((s) => s.tenant === n && s.offsite).reduce((m, s) => Math.max(m, s.time), 0) || t - 30 * DAY));
  const replLags = [
    ...db.replSources.flatMap((r) => r.tenants.filter((n: string) => tenants.includes(n)).map((n: string) => t - (r.status?.[n]?.last_ok ?? r.created))),
    ...db.replPeers.filter((p) => p.state === 'enrolled' && p.tenants.some((n: string) => tenants.includes(n))).map((p) => t - (p.last_seen ?? p.created)),
  ];
  const verified = snaps.map((s) => s.verified).filter(Boolean) as number[];
  const offsite = {
    tenants: offT.length,
    lag_max_s: lags.length ? Math.max(...lags) : null,
    lagging: lags.filter((l) => l > 1.5 * DAY).length,
    lock_coverage: snaps.length ? snaps.filter((s) => s.lock_until > t).length / snaps.length : null,
    replication_lag_max_s: replLags.length ? Math.max(...replLags) : null,
    last_verify: verified.length ? Math.max(...verified) : null,
    verify_failed: 0,
  };
  return {
    generated: t,
    days,
    protection: prot,
    jobs: {
      success_rate: total ? +((sum.ok + sum.warning) / total).toFixed(4) : null,
      total,
      ...sum,
      per_day,
      failed_by_kind: Object.entries(byKind).map(([kind, failed]) => ({ kind, failed })).sort((a, b) => b.failed - a.failed),
    },
    capacity,
    offsite,
  };
}
// ---- storage accounting (Phase 13d/e, docs/storage-accounting.md). Synthetic per-snapshot
// statistics: a source's first snapshot writes ~55 % of its size (the rest deduplicates against
// other guests), later ones its daily change rate; compression by source type. Scaled so that
// Stored matches the store size the dashboard shows.
const STORE_TOTAL = 64 * 2 ** 40;
function storeUsedAt(d: number) {
  const wobble = ((hash(d, 7) % 1000) / 1000 - 0.5) * 0.004;
  return Math.round(STORE_TOTAL * (0.78 - 0.0011 * d + wobble));
}
const COMPRESSION: [string, number][] = [['plugin-postgresql-', 3.2], ['plugin-', 1.8], ['host-', 2.1], ['share-', 1.25], ['nas-', 1.4], ['', 1.7]];
interface Sum { snapshots: number; logical: number; data_in: number; stored: number }
function sumJson(s: Sum, k = 1) {
  const r = (a: number, b: number) => (b > 0 ? +(a / b).toFixed(3) : null);
  const [l, d, st] = [s.logical * k, s.data_in * k, s.stored * k].map(Math.round);
  return { snapshots: s.snapshots, logical: l, data_in: d, stored: st, saved: Math.max(0, l - st), dedup: r(l, d), compression: r(d, st), reduction: r(l, st) };
}
function groupOfSource(tenant: string, source: string): (typeof db.groups)[number] | undefined {
  return db.groups.find((g) => {
    if (g.tenant !== tenant) return false;
    const src = db.sources.find((s) => s.id === g.source_id);
    if (!src) return false;
    if (src.kind === 'pve') return g.guests.some((v) => source === `vm-${v}` || source === `ct-${v}`);
    if (src.kind === 'linux') return g.guests.some((a) => source === `host-${a}`);
    if (src.kind === 'nfs' || src.kind === 'smb') return source === `share-${src.id}`;
    if (src.kind === 'truenas') return source.startsWith(`nas-${src.id}-`);
    const m = /^plugin-[a-z0-9]+-(\d+)(?:-(.+))?$/.exec(source);
    return !!m && Number(m[1]) === src.id && (!g.guests.length || g.guests.includes(m[2] ?? ''));
  });
}
function storageStats(u: User) {
  const t = now();
  // replicated snapshots (origin set) carry no statistics, like on a real appliance
  const kept = (db.snapshots as Json[]).filter((s) => s.local);
  const snaps = kept.filter((s) => !s.origin).sort((a, b) => a.time - b.time);
  const seen = new Set<string>();
  const zero = (): Sum => ({ snapshots: 0, logical: 0, data_in: 0, stored: 0 });
  const all = zero();
  const perTenant = new Map<string, Sum>();
  const perGroup = new Map<string, { tenant: string; group_id: number | null; group: string | null; sum: Sum; sources: Set<string> }>();
  for (const s of snaps) {
    const key = `${s.tenant}/${s.source}`;
    const rate = 0.02 + (hash(s.source.length, s.time % 97) % 5) / 100;
    const dataIn = s.size * (seen.has(key) ? rate : 0.55);
    seen.add(key);
    const comp = COMPRESSION.find(([p]) => s.source.startsWith(p))![1];
    const g = groupOfSource(s.tenant, s.source);
    const gk = `${s.tenant}/${g?.id ?? '-'}`;
    if (!perGroup.has(gk)) perGroup.set(gk, { tenant: s.tenant, group_id: g?.id ?? null, group: g?.name ?? null, sum: zero(), sources: new Set() });
    if (!perTenant.has(s.tenant)) perTenant.set(s.tenant, zero());
    const pg = perGroup.get(gk)!;
    pg.sources.add(s.source);
    for (const x of [all, perTenant.get(s.tenant)!, pg.sum]) {
      x.snapshots += 1;
      x.logical += s.size;
      x.data_in += dataIn;
      x.stored += dataIn / comp;
    }
  }
  // the whole store: Stored ≈ 97 % of the bytes on disk (the rest is indexes and manifests)
  const sizeOf = (n?: string) => kept.filter((s) => !n || s.tenant === n).reduce((a, s) => a + s.size, 0);
  const allBytes = sizeOf() || 1;
  const k = (storeUsedAt(0) * 0.97 * (all.logical / allBytes)) / (all.stored || 1);
  const tenants = db.tenants.map((x) => x.name).filter((n) => !u.tenant || n === u.tenant);
  const usedOf = (n: string) => Math.round((storeUsedAt(0) * sizeOf(n)) / allBytes);
  const total = u.tenant ? (perTenant.get(u.tenant) ?? zero()) : all;
  const growth = (used: number) => {
    const at = (d: number) => Math.round(used - (used * (0.78 - 0.0011 * d)) / 0.78);
    return { d7: at(7), d30: at(30), d90: at(90) };
  };
  const usedTotal = tenants.reduce((a, n) => a + usedOf(n), 0);
  const share = usedTotal / storeUsedAt(0);
  const tot = sumJson(total, k);
  return {
    generated: t,
    totals: { ...tot, snapshots_all: kept.filter((s) => !u.tenant || s.tenant === u.tenant).length, used: usedTotal, growth: growth(usedTotal) },
    tenants: tenants.map((n) => {
      const used = usedOf(n);
      const q = db.tenants.find((x) => x.name === n)?.quota_bytes ?? null;
      return { tenant: n, ...sumJson(perTenant.get(n) ?? zero(), k), used, quota_bytes: q, quota_used: q ? +(used / q).toFixed(4) : null, growth: growth(used) };
    }),
    groups: [...perGroup.values()]
      .filter((g) => !u.tenant || g.tenant === u.tenant)
      .sort((a, b) => a.tenant.localeCompare(b.tenant) || (a.group_id ?? 1e9) - (b.group_id ?? 1e9))
      .map((g) => ({ tenant: g.tenant, group_id: g.group_id, group: g.group, sources: g.sources.size, ...sumJson(g.sum, k) })),
    per_day: Array.from({ length: 90 }, (_, i) => 89 - i).map((d) => {
      const used = Math.round(storeUsedAt(d) * share);
      return { day: isoDay(Math.floor(t / DAY) * DAY - d * DAY), used, logical: Math.round(used * 0.97 * (tot.reduction ?? 1)) };
    }),
  };
}
on('GET', '/storage', (c) => [200, storageStats(need(c.user))]);
on('PUT', '/tenants/:name/quota', async (c, [name]) => {
  const u = need(c.user, 'admin');
  const x = find(db.tenants, (y) => y.name === decodeURIComponent(name), 'tenant');
  const q = c.body.quota_bytes;
  if (q !== null && !(Number.isInteger(q) && q > 0)) throw new HttpError(400, 'quota_bytes: a positive number of bytes, or null');
  x.quota_bytes = q;
  await audit(u.name, 'tenant.quota', `tenant/${x.name}`, { name: x.name, quota_bytes: q });
  return [200, { name: x.name, quota_bytes: q }];
});
on('GET', '/settings/anomaly', (c) => (need(c.user, 'admin', 'security_officer'), [200, db.anomaly]));
on('PUT', '/settings/anomaly', async (c) => {
  const u = need(c.user, 'admin');
  const { enabled, factor, history, floor_bytes, ...rest } = c.body;
  if (Object.keys(rest).length) throw new HttpError(400, `unknown field \`${Object.keys(rest)[0]}\``);
  if (typeof enabled !== 'boolean') throw new HttpError(400, 'enabled: boolean required');
  if (!(factor >= 1.5 && factor <= 100)) throw new HttpError(400, 'factor: 1.5..=100');
  if (!(Number.isInteger(history) && history >= 5 && history <= 100)) throw new HttpError(400, 'history: 5..=100 runs');
  if (!(Number.isInteger(floor_bytes) && floor_bytes >= 2 ** 20 && floor_bytes <= 2 ** 50)) throw new HttpError(400, 'floor_bytes: 1 MiB..=1 PiB');
  const next = { enabled, factor, history, floor_bytes };
  const old = db.anomaly;
  // weakening the detection (a ransomware signal) needs approval
  if ((old.enabled && !enabled) || factor > old.factor || floor_bytes > old.floor_bytes)
    return quorum(u, 'settings.anomaly', { anomaly: next, old: structuredClone(old) });
  db.anomaly = next;
  await audit(u.name, 'settings.anomaly', 'settings/anomaly', next);
  return [200, next];
});

const dashCache = new Map<string, { at: number; body: Json }>();
on('GET', '/dashboard', (c) => {
  const u = need(c.user);
  const days = c.query.get('days') === '7' ? 7 : 30;
  const key = `${u.tenant ?? '*'}/${days}`;
  const hit = dashCache.get(key);
  if (hit && now() - hit.at < 60) return [200, hit.body];
  const body = dashboard(u, days);
  dashCache.set(key, { at: now(), body });
  return [200, body];
});

// ---- OIDC (§2). The mock has no identity provider: "start" goes straight to the callback, which
// signs in as the SSO demo user lwagner (Keycloak groups: nexus-operators).
const MAPPING_ROLES = ['admin', 'security_officer', 'operator', 'tenant_user'];
const pubOidc = () => {
  const { client_secret, ...rest } = db.oidc;
  return { ...structuredClone(rest), client_secret_set: !!client_secret };
};
on('GET', '/auth/oidc', () => [200, db.oidc.enabled ? { enabled: true, label: db.oidc.label } : { enabled: false }]);
on('GET', '/auth/oidc/start', (c) => {
  if (!db.oidc.enabled) {
    c.res.setHeader('Location', '/#/login?oidc_error=disabled');
    return [302, ''];
  }
  const next = String(c.query.get('next') ?? '/');
  c.res.setHeader('Location', `/api/v1/auth/oidc/callback?code=${rand(16)}&state=${encodeURIComponent(next)}`);
  return [302, ''];
});
on('GET', '/auth/oidc/callback', async (c) => {
  const claims = { sub: 'f3c1a9e2-5b7d-4e08-9a61-2d4c8b0e7f15', preferred_username: 'lwagner', groups: ['nexus-operators', 'staff'] };
  const fail = async (code: string) => {
    await audit(claims.preferred_username, 'auth.oidc_denied', 'session', { reason: code });
    c.res.setHeader('Location', `/#/login?oidc_error=${code}`);
    return [302, ''] as [number, unknown];
  };
  if (!db.oidc.enabled) return fail('disabled');
  const hits = (db.oidc.mappings as Json[]).filter((m) => claims.groups.includes(m.group));
  if (!hits.length) return fail('denied');
  const best = hits.sort((a, b) => MAPPING_ROLES.indexOf(a.role) - MAPPING_ROLES.indexOf(b.role))[0];
  let x = db.users.find((y) => y.auth === 'oidc' && y.oidc_sub === claims.sub);
  if (!x) {
    x = { id: nextId(), name: claims.preferred_username, role: best.role, tenant: null, disabled: false, created: now(), password: '', totp_secret: '', auth: 'oidc', oidc_sub: claims.sub };
    db.users.push(x);
    await audit('system', 'user.oidc_created', `user/${x.id}`, { name: x.name, role: x.role });
  }
  Object.assign(x, { role: best.role, tenant: best.tenants?.[0] ?? null });
  if (x.disabled) return fail('denied');
  const sid = rand(32);
  db.sessions.set(sid, { userId: x.id, csrf: rand(16), created: now(), last: now() });
  c.res.setHeader('Set-Cookie', `nx_session=${sid}; HttpOnly; SameSite=Lax; Path=/`);
  await audit(x.name, 'auth.oidc_login', 'session', { groups: claims.groups });
  const state = decodeURIComponent(String(c.query.get('state') ?? '/'));
  c.res.setHeader('Location', state.startsWith('/') && !state.startsWith('//') ? state : '/');
  return [302, ''];
});
on('GET', '/settings/oidc', (c) => (need(c.user, 'admin', 'security_officer'), [200, pubOidc()]));
on('PUT', '/settings/oidc', async (c) => {
  const u = need(c.user, 'admin');
  const b = c.body;
  if (typeof b.issuer !== 'string' || !/^https:\/\/[^\s/]+/.test(b.issuer)) throw new HttpError(400, 'issuer: https URL required');
  if (!String(b.client_id ?? '').trim()) throw new HttpError(400, 'client_id: required');
  if (!Array.isArray(b.scopes) || !b.scopes.includes('openid')) throw new HttpError(400, 'scopes: must include openid');
  if (!String(b.label ?? '').trim()) throw new HttpError(400, 'label: required');
  if (!Array.isArray(b.mappings)) throw new HttpError(400, 'mappings: array required');
  for (const m of b.mappings) {
    if (!String(m.group ?? '').trim()) throw new HttpError(400, 'mappings: group required');
    if (!MAPPING_ROLES.includes(m.role)) throw new HttpError(400, `mappings: unknown role ${m.role}`);
    if (!Array.isArray(m.tenants) || m.tenants.some((n: string) => !db.tenants.some((x) => x.name === n))) throw new HttpError(400, 'mappings: unknown tenant');
    if (m.role === 'tenant_user' && !m.tenants.length) throw new HttpError(400, 'mappings: tenant users need a tenant');
  }
  const next = {
    enabled: !!b.enabled, issuer: b.issuer, client_id: String(b.client_id).trim(), scopes: b.scopes, label: String(b.label).trim(),
    username_claim: String(b.username_claim || 'preferred_username'), groups_claim: String(b.groups_claim || 'groups'), mappings: b.mappings,
  };
  const secret = b.client_secret ? String(b.client_secret) : undefined;
  if (db.approvals) {
    const q = await quorum(u, 'oidc.update', { ...next, client_secret_changed: !!secret });
    if (secret) db.quorumSecrets.set(q[1].quorum_id, { client_secret: secret });
    return q;
  }
  Object.assign(db.oidc, next, secret ? { client_secret: secret } : {});
  await audit(u.name, 'settings.oidc', 'settings/oidc', { enabled: next.enabled, issuer: next.issuer, approvals: 'disabled' });
  return [200, pubOidc()];
});
on('POST', '/settings/oidc/test', (c) => {
  need(c.user, 'admin');
  const host = /^https:\/\/([^/]+)/.exec(String(db.oidc.issuer))?.[1] ?? '';
  if (/bad|invalid/.test(host)) return [200, { discovery: `error: ${host}: connection refused`, jwks: 'error: discovery failed' }];
  return [200, { discovery: `ok: ${db.oidc.issuer}/.well-known/openid-configuration`, jwks: 'ok: 2 signing keys (RS256)' }];
});

// ---- alert delivery (§3)
const pubAlerts = () => {
  const a = structuredClone(db.alertSettings);
  if (a.smtp) {
    a.smtp.password_set = !!a.smtp.password;
    delete a.smtp.password;
  }
  return a;
};
on('GET', '/settings/alerts', (c) => (need(c.user, 'admin', 'security_officer'), [200, pubAlerts()]));
on('PUT', '/settings/alerts', async (c) => {
  const u = need(c.user, 'admin');
  const b = c.body;
  if (b.webhook_url && !/^https:\/\/\S+$/.test(String(b.webhook_url))) throw new HttpError(400, 'webhook_url: https URL required');
  if (!['info', 'warning', 'critical'].includes(b.min_severity)) throw new HttpError(400, 'min_severity: info, warning or critical');
  let smtp = null;
  if (b.smtp) {
    const s = b.smtp;
    if (!String(s.host ?? '').trim()) throw new HttpError(400, 'smtp.host: required');
    if (!(Number.isInteger(s.port) && s.port > 0 && s.port < 65536)) throw new HttpError(400, 'smtp.port: 1..65535');
    if (!Array.isArray(s.to) || !s.to.length || s.to.some((x: string) => !/^[^@\s]+@[^@\s]+$/.test(x))) throw new HttpError(400, 'smtp.to: e-mail addresses required');
    if (!/^[^@\s]+@[^@\s]+$/.test(String(s.from ?? ''))) throw new HttpError(400, 'smtp.from: e-mail address required');
    smtp = { host: s.host, port: s.port, starttls: !!s.starttls, from: s.from, to: s.to, user: String(s.user ?? ''), password: s.password || db.alertSettings.smtp?.password || '' };
  }
  db.alertSettings = { webhook_url: b.webhook_url || null, smtp, min_severity: b.min_severity };
  await audit(u.name, 'settings.alerts', 'settings/alerts', { webhook: !!b.webhook_url, smtp: !!smtp, min_severity: b.min_severity });
  return [200, pubAlerts()];
});
on('POST', '/settings/alerts/test', async (c) => {
  const u = need(c.user, 'admin');
  const a = db.alertSettings;
  const out: Json = {};
  if (a.webhook_url) out.webhook = /bad|invalid/.test(a.webhook_url) ? 'error: HTTP 404 from the webhook' : 'ok';
  if (a.smtp) out.smtp = /bad|invalid/.test(a.smtp.host) ? `error: ${a.smtp.host}:${a.smtp.port}: connection refused` : 'ok';
  await audit(u.name, 'settings.alerts_test', 'settings/alerts', out);
  return [200, out];
});

// ---- appliance SSH keys (§4)
on('GET', '/ssh-keys', (c) => (need(c.user, 'admin', 'operator', 'security_officer'), [200, db.sshKeys]));
on('POST', '/ssh-keys/:name/rotate', (c, [name]) => {
  const u = need(c.user, 'admin');
  const k = find(db.sshKeys, (x) => x.name === name, 'ssh key');
  if (k.previous) throw new HttpError(409, 'retire the old key first');
  return quorum(u, 'ssh_key.rotate', { name: k.name, fingerprint: k.fingerprint });
});
on('POST', '/ssh-keys/:name/retire', async (c, [name]) => {
  const u = need(c.user, 'admin');
  const k = find(db.sshKeys, (x) => x.name === name, 'ssh key');
  if (!k.previous) throw new HttpError(409, 'there is no old key to retire');
  const old = k.previous.fingerprint;
  k.previous = null;
  await audit(u.name, 'ssh_key.retire', `ssh_key/${name}`, { fingerprint: old });
  return [200, k];
});

// ---- updates (§5)
const pubUpdates = () => {
  const x = db.updates;
  if (x.status === 'checking' && now() - x.checking_since >= 3) Object.assign(x, { status: x.staged ? 'staged' : 'idle', last_check: now() });
  const { checking_since: _c, ...rest } = x;
  return rest;
};
on('GET', '/updates', (c) => (need(c.user, 'admin', 'security_officer', 'operator'), [200, pubUpdates()]));
on('POST', '/updates/check', async (c) => {
  const u = need(c.user, 'admin');
  Object.assign(db.updates, { status: 'checking', checking_since: now() });
  await audit(u.name, 'update.check', 'updates', {});
  return [202, pubUpdates()];
});
on('POST', '/updates/apply', (c) => {
  const u = need(c.user, 'admin');
  if (!db.updates.available) throw new HttpError(409, 'no update available');
  if (db.updates.staged) throw new HttpError(409, 'an update is already staged');
  return quorum(u, 'update.apply', { version: db.updates.available.version, digest: db.updates.available.digest });
});

// ---------------------------------------------------------------- server glue

function readBody(req: Req): Promise<Uint8Array & { toString(enc: string): string }> {
  return new Promise((resolve) => {
    const parts: Uint8Array[] = [];
    req.on('data', (c) => c && parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts)));
  });
}
declare const Buffer: { concat(xs: Uint8Array[]): Uint8Array & { toString(enc: string): string } };

async function handle(req: Req, res: Res) {
  tick();
  const url = new URL(req.url ?? '/', 'http://x');
  const path = url.pathname.slice('/api/v1'.length) || '/';
  const method = req.method ?? 'GET';
  const send = (status: number, body: unknown, type = 'application/json') => {
    res.statusCode = status;
    res.setHeader('Content-Type', type);
    res.setHeader('Cache-Control', 'no-store');
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };
  try {
    const cookie = String(req.headers.cookie ?? '');
    const sid = /(?:^|;\s*)nx_session=([0-9a-f]+)/.exec(cookie)?.[1] ?? null;
    const sess = sid ? db.sessions.get(sid) : undefined;
    let user: User | null = null;
    if (sess) {
      if (now() - sess.last > 1800 || now() - sess.created > 12 * 3600) db.sessions.delete(sid!);
      else {
        sess.last = now();
        user = db.users.find((u) => u.id === sess.userId && !u.disabled) ?? null;
      }
    }
    if (method !== 'GET' && path !== '/auth/login' && !path.startsWith('/auth/activate/') && user && req.headers['x-csrf-token'] !== sess?.csrf) {
      throw new HttpError(403, 'CSRF token missing or invalid');
    }
    const dl = /^\/downloads\/([0-9a-f]+)$/.exec(path);
    if (dl && method === 'GET') {
      const u = need(user);
      const d = db.downloads.get(dl[1]);
      if (!d || d.expires < now()) throw new HttpError(404, 'download not found or expired');
      if (d.owner !== u.name) throw new HttpError(403, 'only the requester can download this file');
      res.setHeader('Content-Disposition', `attachment; filename="${d.filename}"`);
      return send(200, d.body, 'application/octet-stream');
    }
    const bytes = method === 'GET' ? null : await readBody(req);
    // Plugin uploads are raw bundles, everything else JSON.
    const raw = method === 'POST' && path === '/plugins' ? bytes : null;
    const text = bytes && !raw ? bytes.toString('utf8') : '';
    let body: Json = {};
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        throw new HttpError(400, 'invalid JSON');
      }
    }
    for (const [m, re, h] of routes) {
      const mm = method === m ? re.exec(path) : null;
      if (!mm) continue;
      const [status, out] = await h({ method, path, query: url.searchParams, body, raw, headers: req.headers, user, sid, res }, mm.slice(1));
      return send(status, out);
    }
    throw new HttpError(404, 'no such endpoint');
  } catch (e) {
    if (e instanceof HttpError) return send(e.status, { error: e.message });
    console.error(e);
    return send(500, { error: 'internal error' });
  }
}

export function mockApi(): Plugin {
  seed();
  // Audit entries for the seed, so the viewer and chain verification have data.
  const ready = (async () => {
    // a plausible history: first boot, configuration, approvals, replication, then the pending requests
    const t = now();
    const hist: [number, string, string, string, Json][] = [
      [t - 86400 * 90, 'setup', 'setup.network', '-', { method: 'static', address: '198.51.100.5/24' }],
      [t - 86400 * 90 + 60, 'setup', 'setup.keyd.init', '-', {}],
      [t - 86400 * 90 + 120, 'setup', 'setup.keyd.confirmed', '-', { recovery_key: 'shown once, re-entered' }],
      [t - 86400 * 90 + 180, 'setup', 'setup.tls', '-', { san: ['backup.example.com', '198.51.100.5'] }],
      [t - 86400 * 90 + 240, 'setup', 'setup.done', '-', { users: ['admin', 'so'] }],
      [t - 86400 * 89, 'admin', 'auth.login', 'session', {}],
      [t - 86400 * 89 + 300, 'admin', 'tenant.create', 'tenant/acme', {}],
      [t - 86400 * 89 + 400, 'admin', 'tenant.create', 'tenant/initech', {}],
      [t - 86400 * 60, 'admin', 'settings.approvals', 'settings/approvals', { enabled: true }],
      [t - 86400 * 41, 'admin', 'quorum.request', 'quorum/plugin_key.add', { action: 'plugin_key.add', publisher: 'example-labs' }],
      [t - 86400 * 41 + 900, 'so', 'quorum.approve', 'quorum/plugin_key.add', { action: 'plugin_key.add' }],
      [t - 86400 * 21, 'admin', 'quorum.request', 'quorum/replication_peer.create', { action: 'replication_peer.create', name: 'dr-site', tenants: ['acme'] }],
      [t - 86400 * 21 + 900, 'so', 'quorum.approve', 'quorum/replication_peer.create', { action: 'replication_peer.create' }],
      [t - 86400 * 20, 'system', 'replication_peer.enrolled', 'replication_peer/a1b2c3d4e5f60718', { name: 'dr-site' }],
      [t - 86400 * 20 + 900, 'so2', 'quorum.approve', 'quorum/replication.key_export', { action: 'replication.key_export' }],
      [t - 86400 * 9, 'so', 'quorum.reject', 'quorum/source.delete', { action: 'source.delete', name: 'old-esx-import' }],
      [t - 86400 - 7200, 'acme', 'job.create', 'job/files_get', { kind: 'files_get', tenant: 'acme', paths: ['/etc/nginx'], format: 'zip' }],
      [t - 86400 - 3600, 'admin', 'job.create', 'job/plugin_restore', { kind: 'plugin_restore', tenant: 'acme', restore: 'pitr' }],
      [t - 5400, 'admin', 'job.create', 'job/backup', { kind: 'backup', tenant: 'initech', params: { vmid: 101 } }],
      [t - 3605, 'unknown-user', 'auth.login_failed', 'session', {}],
    ];
    for (const q of [...db.quorum].filter((x) => x.state === 'pending').sort((a, b) => a.created - b.created))
      hist.push([q.created, q.requested_by, 'quorum.request', `quorum/${q.id}`, { action: q.action, params: q.params }]);
    hist.sort((a, b) => a[0] - b[0]);
    for (const [ts, actor, action, target, details] of hist) await audit(actor, action, target, details, ts);
  })();
  const mw = (req: Req, res: Res, next: () => void) => {
    if (!req.url?.startsWith('/api/v1/')) return next();
    // Small latency so loading states are visible.
    ready.then(() => setTimeout(() => void handle(req, res), 120));
  };
  return {
    name: 'nexus-mock-api',
    configureServer(server) {
      server.middlewares.use(mw as any);
    },
    configurePreviewServer(server) {
      server.middlewares.use(mw as any);
    },
  };
}
