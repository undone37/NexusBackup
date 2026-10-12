// In-memory mock of the /api/v1 contract (docs/control-plane.md) for `npm run dev`
// and `npm run preview`. Vite server middleware only — never part of the build output.
//
// Users (password "nexus", any 6-digit TOTP code): admin, so, so2, op, acme (tenant_user of "acme"),
// auditor (viewer, all tenants), acme-view (viewer of "acme").
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
// Phase 13b: the schedule grammar and blackout check the UI uses as well.
import { blackoutActive, isPaused, parseSchedule, schedulePeriod, validWindow, type BlackoutWindow } from '../src/lib/schedule.ts';

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

type Role = 'admin' | 'security_officer' | 'operator' | 'tenant_user' | 'viewer';
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
  /** Phase 14d: explicit download privilege (unset = the role's default), expiry, last sign-in */
  can_download?: boolean | null;
  expires?: number | null;
  last_login?: number | null;
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
  /** Phase 15f: limits, certificate validity, unconfirmed renewal */
  limits: { bwlimit?: number; nice?: number };
  cert_issued: number | null;
  cert_expires: number | null;
  cert_renewal_pending: boolean;
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
  /** Phase 13b: retry chain, retry delay, cancel request of a running job */
  attempt?: number;
  retry_of?: number | null;
  not_before?: number | null;
  cancel_by?: string | null;
  cancel_at?: number;
}

interface MockGroup {
  id: number;
  tenant: string;
  source_id: number;
  policy_id: number;
  name: string;
  guests: (number | string)[];
  mode: 'explicit' | 'all' | 'tags';
  selector: string[];
  exclude: string[];
  /** Phase 13b */
  timezone?: string;
  paused_until?: number | null;
  /** Phase 15g: index the files of VM/CT disks after each backup */
  index_files?: boolean;
  /** Phase 15e/f */
  exclude_disks?: Record<string, string[]>;
  exclude_disks_mode?: 'placeholder' | 'omit';
  parallel_guests?: number;
}
interface InvRow {
  guest: string;
  name: string;
  kind: string;
  tags: string[];
  seen: number;
  gone: number | null;
}

const db = {
  users: [] as User[],
  tenants: [] as { name: string; offsite: Json; quota_bytes?: number | null }[],
  /** kind: pve | linux | nfs | smb | plugin:<kind> */
  sources: [] as { id: number; tenant: string; kind: string; name: string; config: Json; maintenance_until?: number | null }[],
  agents: [] as Agent[],
  replPeers: [] as Json[],
  replSources: [] as Json[],
  policies: [] as {
    id: number;
    name: string;
    schedule: string;
    gfs: Json;
    offsite: boolean;
    retry?: { count: number; delay_min: number };
    blackout?: BlackoutWindow[];
    sla_minutes?: number | null;
    require_consistency?: { mode: string; level: string };
    file_filters?: { exclude: string[]; exclude_regex: string[] };
  }[],
  groups: [] as MockGroup[],
  /** Phase 13c: guest inventory per source id (GET /sources/{id}/inventory) */
  inventory: new Map<number, InvRow[]>(),
  jobs: [] as Job[],
  snapshots: [] as Json[],
  /** Phase 15c legal holds (catalog v18 `legal_holds`, with history) */
  holds: [] as Json[],
  quorum: [] as Json[],
  audit: [] as Json[],
  alerts: [] as Json[],
  sessions: new Map<string, { id: number; userId: number; csrf: string; created: number; last: number; ip: string; ua: string }>(),
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
  pullAuth: null as null | { username: string },
  /** Phase 14b diagnostics runs (GET /diagnostics) */
  diag: [] as Json[],
  /** Phase 13e setting `anomaly` */
  anomaly: { enabled: true, factor: 3, history: 14, floor_bytes: 2 ** 30 } as Json,
  /** Phase 14a setting `forwarding` (header values: plaintext here, null in responses) */
  forwarding: {
    syslog: { enabled: true, host: 'siem.example.com', port: 6514, ca_pem: null, pin_sha256: '3f'.repeat(32), app_name: 'nexus', facility: 13 },
    https: null,
  } as Json,
  /** last delivery error per sink (none = the forwarder keeps up) */
  forwardErr: {} as Record<string, string>,
  /** Phase 14d settings `session`, `dormant_days`, `login_banner` (`mgmt_allow` = firewall.web.allow since 16c) */
  security: {
    session: { idle_min: 30, absolute_h: 12 },
    dormant_days: 90,
    login_banner: 'Authorised use only. Activity on this appliance is recorded in a tamper-evident audit log.',
  },
  /** Phase 16c setting `inbound`: per-service source lists (empty = any) */
  firewall: {
    web: { allow: ['198.51.100.0/24', '192.0.2.0/24'], enabled: true },
    icmp: { allow: [] as string[], enabled: false },
  } as Record<string, { allow: string[]; enabled: boolean }>,
  /** Phase 14e setting `reports` (scheduled reports) */
  reports: [] as Json[],
  /** Phase 16a/b: nexus-disks status (GET /hardware) */
  hardware: {} as Json,
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
      { files_list: 3, files_get: 5, backup: 12, restore: 16, restore_ct: 12, instant_recover: 10, restore_files: 8, agent_enroll: 5, agent_update: 6, agent_renew: 4 }[kind] ?? 8,
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
    case 'inventory':
      return psrc?.kind === 'pve'
        ? [`nexus-pve inventory: GET /cluster/resources?type=vm on ${psrc.config.host}`, `${db.inventory.get(psrc.id)?.length ?? 0} guests`, 'inventory updated']
        : psrc?.kind === 'truenas'
          ? [`datasets of source ${psrc.name} (catalog)`, 'inventory updated']
          : [`starting nexus-pluginhost for ${psrc?.kind} (source ${psrc?.name})`, 'ListGuests', 'inventory updated'];
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
        ...(/^(vm|ct)-/.test(src)
          ? [
              `nexus-pve ${src.startsWith('ct-') ? 'ct-files' : 'files'} ${src.slice(3)} ${p.time} get <downloads>/restore-<job>.tar ${(p.paths ?? []).join(' ')}`,
              'restore VM booted in 1.9s, 2 file systems mounted read-only',
            ]
          : []),
        `connecting to agent ${agName} over mTLS`,
        `RestoreBegin target=${p.target} overwrite=${p.overwrite} confirm="${p.confirm}"`,
        `reading ${src} @ ${p.time}: ${(p.paths ?? []).join(', ')}`,
        'restored 1,284 files (48.2 MiB), skipped 3 existing files',
        ...(src === `host-${p.agent_id}`
          ? []
          : ['restore to another host: skipped 0 entries (devices, sockets, alternate data streams) and 12 xattrs the target cannot take']),
        `restore to ${p.target} finished`,
      ];
    case 'agent_enroll':
      return [
        `connecting to ${agName} with the one-time token`,
        'token proof verified (bound to the TLS session)',
        'issued client certificate, pinned agent certificate',
        'agent enrolled',
      ];
    case 'agent_renew':
      return [
        `session with ${agName}: RenewCert`,
        'agent generated a new key pair, CSR received',
        'signed (CN nexus-agent:<id>, 10 years); new fingerprint accepted as a second pin',
        'agent swapped key and certificate (RenewOk); confirmed with a new session',
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
    case 'restore':
    case 'restore_ct': {
      const ct = kind === 'restore_ct';
      const vmid = String(src).slice(3);
      const name = p.name ?? `${p.name_prefix ?? ''}${ct ? 'ct' : 'vm'}${vmid}${p.name_prefix ? '' : '-restore'}`;
      return [
        `restoring ${src} @ ${p.time} as ${ct ? 'CT' : 'VM'} ${p.target} (${name}) on ${p.node}, storage ${p.storage}${p.pool ? `, pool ${p.pool}` : ''}`,
        ct ? 'streaming the container archive' : 'serving disks over NBD: drive-scsi0',
        `restored ${ct ? 'lxc' : 'qemu'} ${p.target} (${name})`,
        ...(p.link_down ? [`NICs of ${p.target}: link_down=1`] : []),
        ...(p.replace
          ? [
              `original ${ct ? 'lxc' : 'qemu'} ${vmid} stopped, renamed ${ct ? 'ct' : 'vm'}${vmid}-replaced-202610122130, onboot 0${p.keep_original_links ? '' : ', NICs link_down'}; ${p.target} is now ${ct ? 'ct' : 'vm'}${vmid}`,
            ]
          : []),
        ...(p.start || p.replace ? [`${p.target} started`] : []),
      ];
    }
    case 'instant_recover':
      return [
        `exporting ${src} @ ${p.time} via NBD over SSH to ${p.node}`,
        `creating qcow2 overlay, VM ${p.target}${p.link_down ? ' (NICs link_down)' : ''}`,
        p.start === false ? 'VM created switched off; moving disks offline' : 'VM started from backup',
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
    if (j.state === 'queued' && t - j.created >= 1 && !(j.not_before && j.not_before > t)) {
      j.state = 'running';
      j.started = t;
    }
    if (j.state !== 'running' || j.started === null) continue;
    if (j.cancel_by && t - (j.cancel_at ?? t) >= 2) {
      Object.assign(j, { state: 'cancelled', finished: t });
      j.log += `\n[scheduler] cancelled (requested by ${j.cancel_by})`;
      continue;
    }
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
      if (j.kind === 'inventory' || j.kind === 'plugin_guests') inventoryResult(j, t);
      if (j.kind === 'report_send') reportSent(j);
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
      if (j.kind === 'agent_renew' && ag)
        Object.assign(ag, { cert_sha256: rand(32), cert_issued: t, cert_expires: t + 3650 * 86400, cert_renewal_pending: false, last_seen: t });
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
        const guests = resolveGuests(pgroup);
        const names = guests.length ? guests.map((g) => `plugin-${pid}-${psrc.id}-${g}`) : pgroup.mode === 'explicit' ? [`plugin-${pid}-${psrc.id}`] : [];
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
              ? resolveGuests(g!).map((d) => `nas-${gsrc.id}-${String(d).replaceAll('/', '.')}`)
              : (j.params.vmid ? [j.params.vmid] : j.params.agent_id ? [j.params.agent_id] : g ? resolveGuests(g) : []).map(guestName);
        for (const n of names) db.snapshots.push(snap(j.tenant, n, t, 64 << 30, true, false, null));
        // Phase 15g: groups with index_files list the guests' file systems after the backup
        if (g?.index_files && gsrc?.kind === 'pve')
          for (const n of names) {
            const x = addJob('file_index', j.tenant, { source: n, time: t, source_id: gsrc.id }, 'scheduler');
            x.plan = [`booting the restore micro-VM for ${n} @ ${t}`, 'walking the guest file systems', 'file index sealed and written'];
          }
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
/** Phase 15d demo levels: VMs quiesced by the guest agent (vm-101: agent not running), containers and
 * NAS snapshots crash-consistent, agents and plugins application-consistent (hooks / VSS / dumps). */
const levelOf = (source: string) =>
  source === 'vm-101' || /^(ct|nas|share)-/.test(source) ? 'crash' : /^(vm|host|plugin)-/.test(source) ? 'application' : 'unknown';
const snap = (tenant: string, source: string, time: number, size: number, local: boolean, offsite: boolean, verified: number | null) => ({
  tenant,
  source,
  time,
  size,
  local,
  offsite,
  lock_until: time + 14 * 86400,
  verified,
  consistency: levelOf(source),
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
    mk('auditor', 'viewer', null, t - 86400 * 30),
    mk('acme-view', 'viewer', 'acme', t - 86400 * 30),
  );
  for (const u of db.users) u.last_login = t - 86400 * 2;
  // a contractor account with an end date and no download privilege
  const contractor = mk('contractor', 'operator', null, t - 86400 * 20);
  Object.assign(contractor, { can_download: false, expires: day(-30, 0), last_login: t - 86400 * 5 });
  db.users.push(contractor);
  // the admin's other sessions (Account → Sessions)
  const admin0 = db.users[0];
  db.sessions.set('a1'.repeat(32), { id: 1, userId: admin0.id, csrf: 'x', created: t - 3 * 3600, last: t - 1200, ip: '198.51.100.23', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0' });
  db.sessions.set('b2'.repeat(32), { id: 2, userId: admin0.id, csrf: 'x', created: t - 7 * 3600, last: t - 5400, ip: '192.0.2.40', ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15' });
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
    limits: {},
    cert_issued: state === 'enrolled' ? t - 86400 * 20 : null,
    cert_expires: state === 'enrolled' ? t - 86400 * 20 + 3650 * 86400 : null,
    cert_renewal_pending: false,
  });
  const web01 = agent('acme', 'web01', '198.51.100.31', 'enrolled', 'Debian GNU/Linux 13 (trixie)');
  const fs02 = agent('acme', 'fs02', 'fs02.acme.example.com', 'enrolled', 'Windows Server 2022 Standard (10.0.20348)');
  // Phase 15f: web01 is throttled during business-hours backups
  web01.limits = { bwlimit: 20 * 1024 * 1024, nice: 10 };
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

  const grp = (tenant: string, source_id: number, policy_id: number, name: string, guests: (number | string)[], auto: Partial<MockGroup> = {}): MockGroup => ({
    id: nextId(), tenant, source_id, policy_id, name, guests, mode: 'explicit', selector: [], exclude: [],
    exclude_disks: {}, exclude_disks_mode: 'placeholder', parallel_guests: 1, ...auto,
  });
  // Phase 15e/f: the scratch disk of the ERP database is not backed up, two guests at once
  const gProd = grp('initech', sInitech.id, gold.id, 'production', [100, 101, 200], {
    exclude_disks: { '101': ['scsi2'] },
    index_files: true,
    parallel_guests: 2,
  });
  // auto-protect (Phase 13c): every guest of the PVE pool "dev" except the build runner
  const gDev = grp('initech', sInitech.id, bronze.id, 'development', [], { mode: 'tags', selector: ['pool:dev'], exclude: ['105'] });
  const gAcmeVms = grp('acme', sAcme.id, silver.id, 'acme-vms', [300, 301]);
  const gSmb = grp('acme', sSmb.id, bronze.id, 'acme-fs01', []);
  const gDbs = grp('acme', sPg.id, hourly.id, 'acme-databases', ['shop', 'crm']);
  db.groups.push(
    gProd,
    gDev,
    gAcmeVms,
    grp('acme', sWeb01.id, silver.id, 'acme-web01', [web01.id]),
    grp('acme', sFs02.id, silver.id, 'acme-fs02', [fs02.id]),
    grp('acme', sNas01.id, silver.id, 'acme-nas01', [], { mode: 'all' }),
    grp('acme', sNfs.id, silver.id, 'acme-filer', []),
    gSmb,
    gDbs,
    grp('acme', sPg.id, silver.id, 'acme-pg-cluster', []),
    grp('acme', sNas02.id, silver.id, 'acme-nas02', ['tank.media']),
  );
  // guest inventory (scheduler `inventory` jobs, 20 minutes ago)
  const inv = (sid: number, rows: [string, string, string, string[]][]) =>
    db.inventory.set(sid, rows.map(([guest, name, kind, tags]) => ({ guest, name, kind, tags, seen: t - 1200, gone: null })));
  const vm = (node: string, ...more: string[]) => ['type:qemu', `node:${node}`, ...more];
  inv(sInitech.id, [
    ['100', 'erp-app', 'qemu', vm('pve1', 'pool:prod', 'tag:erp')],
    ['101', 'erp-db', 'qemu', vm('pve1', 'pool:prod', 'tag:erp')],
    ['102', 'dev-sandbox', 'qemu', vm('pve2', 'pool:dev')],
    ['103', 'legacy-ftp', 'qemu', vm('pve2')],
    ['105', 'build-runner', 'qemu', vm('pve2', 'pool:dev', 'tag:ci')],
    ['200', 'proxy', 'lxc', ['type:lxc', 'node:pve1', 'pool:prod', 'tag:web']],
  ]);
  inv(sAcme.id, [
    ['300', 'shop-web', 'qemu', vm('acme-pve1', 'tag:shop')],
    ['301', 'shop-api', 'qemu', vm('acme-pve1', 'tag:shop')],
    ['302', 'test-web', 'qemu', vm('acme-pve1', 'tag:test')],
  ]);
  inv(sNas01.id, [
    ['tank/projects', 'tank/projects', 'dataset', ['pool:tank']],
    ['tank/home', 'tank/home', 'dataset', ['pool:tank']],
  ]);
  inv(sPg.id, [
    ['shop', 'shop', '', []],
    ['crm', 'crm', '', []],
    ['analytics', 'analytics (reporting)', '', []],
  ]);
  inv(sNas02.id, [
    ['tank.media', 'tank/media (/mnt/tank/media)', '', []],
    ['tank.archive', 'tank/archive (/mnt/tank/archive)', '', []],
    ['tank.vm-images', 'tank/vm-images (/mnt/tank/vm-images)', '', []],
  ]);

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
  // (13f lifecycle: repeats counted on the open alert, success paths resolve them)
  db.alerts.push(
    mkAlert({
      ts: nightly.finished! - 2 * 86400, last_ts: nightly.finished, count: 3, severity: 'critical', kind: 'job_failed',
      key: `job_failed:initech/backup/group/${gProd.id}`, tenant: 'initech', message: `backup job ${nightly.id} (initech) failed: ${fleecing}`,
    }),
    mkAlert({
      ts: retry.finished, severity: 'critical', kind: 'job_failed', key: 'job_failed:initech/backup/vmid/101', tenant: 'initech',
      message: `backup job ${retry.id} (initech) failed: ${fleecing}`,
    }),
    mkAlert({ ts: t - 3 * 86400, last_ts: t - 1800, count: 147, severity: 'warning', kind: 'capacity', key: 'capacity', message: 'store capacity above 75 % (now 78 %)' }),
    mkAlert({
      ts: smbJob.finished, severity: 'warning', kind: 'backup_inconsistent', key: `backup_inconsistent:share-${sSmb.id}: no snapshot`,
      message: `share-${sSmb.id} — read without a NAS snapshot: not point-in-time consistent (backup job ${smbJob.id}, tenant acme, snapshot share-${sSmb.id})`,
      acked_by: 'op', note: 'Storage team enables NAS snapshots on fs01 next week.',
    }),
    mkAlert({
      ts: t - 86400 * 3, last_ts: t - 86400 * 2, count: 96, severity: 'warning', kind: 'offsite_lag', key: 'offsite_lag:acme', tenant: 'acme',
      message: 'offsite copy of tenant acme lags by 73 h (oldest snapshot not offsite: 1759500000)', resolved_at: t - 86400 * 2 + 300, resolved_by: 'scheduler', auto: true,
    }),
    mkAlert({
      ts: t - 86400 * 6, last_ts: t - 86400 * 5, count: 40, severity: 'warning', kind: 'replication_lag', key: 'replication_lag:hq-primary:globex', tenant: 'globex',
      message: 'replication of tenant globex from hq-primary lags: no successful sync for 50 h', acked_by: 'admin',
      resolved_at: t - 86400 * 5, resolved_by: 'admin', note: 'Primary was in a maintenance window; the next sync caught up.',
    }),
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
  db.alerts.push(
    mkAlert({
      ts: gcq.created, severity: 'warning', kind: 'gc_quorum', key: 'gc_quorum:initech', tenant: 'initech',
      message: `GC for tenant initech needs approval by an admin or security officer (quorum request ${gcq.id}): GC would delete 34 % of the stored chunks (limit 20 %)`,
    }),
  );
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
  seedRunControl(t);
  seedPhase14d2(t);
  seedReports(t);
  seedDiag(t);
  seedConsole(t);
  seedHolds(t);
  seedHardware(t);
}

// ---------------------------------------------------------------- run control (Phase 13b)

/** Policy run-control fields as the web-api validates them (defaults: 3 retries 5 min apart, no blackout, no SLA). */
function runControl(b: Json): {
  retry: { count: number; delay_min: number };
  blackout: BlackoutWindow[];
  sla_minutes: number | null;
  require_consistency: { mode: string; level: string };
  file_filters: { exclude: string[]; exclude_regex: string[] };
} {
  if (!parseSchedule(String(b.schedule ?? ''))) throw new HttpError(400, `schedule: bad schedule ${JSON.stringify(b.schedule)}`);
  const retry = b.retry ?? { count: 3, delay_min: 5 };
  if (!(retry.count >= 0 && retry.count <= 10 && retry.delay_min >= 1 && retry.delay_min <= 1440))
    throw new HttpError(400, 'retry: count 0..=10, delay_min 1..=1440');
  const blackout: BlackoutWindow[] = (b.blackout ?? []).map((w: Json) => ({ days: w.days ?? [], from: w.from, to: w.to, abort: !!w.abort }));
  if (blackout.length > 20 || !blackout.every(validWindow)) throw new HttpError(400, 'blackout: from/to must be different HH:MM times');
  const sla = b.sla_minutes ?? null;
  if (sla !== null && !(sla >= 1 && sla <= 10080)) throw new HttpError(400, 'sla_minutes: 1..=10080');
  // Phase 15d
  const rc = { mode: 'off', level: 'crash', ...(b.require_consistency ?? {}) };
  if (!['off', 'warn', 'fail'].includes(rc.mode) || !['application', 'crash'].includes(rc.level))
    throw new HttpError(400, 'require_consistency: mode off|warn|fail, level application|crash');
  // Phase 15e: global file excludes
  const ff = b.file_filters ?? {};
  for (const k of Object.keys(ff)) if (!['exclude', 'exclude_regex'].includes(k)) throw new HttpError(400, `file_filters: unknown field "${k}"`);
  const list = (v: unknown, what: string) => {
    if (!Array.isArray(v ?? []) || ((v ?? []) as unknown[]).some((x) => typeof x !== 'string' || !x.trim())) throw new HttpError(400, `${what}: non-empty patterns`);
    return (v ?? []) as string[];
  };
  const file_filters = { exclude: list(ff.exclude, 'file_filters.exclude'), exclude_regex: list(ff.exclude_regex, 'file_filters.exclude_regex') };
  return { retry, blackout, sla_minutes: sla, require_consistency: { mode: rc.mode, level: rc.level }, file_filters };
}

function checkTz(tz: unknown): string {
  const z = tz === undefined ? 'UTC' : String(tz);
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: z });
  } catch {
    throw new HttpError(400, `timezone: unknown time zone "${z}"`);
  }
  return z;
}

/** GET /groups: run state (paused, source maintenance, active blackout window). */
function groupState(g: (typeof db.groups)[number]) {
  const pol = db.policies.find((p) => p.id === g.policy_id);
  const src = db.sources.find((s) => s.id === g.source_id);
  return {
    ...g,
    timezone: g.timezone ?? 'UTC',
    paused_until: g.paused_until ?? null,
    index_files: g.index_files ?? false,
    maintenance_until: src?.maintenance_until ?? null,
    blackout_active: blackoutActive(pol?.blackout ?? [], g.timezone ?? 'UTC', now()),
    resolved_guests: resolveGuests(g),
  };
}

/** "Back up now" params: `guests` (a subset of the group's) or `failed_only` (from the last failed run). */
function backupGuests(p: Json) {
  if (p.group_id === undefined) {
    if (p.guests !== undefined || p.failed_only) throw new HttpError(400, 'params: guests and failed_only need group_id');
    return;
  }
  const g = find(db.groups, (x) => x.id === p.group_id, 'group');
  if (p.failed_only) {
    if (p.guests !== undefined) throw new HttpError(400, 'params: guests or failed_only, not both');
    const last = db.jobs
      .filter((j) => j.kind === 'backup' && j.params.group_id === g.id && (j.state === 'ok' || j.state === 'failed'))
      .sort((a, b) => b.id - a.id)[0];
    if (last?.state !== 'failed') throw new HttpError(409, "the group's last run did not fail");
    delete p.failed_only;
    if (Array.isArray(last.result?.failed_guests)) p.guests = last.result.failed_guests;
    return;
  }
  if (p.guests !== undefined && (!Array.isArray(p.guests) || !p.guests.length || p.guests.some((x: unknown) => !resolveGuests(g).includes(x as never))))
    throw new HttpError(400, "guests: a non-empty subset of the group's guests");
}

/** Demo state: retries, blackout window, SLA, a paused group, a source in maintenance, a retry chain. */
function seedRunControl(t: number) {
  for (const p of db.policies)
    Object.assign(p, { retry: { count: 3, delay_min: 5 }, blackout: [], sla_minutes: null, require_consistency: { mode: 'off', level: 'crash' }, ...p });
  const pol = (n: string) => db.policies.find((p) => p.name === n)!;
  pol('gold').retry = { count: 2, delay_min: 10 };
  pol('gold').sla_minutes = 240;
  pol('gold').require_consistency = { mode: 'warn', level: 'application' };
  pol('bronze').blackout = [{ days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'], from: '07:00', to: '19:00', abort: true }];
  pol('databases-hourly').schedule = 'every 2h at 15';
  pol('databases-hourly').sla_minutes = 20;
  pol('silver').schedule = 'Mon-Sat 22:00';
  for (const g of db.groups) Object.assign(g, { timezone: g.tenant === 'initech' ? 'Europe/Berlin' : 'UTC', paused_until: null, ...g });
  const grp = (n: string) => db.groups.find((g) => g.name === n)!;
  const nas02 = grp('acme-nas02');
  nas02.paused_until = -1;
  const fs02 = db.sources.find((s) => s.name === 'fs02-files');
  if (fs02) fs02.maintenance_until = t + 2 * DAY;
  // the nightly production run failed for vm-101: retried for that guest only
  const prod = grp('production');
  const first = db.jobs.find((j) => j.kind === 'backup' && j.params.group_id === prod.id && j.state === 'failed');
  if (first) {
    first.result = { failed_guests: [101] };
    first.log += `\n[scheduler] attempt 1 of 3 failed; retry as job ${db.seq + 1} in 10 min for [101]`;
    const second = addJob('backup', 'initech', { group_id: prod.id, guests: [101] }, 'scheduler', { attempt: 2, retry_of: first.id });
    Object.assign(second, {
      created: (first.finished ?? t) + 1, started: (first.finished ?? t) + 600, finished: (first.finished ?? t) + 640, state: 'failed', plan: [],
      result: { failed_guests: [101] },
      log: ['starting backup of vm-101 via node pve2', 'ERROR: vm-101: fleecing storage local-lvm on pve2 is full (98 %)', `[scheduler] attempt 2 of 3 failed; retry as job ${db.seq + 1} in 10 min for [101]`].join('\n'),
    });
    const third = addJob('backup', 'initech', { group_id: prod.id, guests: [101] }, 'scheduler', { attempt: 3, retry_of: first.id });
    Object.assign(third, { created: (second.finished ?? t) + 1, not_before: t + 8 * 60 });
  }
  db.alerts.push(
    mkAlert({ ts: t - 7 * 3600, severity: 'warning', kind: 'paused', key: `paused:group:${nas02.id}:-1`, tenant: 'acme', message: `group ${nas02.id} acme-nas02 (acme) paused until further notice: no scheduled backups meanwhile` }),
    mkAlert({
      ts: t - 26 * 3600, severity: 'warning', kind: 'sla_missed', key: 'sla_missed:4690', tenant: 'acme', resolved_at: t - 25 * 3600, resolved_by: 'op',
      message: `backup job 4690 of group acme-databases (acme) still running after 21 min (SLA 20 min)`,
    }),
  );
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
  can_download: canDownload(u),
  expires: u.expires ?? null,
  last_login: u.last_login ?? null,
});
const canDownload = (u: User) => u.can_download ?? ['admin', 'operator', 'tenant_user'].includes(u.role);
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
// (console.unlock: nobody executes it; the requester then fetches the code once, 14c)
const SCHEDULER_ACTIONS = ['replication.key_export', 'gc_large', 'console.unlock'];
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
    execute(0, action, params, u.name, u.name);
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
  ['daily', 'weekly', 'monthly', 'yearly'].some((k) => Number(b.gfs?.[k]) < Number(a.gfs?.[k])) ||
  // Phase 15e: a new global exclude backs up less
  (['exclude', 'exclude_regex'] as const).some((k) =>
    (b.file_filters?.[k] ?? []).some((x: string) => !(a.file_filters?.[k] ?? []).includes(x)),
  ) ||
  (a.offsite && !b.offsite) ||
  // Phase 13b: a new blackout window means fewer runs
  (b.blackout ?? []).some((w: Json) => !(a.blackout ?? []).some((x: Json) => JSON.stringify(x) === JSON.stringify(w))) ||
  // Phase 15d: a relaxed consistency requirement
  (b.require_consistency &&
    (['off', 'warn', 'fail'].indexOf(b.require_consistency.mode) < ['off', 'warn', 'fail'].indexOf(a.require_consistency?.mode ?? 'off') ||
      (b.require_consistency.mode !== 'off' && a.require_consistency?.level === 'application' && b.require_consistency.level === 'crash')));
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
    case 'security.session':
      db.security.session = structuredClone(p.session);
      break;
    case 'security.mgmt_allow':
      db.firewall.web.allow = [...p.mgmt_allow];
      break;
    case 'firewall.inbound':
      if (JSON.stringify(db.firewall[p.service]) !== JSON.stringify(p.old))
        throw new HttpError(409, 'the rule changed since this request was made; reject it and request the change again');
      db.firewall[p.service] = structuredClone(p.rule);
      break;
    case 'settings.forwarding':
      db.forwarding = structuredClone(p.forwarding);
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
    case 'restore.replace': {
      // the scheduler queues the restore job with replace (crates/scheduler/src/restore.rs)
      addJob(p.kind, p.tenant, { ...p.params, replace: true, quorum_id: qid, requested_by: by }, 'scheduler');
      break;
    }
    case 'snapshot.hold_release': {
      const h = find(db.holds, (x) => x.id === p.hold_id && x.state === 'active', 'active hold');
      Object.assign(h, { state: 'released', released_by: by, approved_by: decider || by, released_at: now() });
      break;
    }
    case 'snapshot.delete': {
      // the scheduler's `snapshot_delete` job; an offsite copy stays (offsite retention)
      const x = find(db.snapshots, (y) => y.tenant === p.tenant && y.source === p.source && y.time === p.time, 'snapshot');
      if (x.offsite) x.local = false;
      else db.snapshots = db.snapshots.filter((y) => y !== x);
      break;
    }
    case 'disks.create_array':
    case 'disks.add_spare':
    case 'disks.replace':
    case 'disks.grow':
      hwExecute(action, p, by, qid);
      break;
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
// an optional third element is the content type (CSV downloads)
type Reply = [number, unknown] | [number, unknown, string];
type Handler = (c: Ctx, m: string[]) => Promise<Reply> | Reply;
const routes: [string, RegExp, Handler][] = [];
const on = (method: string, path: string, h: Handler) =>
  routes.push([method, new RegExp('^' + path.replace(/:\w+/g, '([^/]+)') + '$'), h]);

on('GET', '/health', () => [200, { ok: true }]);

on('POST', '/auth/login', async (c) => {
  const { name = '', password = '', totp = '' } = c.body;
  const f = db.failures.get(name);
  if (f && f.until > now()) throw new HttpError(429, 'too many failed sign-ins; try again in 15 minutes');
  const u = db.users.find((x) => x.name === name);
  const expired = !!u?.expires && u.expires <= now();
  if (!u || u.disabled || expired || u.act || !u.password || u.password !== password || !/^\d{6}$/.test(String(totp))) {
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
  const ua = String(c.headers['user-agent'] ?? '').slice(0, 256);
  db.sessions.set(sid, { id: nextId(), userId: u.id, csrf, created: now(), last: now(), ip: '198.51.100.17', ua });
  u.last_login = now();
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
  return [200, { user: pub(u), csrf: db.sessions.get(c.sid!)!.csrf, console_shell: u.tenant || u.role === 'tenant_user' ? null : consoleShell }];
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
    if (!['agent_id', 'paths', 'excludes', 'hooks', 'include', 'exclude_regex', 'cross_mounts', 'skip_fstypes'].includes(k))
      throw new HttpError(400, `config: unknown field "${k}"`);
  find(db.agents, (a) => a.id === cfg.agent_id && a.tenant === tenant, 'agent in tenant');
  const paths = cfg.paths;
  if (!Array.isArray(paths) || paths.length < 1 || paths.length > 64 || paths.some((p) => typeof p !== 'string' || !p.startsWith('/')))
    throw new HttpError(400, 'config.paths: 1 to 64 absolute paths required');
  const excludes = cfg.excludes ?? [];
  if (!Array.isArray(excludes) || excludes.length > 256 || excludes.some((p) => typeof p !== 'string' || !p))
    throw new HttpError(400, 'config.excludes: at most 256 non-empty patterns');
  const sel = selection(cfg, true);
  return { agent_id: cfg.agent_id, paths, excludes, hooks: !!cfg.hooks, ...sel };
}
/** Phase 15e: include roots, regex excludes (+ nested mounts for agents); empty values are not stored. */
function selection(cfg: Json, agent: boolean): Json {
  const out: Json = {};
  const include = cfg.include ?? [];
  if (!Array.isArray(include) || include.length > 256 || include.some((p) => typeof p !== 'string' || !(p.startsWith('/') || (agent && /^[A-Za-z]:[\\/]/.test(p)))))
    throw new HttpError(400, 'config.include: absolute paths');
  if (include.length) out.include = include;
  const rx = cfg.exclude_regex ?? [];
  if (!Array.isArray(rx) || rx.some((p) => typeof p !== 'string' || !p.trim())) throw new HttpError(400, 'config.exclude_regex: non-empty patterns');
  if (rx.length) out.exclude_regex = rx;
  if (agent && cfg.cross_mounts) out.cross_mounts = true;
  const fst = cfg.skip_fstypes ?? [];
  if (agent && fst.length) {
    if (fst.some((x: unknown) => typeof x !== 'string' || !/^[A-Za-z0-9._-]{1,32}$/.test(x))) throw new HttpError(400, 'config.skip_fstypes: file system type names');
    out.skip_fstypes = fst;
  }
  return out;
}

// nfs/smb source config: NFS and SMB fields must not be mixed (deny_unknown_fields in the web-api).
function shareConfig(kind: string, cfg: Json): Json {
  const common = ['host', 'port', 'version', 'snapshot_dir', 'snapshot_prefix', 'snapshot_order', 'excludes', 'include', 'exclude_regex', 'threads', 'xattrs', 'timeout_secs'];
  const own = kind === 'nfs' ? ['export', 'mount_port'] : ['share', 'user', 'domain', 'sec', 'sign', 'seal', 'password', 'keytab', 'principal'];
  for (const k of Object.keys(cfg ?? {})) if (![...common, ...own].includes(k)) throw new HttpError(400, `config: unknown field "${k}"`);
  if (!cfg?.host) throw new HttpError(400, 'host: required');
  if (kind === 'nfs' && !String(cfg.export ?? '').startsWith('/')) throw new HttpError(400, 'export: absolute path required');
  if (kind === 'smb' && !cfg.share) throw new HttpError(400, 'share: required');
  const { include: _i, exclude_regex: _r, ...rest } = cfg;
  return { ...rest, ...selection(cfg, false) };
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
on('GET', '/policies', (c) => (need(c.user), [200, db.policies.map((p) => ({ file_filters: { exclude: [], exclude_regex: [] }, ...p }))]));
on('POST', '/policies', async (c) => {
  const u = need(c.user, 'admin');
  const p = { id: nextId(), name: c.body.name, schedule: c.body.schedule, gfs: c.body.gfs, offsite: !!c.body.offsite, ...runControl(c.body) };
  db.policies.push(p);
  await audit(u.name, 'policy.create', `policy/${p.id}`, p);
  return [201, p];
});
on('PUT', '/policies/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const p = find(db.policies, (x) => x.id === Number(id), 'policy');
  const after = { name: c.body.name, schedule: c.body.schedule, gfs: c.body.gfs, offsite: !!c.body.offsite, ...runControl(c.body) };
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
on('GET', '/groups', (c) => [200, byTenant(need(c.user), db.groups).map(groupState)]);

// ---- Phase 13c: guest inventory and auto-protect groups (crates/web-api/src/inventory.rs)
function hasInventory(src: (typeof db.sources)[number]): boolean {
  return src.kind === 'pve' || src.kind === 'truenas' || (src.kind.startsWith('plugin:') && !!pluginKind(src.kind)?.kind.guests?.list);
}
/** Guests of a group as the scheduler resolves them: explicit list, or the inventory (all / tags); exclude wins. */
function resolveGuests(g: MockGroup): (number | string)[] {
  const ex = new Set((g.exclude ?? []).map(String));
  if (!g.mode || g.mode === 'explicit') return g.guests.filter((x) => !ex.has(String(x)));
  const pve = db.sources.find((s) => s.id === g.source_id)?.kind === 'pve';
  return (db.inventory.get(g.source_id) ?? [])
    .filter((r) => r.gone === null && !ex.has(r.guest) && (g.mode === 'all' || r.tags.some((x) => g.selector.includes(x))))
    .map((r) => (pve ? Number(r.guest) : r.guest));
}
/** Names of the groups protecting `guest` of a source (a plugin group without guests: the whole source). */
function coveringGroups(sid: number, guest: string): string[] {
  return db.groups
    .filter((g) => g.source_id === sid)
    .filter((g) => resolveGuests(g).map(String).includes(guest) || (g.mode === 'explicit' && !g.guests.length && !!db.sources.find((s) => s.id === sid)?.kind.startsWith('plugin:')))
    .map((g) => g.name)
    .sort();
}
const TAG_RE = /^[^\s\x00-\x1f\x7f](?:[^\x00-\x1f\x7f]{0,126}[^\s\x00-\x1f\x7f])?$/;
function checkMode(src: (typeof db.sources)[number], b: Json): Pick<MockGroup, 'mode' | 'selector' | 'exclude'> {
  let mode = b.mode ?? 'explicit';
  const selector: string[] = b.selector ?? [];
  const exclude: unknown[] = b.exclude ?? [];
  if (!['explicit', 'all', 'tags'].includes(mode)) throw new HttpError(400, 'mode: explicit, all or tags');
  if (src.kind === 'truenas' && mode === 'explicit' && !(b.guests ?? []).length) mode = 'all';
  if (mode === 'explicit') {
    if (selector.length || exclude.length) throw new HttpError(400, 'selector, exclude: only for groups of mode all or tags');
    return { mode, selector: [], exclude: [] };
  }
  if (!hasInventory(src)) throw new HttpError(400, 'mode: this source has no guest inventory (linux, nfs, smb and plugin kinds without a guest list: explicit only)');
  if ((b.guests ?? []).length) throw new HttpError(400, 'guests: a group of mode all or tags lists no guests (they come from the inventory)');
  if (mode === 'all' && selector.length) throw new HttpError(400, 'selector: only for mode tags');
  if (mode === 'tags' && (!selector.length || selector.length > 50)) throw new HttpError(400, 'selector: 1..=50 tags');
  const bad = selector.find((x) => typeof x !== 'string' || !TAG_RE.test(x));
  if (bad !== undefined) throw new HttpError(400, `selector: invalid tag ${JSON.stringify(bad)}`);
  const ids = exclude.map(String);
  if (src.kind === 'pve' && ids.some((x) => !/^[1-9]\d{2,8}$/.test(x))) throw new HttpError(400, 'exclude: VM/CT IDs of this source');
  return { mode, selector: [...new Set(selector)].sort(), exclude: [...new Set(ids)].sort() };
}
on('GET', '/sources/:id/inventory', (c, [id]) => {
  const u = need(c.user);
  const src = db.sources.find((s) => s.id === Number(id) && (!u.tenant || s.tenant === u.tenant));
  if (!src) throw new HttpError(404, 'not found');
  const refreshed = db.jobs.filter((j) => ['inventory', 'plugin_guests'].includes(j.kind) && j.state === 'ok' && Number(j.params.source_id) === src.id).reduce((m, j) => Math.max(m, j.finished ?? 0), 0);
  const rows = db.inventory.get(src.id) ?? [];
  return [
    200,
    {
      source_id: src.id,
      kind: src.kind,
      inventory: hasInventory(src),
      refreshed: refreshed || (rows.length ? Math.max(...rows.map((r) => r.seen)) : null),
      guests: rows
        .slice()
        .sort((a, b) => Number(a.gone !== null) - Number(b.gone !== null) || a.guest.length - b.guest.length || a.guest.localeCompare(b.guest))
        .map((r) => ({ ...r, groups: r.gone === null ? coveringGroups(src.id, r.guest) : [] })),
    },
  ];
});
/** `inventory` / `plugin_guests` finished: the listing replaces the source's inventory (rows of gone guests are kept). */
function inventoryResult(j: Job, t: number) {
  const sid = Number(j.params.source_id);
  const rows = db.inventory.get(sid) ?? [];
  if (j.kind === 'plugin_guests' && Array.isArray(j.result?.guests)) {
    const listed = new Set<string>();
    for (const g of j.result.guests) {
      listed.add(g.id);
      const r = rows.find((x) => x.guest === g.id);
      if (r) Object.assign(r, { name: g.title, tags: g.tags ?? [], seen: t, gone: null });
      else rows.push({ guest: g.id, name: g.title, kind: '', tags: g.tags ?? [], seen: t, gone: null });
    }
    for (const r of rows) if (!listed.has(r.guest) && r.gone === null) r.gone = t;
  } else for (const r of rows) if (r.gone === null) r.seen = t;
  db.inventory.set(sid, rows);
  if (j.kind === 'inventory')
    j.result = { guests: rows.filter((r) => r.gone === null).map((r) => ({ id: r.guest, title: r.name, kind: r.kind, tags: r.tags })) };
}
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
/** Phase 15e/f group fields: disk keys (PVE only), restore mode, parallel guests. */
function groupSelection(src: (typeof db.sources)[number], b: Json): Pick<MockGroup, 'exclude_disks' | 'exclude_disks_mode' | 'parallel_guests'> {
  const ex: Record<string, string[]> = {};
  for (const [k, v] of Object.entries((b.exclude_disks ?? {}) as Json)) {
    if (k !== '*' && !/^[1-9]\d{2,8}$/.test(k)) throw new HttpError(400, 'exclude_disks: keys are "*" or vmids');
    if (!Array.isArray(v) || v.some((d) => typeof d !== 'string' || !/^[a-z]+\d{1,3}$/.test(d)))
      throw new HttpError(400, 'exclude_disks: up to 32 disk keys like scsi1, virtio2, sata0, efidisk0');
    if (v.length) ex[k] = [...new Set(v as string[])].sort();
  }
  if (Object.keys(ex).length && src.kind !== 'pve') throw new HttpError(400, 'exclude_disks: only for groups of a pve source');
  const mode = b.exclude_disks_mode ?? 'placeholder';
  if (!['placeholder', 'omit'].includes(mode)) throw new HttpError(400, 'exclude_disks_mode: placeholder or omit');
  const par = b.parallel_guests ?? 1;
  if (!(Number.isInteger(par) && par >= 1 && par <= 8)) throw new HttpError(400, 'parallel_guests: 1..=8');
  return { exclude_disks: ex, exclude_disks_mode: mode, parallel_guests: par };
}
const disksAdded = (a: Record<string, string[]> = {}, b: Record<string, string[]> = {}) =>
  Object.entries(b).some(([k, l]) => l.some((d) => !(a[k] ?? []).includes(d)));
on('POST', '/groups', async (c) => {
  const u = need(c.user, 'admin');
  const g: MockGroup = { id: nextId(), tenant: c.body.tenant, source_id: Number(c.body.source_id), policy_id: Number(c.body.policy_id), name: c.body.name, guests: c.body.guests ?? [], mode: 'explicit', selector: [], exclude: [], timezone: checkTz(c.body.timezone), paused_until: null };
  const src = find(db.sources, (s) => s.id === g.source_id && s.tenant === g.tenant, 'source in tenant');
  Object.assign(g, checkMode(src, c.body), groupSelection(src, c.body));
  if (g.mode === 'explicit') checkGuests(src, g.guests);
  db.groups.push(g);
  await audit(u.name, 'group.create', `group/${g.id}`, g);
  return [201, g];
});
on('PUT', '/groups/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const g = find(db.groups, (x) => x.id === Number(id), 'group');
  if ('tenant' in c.body) throw new HttpError(400, 'unknown field `tenant`');
  const src = find(db.sources, (s) => s.id === Number(c.body.source_id) && s.tenant === g.tenant, 'source in tenant');
  const next = { name: c.body.name, source_id: Number(c.body.source_id), policy_id: Number(c.body.policy_id), guests: c.body.guests ?? [], ...checkMode(src, c.body), timezone: checkTz(c.body.timezone), ...groupSelection(src, c.body) };
  if (next.mode === 'explicit') checkGuests(src, next.guests);
  const from = find(db.policies, (p) => p.id === g.policy_id, 'policy');
  const to = find(db.policies, (p) => p.id === next.policy_id, 'policy');
  if (weakens(from, to) || disksAdded(g.exclude_disks, next.exclude_disks))
    return quorum(u, 'group.update', { id: g.id, tenant: g.tenant, ...next, old: structuredClone(g) });
  Object.assign(g, next);
  await audit(u.name, 'group.update', `group/${g.id}`, g);
  return [200, g];
});
on('PUT', '/groups/:id/index-files', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const g = find(db.groups, (x) => x.id === Number(id), 'group');
  const src = db.sources.find((s) => s.id === g.source_id);
  if (src?.kind !== 'pve') throw new HttpError(400, 'index_files applies to Proxmox VE groups (VM/CT disks); other snapshots are always indexed');
  if (typeof c.body?.enabled !== 'boolean') throw new HttpError(400, 'enabled: true or false');
  g.index_files = c.body.enabled;
  await audit(u.name, 'group.index_files', `group/${g.id}`, { tenant: g.tenant, index_files: g.index_files });
  return [200, { id: g.id, index_files: g.index_files }];
});
on('DELETE', '/groups/:id', (c, [id]) => {
  const g = find(db.groups, (x) => x.id === Number(id), 'group');
  return quorum(need(c.user, 'admin'), 'group.delete', { id: g.id, name: g.name });
});

// run control (Phase 13b): pause / resume groups, source maintenance
const pauseUntil = (b: Json) => {
  if (b.until === undefined || b.until === null) return -1;
  if (!(b.until > now() && b.until <= now() + 366 * DAY)) throw new HttpError(400, 'until: a time in the next 366 days (or none = indefinitely)');
  return Number(b.until);
};
on('POST', '/groups/:id/pause', async (c, [id]) => {
  const u = need(c.user, 'admin', 'operator');
  const g = find(byTenant(u, db.groups), (x) => x.id === Number(id), 'group');
  g.paused_until = pauseUntil(c.body ?? {});
  await audit(u.name, 'group.pause', `group/${g.id}`, { tenant: g.tenant, paused_until: g.paused_until });
  if (g.paused_until === -1 || g.paused_until > now() + 7 * DAY)
    db.alerts.push(
      mkAlert({
        ts: now(), severity: 'warning', kind: 'paused', key: `paused:group:${g.id}:${g.paused_until}`, tenant: g.tenant,
        message: `group ${g.id} ${g.name} (${g.tenant}) paused until ${g.paused_until === -1 ? 'further notice' : isoDay(g.paused_until)}: no scheduled backups meanwhile`,
      }),
    );
  return [200, { id: g.id, paused_until: g.paused_until }];
});
on('POST', '/groups/:id/resume', async (c, [id]) => {
  const u = need(c.user, 'admin', 'operator');
  const g = find(byTenant(u, db.groups), (x) => x.id === Number(id), 'group');
  g.paused_until = null;
  // like the scheduler's next tick: the group's `paused` warning resolves itself
  for (const a of db.alerts) if (a.kind === 'paused' && !a.resolved_at && String(a.key).startsWith(`paused:group:${g.id}:`)) Object.assign(a, { resolved_at: now(), resolved_by: 'scheduler', auto: true });
  await audit(u.name, 'group.resume', `group/${g.id}`, { tenant: g.tenant, paused_until: null });
  return [200, { id: g.id, paused_until: null }];
});
on('POST', '/sources/:id/maintenance', async (c, [id]) => {
  const u = need(c.user, 'admin', 'operator');
  const s = find(byTenant(u, db.sources), (x) => x.id === Number(id), 'source');
  s.maintenance_until = pauseUntil(c.body ?? {});
  await audit(u.name, 'source.maintenance', `source/${s.id}`, { tenant: s.tenant, maintenance_until: s.maintenance_until });
  return [200, { id: s.id, maintenance_until: s.maintenance_until }];
});
on('POST', '/sources/:id/maintenance/end', async (c, [id]) => {
  const u = need(c.user, 'admin', 'operator');
  const s = find(byTenant(u, db.sources), (x) => x.id === Number(id), 'source');
  s.maintenance_until = null;
  await audit(u.name, 'source.maintenance_end', `source/${s.id}`, { tenant: s.tenant, maintenance_until: null });
  return [200, { id: s.id, maintenance_until: null }];
});

// replication (docs/replication.md): this appliance as primary (peers) and as secondary (sources)
const findPeer = (id: string) => find(db.replPeers, (p) => p.id === id, 'peer');
const findRs = (id: string) => find(db.replSources, (r) => String(r.id) === id, 'replication source');
on('GET', '/replication/peers', (c) => (need(c.user, 'admin', 'security_officer', 'operator'), [200, db.replPeers]));
on('GET', '/replication/sources', (c) => (need(c.user, 'admin', 'security_officer', 'operator'), [200, db.replSources]));
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
    limits: {},
    cert_issued: null,
    cert_expires: null,
    cert_renewal_pending: false,
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
on('PUT', '/agents/:id/limits', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const a = findAgent(u, id);
  for (const k of Object.keys(c.body ?? {})) if (!['bwlimit', 'nice'].includes(k)) throw new HttpError(400, `unknown field ${k}`);
  const bwlimit = c.body.bwlimit ?? 0;
  const nice = c.body.nice ?? 0;
  if (!(Number.isInteger(nice) && nice >= 0 && nice <= 19)) throw new HttpError(400, 'nice: 0..=19');
  if (!(Number.isInteger(bwlimit) && (bwlimit === 0 || bwlimit >= 65536))) throw new HttpError(400, 'bwlimit: 0 (unlimited) or at least 65536 bytes/s');
  const old = a.limits;
  a.limits = { bwlimit, nice };
  await audit(u.name, 'agent.limits', `agent/${a.id}`, { new: a.limits, old });
  return [200, pubAgent(a)];
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
  const { name, role, tenant, can_download, expires } = c.body;
  if ('password' in c.body) throw new HttpError(400, 'unknown field `password`: users set their own password at activation');
  if (!NAME_RE.test(String(name ?? ''))) throw new HttpError(400, 'invalid user name');
  if (db.users.some((x) => x.name === name)) throw new HttpError(409, 'user exists');
  if (role === 'tenant_user' && !tenant) throw new HttpError(400, 'tenant users need a tenant');
  // With approvals on, privileged accounts are created disabled; the quorum request
  // enables them. The requester gets only the first half of the activation code.
  const priv = PRIV.includes(role);
  const gated = priv && db.approvals;
  if (role === 'tenant_admin') throw new HttpError(400, 'role: must be admin, security_officer, operator, tenant_user or viewer');
  const n: User = { id: nextId(), name, password: '', role, tenant: tenant || null, disabled: gated, created: now(), totp_secret: '', can_download: can_download ?? null, expires: expires ?? null };
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
  if (b.can_download !== undefined && !!b.can_download !== canDownload(x)) p.can_download = !!b.can_download;
  if (b.expires !== undefined && (b.expires ?? null) !== (x.expires ?? null)) {
    const others = db.users.filter((y) => y.role === 'admin' && !y.disabled && !y.expires && y.id !== x.id);
    if (b.expires && (p.role ?? x.role) === 'admin' && !others.length) throw new HttpError(409, 'expires: the last admin without an expiry date cannot get one');
    p.expires = b.expires ?? null;
  }
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
on('GET', '/plugin-keys', (c) => (need(c.user, 'admin', 'security_officer', 'operator'), [200, db.pluginKeys]));
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

// access (Phase 14d): sessions, timeouts, dormant accounts, login banner, management allow-list
const CLIENT_IP = '198.51.100.17';
const sessionList = (filter: (s: { userId: number }) => boolean, current: string | null) =>
  [...db.sessions.entries()]
    .filter(([, s]) => filter(s))
    .map(([sid, s]) => ({ id: s.id, user_id: s.userId, user: db.users.find((u) => u.id === s.userId)?.name ?? '?', ip: s.ip, user_agent: s.ua, created: s.created, last_seen: s.last, current: sid === current }))
    .sort((a, b) => b.last_seen - a.last_seen);
function endSession(u: User, id: number, own: boolean) {
  const e = [...db.sessions.entries()].find(([, s]) => s.id === id && (!own || s.userId === u.id));
  if (!e) throw new HttpError(404, 'not found');
  db.sessions.delete(e[0]);
  return db.users.find((x) => x.id === e[1].userId)?.name ?? '?';
}
function cidr(s: string): string | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/.exec(s.trim());
  if (m) {
    const p = m[2] === undefined ? 32 : Number(m[2]);
    const parts = m[1].split('.').map(Number);
    if (p > 32 || parts.some((x) => x > 255)) return null;
    const n = parts.reduce((a, x) => a * 256 + x, 0);
    const net = n - (n % 2 ** (32 - p));
    return `${[24, 16, 8, 0].map((sh) => Math.floor(net / 2 ** sh) % 256).join('.')}/${p}`;
  }
  const v6 = /^([0-9a-fA-F:]+)(?:\/(\d{1,3}))?$/.exec(s.trim());
  if (v6 && v6[1].includes(':') && (v6[2] === undefined || Number(v6[2]) <= 128)) return `${v6[1].toLowerCase()}/${v6[2] ?? 128}`;
  return null;
}
const inCidr = (ip: string, c: string) => {
  const [net, p] = c.split('/');
  if (net.includes(':') || ip.includes(':')) return false;
  const n = (s: string) => s.split('.').map(Number).reduce((a, x) => a * 256 + x, 0);
  const size = 2 ** (32 - Number(p));
  return Math.floor(n(ip) / size) === Math.floor(n(net) / size);
};
const securityState = () => {
  const pend = (a: string) => db.quorum.find((q) => q.action === a && q.state === 'pending')?.id ?? null;
  const allow = db.firewall.web.allow;
  return {
    ...structuredClone(db.security),
    mgmt_allow: [...allow],
    client_ip: CLIENT_IP,
    client_allowed: !allow.length || allow.some((c) => inCidr(CLIENT_IP, c)),
    pending: { session: pend('security.session'), mgmt_allow: fwPending('web') },
  };
};
on('GET', '/auth/banner', () => [200, { banner: db.security.login_banner }]);
on('GET', '/auth/sessions', (c) => {
  const u = need(c.user);
  return [200, sessionList((s) => s.userId === u.id, c.sid)];
});
on('DELETE', '/auth/sessions/:id', async (c, [id]) => {
  const u = need(c.user);
  const name = endSession(u, Number(id), true);
  await audit(u.name, 'session.revoke', `user/${name}`, { session: Number(id) });
  return [200, { revoked: 1 }];
});
on('GET', '/sessions', (c) => {
  need(c.user, 'admin');
  const uid = c.query.get('user');
  return [200, sessionList((s) => !uid || s.userId === Number(uid), c.sid)];
});
on('DELETE', '/sessions/:id', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const name = endSession(u, Number(id), false);
  await audit(u.name, 'session.revoke', `user/${name}`, { session: Number(id) });
  return [200, { revoked: 1 }];
});
on('POST', '/users/:id/sessions/revoke', async (c, [id]) => {
  const u = need(c.user, 'admin');
  const x = find(db.users, (y) => y.id === Number(id), 'user');
  let n = 0;
  for (const [sid, s] of db.sessions) if (s.userId === x.id) (db.sessions.delete(sid), n++);
  await audit(u.name, 'session.revoke_user', `user/${x.name}`, { revoked: n });
  return [200, { revoked: n }];
});
on('POST', '/sessions/revoke-all', async (c) => {
  const u = need(c.user, 'admin');
  if (!c.body.current_password || !c.body.current_totp) throw new HttpError(400, 'current_password and current_totp are required');
  if (c.body.current_password !== u.password || !/^\d{6}$/.test(String(c.body.current_totp))) throw new HttpError(403, 're-authentication failed: wrong current password or TOTP code');
  let n = 0;
  for (const sid of [...db.sessions.keys()]) if (sid !== c.sid) (db.sessions.delete(sid), n++);
  await audit(u.name, 'session.revoke_all', 'appliance', { revoked: n });
  return [200, { revoked: n }];
});
on('GET', '/settings/security', (c) => (need(c.user, 'admin', 'security_officer'), [200, securityState()]));
on('PUT', '/settings/session', async (c) => {
  const u = need(c.user, 'admin');
  const { idle_min, absolute_h } = c.body;
  if (!Number.isInteger(idle_min) || idle_min < 5 || idle_min > 120) throw new HttpError(400, 'idle_min: 5..=120 minutes');
  if (!Number.isInteger(absolute_h) || absolute_h < 1 || absolute_h > 24) throw new HttpError(400, 'absolute_h: 1..=24 hours');
  const old = db.security.session;
  const next = { idle_min, absolute_h };
  if (idle_min > old.idle_min || absolute_h > old.absolute_h) return quorum(u, 'security.session', { session: next, old });
  db.security.session = next;
  await audit(u.name, 'security.session', 'settings/session', { session: next, old });
  return [200, next];
});
on('PUT', '/settings/dormant', async (c) => {
  const u = need(c.user, 'admin');
  const days = c.body.days;
  if (!Number.isInteger(days) || (days !== 0 && (days < 30 || days > 3650))) throw new HttpError(400, 'days: 0 (off) or 30..=3650');
  await audit(u.name, 'security.dormant', 'settings/dormant_days', { days, old: db.security.dormant_days });
  db.security.dormant_days = days;
  return [200, { dormant_days: days }];
});
on('PUT', '/settings/banner', async (c) => {
  const u = need(c.user, 'admin');
  const text = String(c.body.banner ?? '').replace(/\s+$/, '');
  if (text.length > 2000 || /[\u0000-\u0008\u000b-\u001f\u007f]/.test(text)) throw new HttpError(400, 'banner: up to 2000 characters, no control characters');
  db.security.login_banner = text;
  await audit(u.name, 'security.login_banner', 'settings/login_banner', { banner: text });
  return [200, { banner: text }];
});
// Phase 16c: inbound firewall (Settings → Firewall); the 14d route is an alias for `web`
const FW_SERVICES = [
  { id: 'web', ports: '8443/tcp', lockout: true, available: true, can_disable: false },
  { id: 'icmp', ports: 'icmp echo', lockout: false, available: true, can_disable: true },
  { id: 'ssh', ports: '22/tcp', lockout: true, available: false, can_disable: true },
];
const fwPending = (id: string) =>
  db.quorum.filter((q) => q.action === 'firewall.inbound' && q.state === 'pending' && q.params.service === id).pop()?.id ?? null;
const fwSets = (id: string) => {
  const r = db.firewall[id];
  if (!r.enabled) return { v4: [], v6: [] };
  if (!r.allow.length) return { v4: ['0.0.0.0/0'], v6: ['::/0'] };
  return { v4: r.allow.filter((c) => !c.includes(':')), v6: r.allow.filter((c) => c.includes(':')) };
};
async function fwRequest(u: User, id: string, raw: unknown, enabled: unknown, force: unknown, confirm: unknown): Promise<[number, Json]> {
  const svc = FW_SERVICES.find((s) => s.id === id);
  if (!svc) throw new HttpError(404, 'not found');
  if (!svc.available) throw new HttpError(409, `${id}: nothing listens on ${svc.ports} on this appliance, so there is nothing to restrict`);
  if (enabled === false && !svc.can_disable) throw new HttpError(400, `${id} cannot be switched off, only restricted to source addresses`);
  const entries: unknown[] = Array.isArray(raw) ? raw : [];
  if (entries.length > 64) throw new HttpError(400, 'allow: at most 64 entries');
  const list: string[] = [];
  for (const s of entries) {
    const x = cidr(String(s));
    if (!x) throw new HttpError(400, `allow: "${s}" is not an address or CIDR (10.0.0.0/8)`);
    if (!list.includes(x)) list.push(x);
  }
  const old = structuredClone(db.firewall[id]);
  const rule = { allow: list, enabled: typeof enabled === 'boolean' ? enabled : old.enabled };
  if (JSON.stringify(rule) === JSON.stringify(old)) return [200, { service: id, rule }];
  const ok = !list.length || list.some((x) => inCidr(CLIENT_IP, x));
  if (svc.lockout && !ok && !(force && String(confirm ?? '').trim() === CLIENT_IP))
    throw new HttpError(409, `the list for ${id} does not contain your address ${CLIENT_IP}: you would lose access to the web UI; add it, or confirm with force and confirm = "${CLIENT_IP}"`);
  return quorum(u, 'firewall.inbound', { service: id, rule, old, requested_from: CLIENT_IP });
}
on('PUT', '/settings/mgmt-allow', async (c) => fwRequest(need(c.user, 'admin'), 'web', c.body.mgmt_allow, undefined, c.body.force, c.body.confirm));
on('PUT', '/firewall/inbound/:id', async (c, [id]) => fwRequest(need(c.user, 'admin'), id, c.body.allow, c.body.enabled, c.body.force, c.body.confirm));
on('GET', '/firewall', (c) => {
  need(c.user, 'admin', 'security_officer');
  const t = now();
  return [
    200,
    {
      services: FW_SERVICES.map((s) => {
        const r = db.firewall[s.id] ?? { allow: [], enabled: false };
        return { ...s, enabled: r.enabled, allow: [...r.allow], effective: s.available ? fwSets(s.id) : null, pending: s.available ? fwPending(s.id) : null };
      }),
      client_ip: CLIENT_IP,
      client_allowed: !db.firewall.web.allow.length || db.firewall.web.allow.some((x) => inCidr(CLIENT_IP, x)),
      status_ts: t - 20,
      status_stale: false,
      outbound: {
        endpoints: ['192.0.2.20 . tcp . 8006', '192.0.2.20 . tcp . 22', '192.0.2.21 . tcp . 22', '198.51.100.40 . tcp . 23', '203.0.113.9 . tcp . 6514'],
        dns: ['192.0.2.53'],
        nts: ['162.159.200.1', '192.53.103.108'],
      },
      drops: [
        { src: '203.0.113.77', proto: 'tcp', port: 22, last_seen: t - 300, packets: 41 },
        { src: '203.0.113.77', proto: 'tcp', port: 3389, last_seen: t - 310, packets: 6 },
        { src: '192.0.2.150', proto: 'tcp', port: 8443, last_seen: t - 3600, packets: 3 },
        { src: '2001:db8:4::17', proto: 'udp', port: 161, last_seen: t - 7200, packets: 12 },
      ],
    },
  ];
});

// approvals setting
const approvalsState = () => {
  const n = approvers().length;
  const pend = db.quorum.find((q) => q.action === 'approvals.disable' && q.state === 'pending');
  return { enabled: db.approvals, possible_approvers: n, recommend: !db.approvals && n >= 2, few_approvers: db.approvals && n < 3, pending_disable: pend?.id ?? null };
};
on('GET', '/settings/approvals', (c) => (need(c.user, 'admin', 'security_officer', 'operator'), [200, approvalsState()]));
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
  if (activeHold(tn, src, tm)) throw new HttpError(409, 'snapshot is under a legal hold: release it first (needs approval)');
  return quorum(u, 'snapshot.delete', { tenant: tn, source: src, time: tm });
});
on('GET', '/snapshots', (c) => {
  const u = need(c.user);
  const tq = c.query.get('tenant');
  const sq = c.query.get('source');
  const held = c.query.get('held') === 'true';
  const xs = byTenant(u, db.snapshots as any[])
    .filter((s) => (!tq || s.tenant === tq) && (!sq || s.source === sq))
    .map((s) => ({ ...s, hold: holdView(openHold(s.tenant, s.source, s.time)) }))
    .filter((s) => !held || s.hold);
  return [200, xs.sort((a, b) => b.time - a.time)];
});
const pubJob = (j: Job, withLog: boolean) => {
  const { plan: _p, duration: _d, fail: _f, cancel_at: _c, log, ...rest } = j;
  const out = { attempt: 1, retry_of: null, not_before: null, cancel_by: null, ...rest };
  return withLog ? { ...out, log } : out;
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
const PVE_NAME = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,62}$/;
/** Phase 15a restore options, as web-api `jobs.rs` checks them. */
function checkRestore(kind: string, tenant: string, p: Json) {
  const want = kind === 'restore_ct' ? 'ct-' : 'vm-';
  if (!String(p.source ?? '').startsWith(want)) throw new HttpError(400, `source: ${kind} needs a ${want}<vmid> snapshot`);
  if (!(p.target >= 100 && p.target <= 999999999)) throw new HttpError(400, 'vmid: must be within 100..=999999999');
  if (p.name !== undefined && p.name_prefix !== undefined) throw new HttpError(400, 'name, name_prefix: give at most one');
  for (const k of ['name', 'name_prefix', 'pool'])
    if (p[k] !== undefined && !PVE_NAME.test(String(p[k]))) throw new HttpError(400, `${k}: must match [A-Za-z0-9._-]{1,63} without a leading dot or dash`);
  if (p.replace && kind === 'instant_recover') throw new HttpError(400, 'replace: only a full restore can replace the original');
  if (p.replace && String(p.source).slice(3) === String(p.target)) throw new HttpError(400, 'target: replace restores to a new VMID');
  if (!p.replace && p.keep_original_links !== undefined) throw new HttpError(400, 'keep_original_links: only with replace');
  if (!db.snapshots.some((s) => s.tenant === tenant && s.source === p.source && s.time === p.time)) throw new HttpError(404, 'no such snapshot');
}
function checkJob(u: User, kind: string, tenant: string, p: Json) {
  if (kind === 'restore' || kind === 'restore_ct' || kind === 'instant_recover') checkRestore(kind, tenant, p);
  if (kind === 'agent_enroll') throw new HttpError(400, 'use POST /agents/{id}/enroll');
  if (kind === 'inventory') {
    const src = find(db.sources, (s) => s.id === Number(p.source_id) && s.tenant === tenant, 'source in tenant');
    if (!hasInventory(src)) throw new HttpError(400, 'source_id: this source has no guest inventory');
  }
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
  if (kind === 'agent_update' || kind === 'agent_renew') {
    if (u.role !== 'admin') throw new HttpError(403, 'requires role admin');
    const a = find(db.agents, (x) => x.id === p.agent_id && x.tenant === tenant, 'agent in tenant');
    if (a.enrolled_at === null) throw new HttpError(409, 'agent is not enrolled');
  }
  if (kind === 'restore_files') {
    const src = String(p.source ?? '');
    // Phase 15b: host, TrueNAS, share, plugin (with a download restore), VM and CT snapshots
    if (!/^(host|nas|share|plugin|vm|ct)-/.test(src)) throw new HttpError(400, 'source: not a snapshot with files');
    if (!src.startsWith('host-') && !p.agent_id) throw new HttpError(400, 'agent_id: choose the agent to restore to');
    if (src.startsWith('host-') && !p.agent_id) p.agent_id = src.slice(5);
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
  if (kind === 'files_get' && !canDownload(u)) throw new HttpError(403, 'this account may not download files');
  if (kind === 'backup') backupGuests(params);
  if (params.replace) {
    // Phase 15a: an approval request (`restore.replace`), never a plain job; not for tenant users
    need(u, 'admin', 'operator');
    const { replace: _r, ...rest } = params;
    return quorum(u, 'restore.replace', { tenant, kind, params: rest });
  }
  // Like web-api: files_get gets a server-generated download token, returned in the 202 body.
  const p = kind === 'files_get' ? { ...params, download_token: rand(32) } : params;
  const j = addJob(kind, tenant, p, u.name, params.vmid === 999 ? { fail: 'guest not found on any node' } : {});
  if (kind.startsWith('plugin_')) j.duration = { plugin_validate: 3, plugin_guests: 3, plugin_restore: 14, plugin_mount: 6 }[kind as string] ?? 10;
  if (kind === 'inventory') j.duration = 3;
  await audit(u.name, 'job.create', `job/${j.id}`, { kind, tenant, params: p });
  return [202, p.download_token ? { id: j.id, download_token: p.download_token } : { id: j.id }];
});
// Phase 15a: several guests in one request, one job each (web-api `restores.rs`)
on('POST', '/restores', async (c) => {
  const u = need(c.user, 'admin', 'operator', 'tenant_user');
  const b = c.body;
  if (u.tenant && u.tenant !== b.tenant) throw new HttpError(403, 'forbidden');
  find(db.tenants, (t) => t.name === b.tenant, 'tenant');
  const items: Json[] = b.items ?? [];
  if (!items.length || items.length > 100) throw new HttpError(400, 'items: 1..=100 guests');
  if (new Set(items.map((i) => i.source)).size !== items.length) throw new HttpError(400, 'items: one snapshot per guest');
  const jobs = items.map((it, i) => {
    const kind = String(it.source).startsWith('ct-') ? 'restore_ct' : 'restore';
    const p: Json = { source: it.source, time: it.time, node: b.node, target: Number(b.target_base) + i, storage: b.storage, start: !!b.start, link_down: !!b.link_down };
    if (b.name_prefix) p.name_prefix = b.name_prefix;
    if (b.pool) p.pool = b.pool;
    try {
      checkRestore(kind, b.tenant, p);
    } catch (e) {
      if (e instanceof HttpError) throw new HttpError(e.status, `${it.source}: ${e.message}`);
      throw e;
    }
    return { kind, p };
  });
  const ids = jobs.map(({ kind, p }) => addJob(kind, b.tenant, p, u.name).id);
  await audit(u.name, 'job.create_many', `tenant/${b.tenant}`, { ids, jobs });
  return [202, { ids }];
});
on('POST', '/jobs/:id/cancel', async (c, [id]) => {
  const u = need(c.user, 'admin', 'operator');
  const j = find(db.jobs, (x) => x.id === Number(id), 'job');
  // Phase 13b: a running job gets a cancel request that the scheduler carries out
  if (j.state === 'running') {
    if (j.params.replace) throw new HttpError(409, 'a running restore that replaces the original cannot be cancelled');
    if (j.cancel_by) throw new HttpError(409, 'cancellation already requested');
    Object.assign(j, { cancel_by: u.name, cancel_at: now() });
    await audit(u.name, 'job.cancel', `job/${j.id}`, { running: true });
    return [200, { id: j.id, state: 'cancelling' }];
  }
  if (j.state !== 'queued') throw new HttpError(409, `job is ${j.state}, only queued or running jobs can be cancelled`);
  j.state = 'cancelled';
  j.finished = now();
  await audit(u.name, 'job.cancel', `job/${j.id}`, { running: false });
  return [200, { id: j.id, state: 'cancelled' }];
});

// ---- Phase 15g: file search across snapshots (crates/scheduler/src/search.rs, POST /search)
/** Every entry of a snapshot's synthetic tree (listDir), paths relative without a leading slash. */
function walkSnapshot(source: string, time: number): { path: string; kind: string; size: number; mtime: number }[] {
  const out: { path: string; kind: string; size: number; mtime: number }[] = [];
  const week = 7 * DAY;
  const rec = (dir: string) => {
    for (const e of listDir(dir, source)) {
      const full = dir === '/' ? `/${e.name}` : `${dir}/${e.name}`;
      // documents change weekly (several versions across snapshots), the rest stays put
      const changing = e.kind === 'file' && /\.(pdf|docx|xlsx|odt|txt|sql)$/.test(e.name);
      const mtime = changing ? Math.floor((time - 3600) / week) * week : Math.min(e.mtime, time - 3600);
      const size = changing ? e.size + (Math.floor(time / week) % 7) * 1024 : e.size;
      out.push({ path: full.slice(1), kind: e.kind, size, mtime });
      if (e.kind === 'dir') rec(full);
    }
  };
  rec('/');
  return out;
}
/** Glob (* ? [abc] [a-z] [!x]) as a RegExp; no wildcard = substring. */
function globRe(q: string, caseSensitive: boolean): RegExp {
  const wild = /[*?[]/.test(q);
  let re = '';
  for (let i = 0; i < q.length; i++) {
    const ch = q[i];
    if (ch === '*') re += '.*';
    else if (ch === '?') re += '.';
    else if (ch === '[') {
      const end = q.indexOf(']', i + 2);
      if (end < 0) re += '\\[';
      else {
        let body = q.slice(i + 1, end);
        const neg = body.startsWith('!');
        if (neg) body = body.slice(1);
        re += `[${neg ? '^' : ''}${body.replace(/[\\\]^]/g, '\\$&')}]`;
        i = end;
      }
    } else re += ch.replace(/[.+^${}()|\\/]/g, '\\$&');
  }
  return new RegExp(wild ? `^${re}$` : re, caseSensitive ? '' : 'i');
}
/** VM/CT snapshots are indexed only when a group with index_files covers the guest. */
function vmIndexed(tenant: string, source: string): boolean {
  const id = Number(source.replace(/^(vm|ct)-/, ''));
  return db.groups.some((g) => g.tenant === tenant && g.index_files && resolveGuests(g).some((x) => Number(x) === id));
}
function searchResult(p: Json, tenant: string) {
  const t0 = Date.now();
  const query = String(p.query).replace(/^\/+/, '');
  const re = globRe(query, !!p.case_sensitive);
  const full = query.includes('/');
  const limit = Number(p.limit ?? 500);
  const snaps = (db.snapshots as any[])
    .filter((s) => s.tenant === tenant && s.local && (!p.source || s.source === p.source) && (!p.from || s.time >= p.from) && (!p.to || s.time <= p.to))
    .sort((a, b) => b.time - a.time);
  const groups = new Map<string, Json>();
  let [scanned, unindexed, truncated] = [0, 0, false];
  for (const s of snaps) {
    if (/^(vm|ct)-/.test(s.source) && !vmIndexed(tenant, s.source)) {
      unindexed++;
      continue;
    }
    scanned++;
    for (const e of walkSnapshot(s.source, s.time)) {
      const name = full ? e.path : e.path.split('/').pop()!;
      if (!re.test(name)) continue;
      const k = `${s.source}\0${e.path}\0${e.size}\0${e.mtime}`;
      const m = groups.get(k);
      if (m) m.times.push(s.time);
      else if (groups.size < limit) groups.set(k, { source: s.source, ...e, times: [s.time] });
      else truncated = true;
    }
  }
  const matches = [...groups.values()].sort((a, b) => a.path.localeCompare(b.path) || a.source.localeCompare(b.source) || b.mtime - a.mtime);
  return { matches, scanned, unindexed, truncated, elapsed_ms: Date.now() - t0 + 412 };
}
on('POST', '/search', async (c) => {
  const u = need(c.user, 'admin', 'operator', 'tenant_user');
  const b = c.body ?? {};
  const tenant = String(b.tenant ?? '');
  if (u.tenant && u.tenant !== tenant) throw new HttpError(403, 'forbidden');
  find(db.tenants, (t) => t.name === tenant, 'tenant');
  const query = String(b.query ?? '').trim();
  if (!query || query.length > 256) throw new HttpError(400, 'query: 1..=256 characters');
  if (b.limit !== undefined && !(Number.isInteger(b.limit) && b.limit >= 1 && b.limit <= 2000)) throw new HttpError(400, 'limit: 1..=2000');
  const p: Json = { query, case_sensitive: !!b.case_sensitive, limit: b.limit ?? 500 };
  for (const k of ['source', 'from', 'to']) if (b[k] !== undefined && b[k] !== null && b[k] !== '') p[k] = b[k];
  const j = addJob('file_search', tenant, p, u.name);
  j.duration = 1;
  j.plan = [`searching the file indexes of tenant ${tenant} for "${query}"`, 'done'];
  j.result = searchResult(p, tenant);
  await audit(u.name, 'file.search', `job/${j.id}`, { tenant, ...p });
  return [202, { id: j.id }];
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
// filters as the web-api: actor exact, action prefix, target substring, from/to unix seconds
function auditFiltered(q: URLSearchParams): Json[] {
  const after = Number(q.get('after') ?? 0);
  const before = q.get('before');
  const [actor, action, target] = ['actor', 'action', 'target'].map((k) => q.get(k) || null);
  const from = q.get('from') ? Number(q.get('from')) : null;
  const to = q.get('to') ? Number(q.get('to')) : null;
  return db.audit.filter(
    (e) =>
      e.seq > after &&
      (before === null || e.seq < Number(before)) &&
      (!actor || e.actor === actor) &&
      (!action || e.action.startsWith(action)) &&
      (!target || e.target.includes(target)) &&
      (from === null || e.ts >= from) &&
      (to === null || e.ts <= to),
  );
}
on('GET', '/audit', (c) => {
  need(c.user, 'admin', 'security_officer');
  const before = c.query.get('before');
  const limit = Math.min(Number(c.query.get('limit') ?? 500), 1000);
  const desc = before !== null || c.query.get('order') === 'desc';
  const xs = auditFiltered(c.query);
  return [200, (desc ? [...xs].reverse() : xs).slice(0, limit)];
});
async function auditCsv(u: User, q: URLSearchParams): Promise<string> {
  const shown: Json = {};
  for (const k of ['actor', 'action', 'target', 'from', 'to', 'after', 'before']) if (q.get(k)) shown[k] = /^(from|to|after|before)$/.test(k) ? Number(q.get(k)) : q.get(k);
  const rows = auditFiltered(q);
  await audit(u.name, 'audit.export', 'audit', shown);
  const f = (s: string) => (/[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
  return ['seq,ts,actor,action,target,details,prev_hash,hash', ...rows.map((e) => [e.seq, e.ts, f(e.actor), f(e.action), f(e.target), f(JSON.stringify(e.details)), e.prev_hash, e.hash].join(','))].join('\r\n') + '\r\n';
}
on('GET', '/audit/forwarding', (c) => {
  need(c.user, 'admin', 'security_officer');
  const head = db.audit.length;
  const f = db.forwarding;
  const sinks = (['syslog', 'https'] as const)
    .filter((k) => f[k])
    .map((k) => {
      const err = db.forwardErr[k];
      const dest = k === 'syslog' ? `${f.syslog.host}:${f.syslog.port}` : f.https.url;
      return {
        sink: k, dest, enabled: f[k].enabled,
        audit_seq: !f[k].enabled ? Math.max(0, head - 12) : err ? Math.max(0, head - 3) : head,
        event_seq: err ? 40 : 42,
        last_ok: now() - (err ? 1500 : 4), last_error: err ?? null, last_error_ts: err ? now() - 20 : null, failing_since: err ? now() - 1500 : null,
      };
    });
  return [200, { head_seq: head, sinks }];
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

// alerts (13f lifecycle). They may name other tenants: tenant-scoped users get an empty list.
// (a function declaration: the seed runs before the module's consts are initialised)
function mkAlert(a: Json): Json {
  // the API's English hint; the UI shows its own i18n text per kind
  const hint = a.kind === 'job_failed' ? 'Open the job log on the Jobs page, fix the cause and run the job again.' : 'See the alerts chapter of the user manual.';
  return {
    id: nextId(), first_ts: a.ts, last_ts: a.ts, count: 1, key: `${a.kind}:${a.message}`, tenant: null, hint,
    acked_by: null, resolved_at: null, resolved_by: null, note: null, auto: false, ...a,
  };
}
on('GET', '/alerts', (c) => {
  if (need(c.user).tenant) return [200, []];
  const s = c.query.get('state') ?? 'all';
  if (!['open', 'resolved', 'all'].includes(s)) throw new HttpError(400, 'state: open, resolved or all');
  const id = Number(c.query.get('id') ?? 0);
  const rows = db.alerts
    .filter((a) => s === 'all' || (s === 'open') === !a.resolved_at)
    .filter((a) => !id || a.id === id)
    .map((a): Json => ({ ...a, snapshot: alertSnapshot(a) }));
  return [200, rows.sort((a, b) => b.id - a.id)];
});
const alertNote = (b: Json) => {
  const n = typeof b?.note === 'string' ? b.note.trim() : '';
  if (n.length > 1000) throw new HttpError(400, 'note: up to 1000 characters');
  return n || null;
};
const alertFor = (c: Ctx, id: string) => {
  const u = need(c.user, 'admin', 'operator', 'security_officer');
  if (u.tenant) throw new HttpError(403, 'forbidden');
  const a = find(db.alerts, (x) => x.id === Number(id), 'alert');
  if (['break_glass', 'console_unlock', 'console_root_shell'].includes(a.kind)) need(c.user, 'admin', 'security_officer');
  return { u, a };
};
on('POST', '/alerts/:id/ack', async (c, [id]) => {
  const { u, a } = alertFor(c, id);
  const note = alertNote(c.body);
  if (a.acked_by) throw new HttpError(409, 'already acknowledged');
  a.acked_by = u.name;
  if (note) a.note = note;
  await audit(u.name, 'alert.ack', `alert/${a.id}`, { kind: a.kind, note });
  return [200, { id: a.id, acked_by: u.name }];
});
on('POST', '/alerts/:id/resolve', async (c, [id]) => {
  const { u, a } = alertFor(c, id);
  const note = alertNote(c.body);
  if (a.resolved_at) throw new HttpError(409, 'already resolved');
  Object.assign(a, { resolved_at: now(), resolved_by: u.name, auto: false, acked_by: a.acked_by ?? u.name }, note ? { note } : {});
  await audit(u.name, 'alert.resolve', `alert/${a.id}`, { kind: a.kind, note });
  return [200, { id: a.id, resolved_by: u.name }];
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
    smtp: { host: 'mail.example.com', port: 587, starttls: true, from: 'nexus@example.com', user: 'nexus', password: 'sealed:demo' },
    rules: [
      { name: 'ops-team', min_severity: 'warning', kinds: [], tenants: [], channels: { email: ['ops@example.com', 'backup-team@example.com'], webhook: null } },
      {
        name: 'acme-chat', min_severity: 'info', kinds: ['job_failed', 'verify', 'offsite_lag'], tenants: ['acme'],
        channels: {
          email: [],
          webhook: {
            url: 'https://hooks.slack.com/services/T0000/B0000/acme', headers: {},
            template: '{"text": ":rotating_light: [{{severity}}] {{kind}} on {{host}}: {{message}}\\n{{hint}}\\n<{{alert_url}}|Open alert> (seen {{count}}x)"}',
          },
        },
      },
      {
        name: 'siem', min_severity: 'critical', kinds: [], tenants: [],
        channels: { email: [], webhook: { url: 'https://siem.example.com/api/events', headers: { Authorization: 'sealed:demo' }, template: null } },
      },
    ],
    reminder_hours: 24,
    retention_days: { info: 14, warning: 180, critical: 180 },
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
  db.alerts.push(
    mkAlert({
      ts: t - 86400 * 58, severity: 'critical', kind: 'break_glass',
      message: 'administrator "admin" was reset to pending activation at the console (nexus-setup recover-admin).', acked_by: 'so',
      resolved_at: t - 86400 * 58 + 3600, resolved_by: 'so', note: 'Confirmed with J. Weber (lost TOTP device).',
    }),
  );
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
interface Obj { source: string; name: string; kind: string; tenant: string; rpo_s: number; inGroup: boolean; names: string[]; sourceName?: string; sourceId?: number | null; paused?: boolean; group?: string }

function protectedObjects(u: User): Obj[] {
  const out: Obj[] = [];
  for (const g of byTenant(u, db.groups)) {
    const src = db.sources.find((s) => s.id === g.source_id);
    const pol = db.policies.find((p) => p.id === g.policy_id);
    if (!src || !pol) continue;
    const rpo_s = schedulePeriod(pol.schedule);
    const paused = isPaused(g.paused_until, now()) || isPaused(src.maintenance_until, now());
    const add = (source: string, name: string, names = [source]) => out.push({ source, name, kind: src.kind, tenant: g.tenant, rpo_s, inGroup: true, names, paused, group: g.name });
    const guests = resolveGuests(g);
    if (src.kind === 'pve')
      for (const v of guests) add(guestName(v), `${GUEST_NAMES[`${g.tenant}/${v}`] ?? 'guest'} (${v})`, [`vm-${v}`, `ct-${v}`]);
    else if (src.kind === 'linux') for (const a of guests) add(`host-${a}`, db.agents.find((x) => x.id === a)?.name ?? String(a));
    else if (src.kind === 'truenas') for (const d of guests) add(`nas-${src.id}-${String(d).replaceAll('/', '.')}`, `${src.name}: ${d}`);
    else if (src.kind === 'nfs' || src.kind === 'smb') add(`share-${src.id}`, src.name);
    else if (src.kind.startsWith('plugin:')) {
      const pid = pluginKind(src.kind)?.plugin.id ?? src.kind.slice(7);
      if (guests.length) for (const x of guests) add(`plugin-${pid}-${src.id}-${x}`, `${src.name}: ${x}`);
      else if (g.mode === 'explicit') add(`plugin-${pid}-${src.id}`, src.name);
    }
  }
  // inventory guests in no group of their source (and enrolled agents without a group)
  const extra: Obj[] = [];
  for (const [sid, rows] of db.inventory) {
    const src = db.sources.find((s) => s.id === sid);
    if (!src || (u.tenant && src.tenant !== u.tenant)) continue;
    for (const r of rows)
      if (r.gone === null && !coveringGroups(sid, r.guest).length)
        extra.push({ source: r.guest, name: src.kind === 'pve' ? `${r.name} (${r.guest})` : `${src.name}: ${r.name}`, kind: src.kind, tenant: src.tenant, rpo_s: DAY, inGroup: false, names: [], sourceName: src.name, sourceId: src.id } as Obj);
  }
  for (const a of byTenant(u, db.agents))
    if (!out.some((o) => o.source === `host-${a.id}`))
      extra.push({ source: a.id, name: a.name, kind: 'linux', tenant: a.tenant, rpo_s: DAY, inGroup: false, names: [], sourceName: a.name, sourceId: null } as Obj);
  return [...out, ...extra];
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
    const sla = !last ? 'never' : (age_s as number) > o.rpo_s * 1.5 ? (o.paused ? 'paused' : 'breach') : 'ok';
    return { ...o, last_ok: last, age_s, sla };
  });
  const inGroup = objs.filter((o) => o.inGroup);
  const prot = {
    objects: objs.length,
    protected: inGroup.filter((o) => o.sla !== 'never').length,
    unprotected: objs.length - inGroup.filter((o) => o.sla !== 'never').length,
    sla_ok: inGroup.filter((o) => o.sla === 'ok').length,
    sla_breach: inGroup.filter((o) => o.sla === 'breach').length,
    sla_paused: inGroup.filter((o) => o.sla === 'paused').length,
    never: inGroup.filter((o) => o.sla === 'never').length,
    unprotected_list: objs
      .filter((o) => !o.inGroup)
      .map((o) => ({ tenant: o.tenant, kind: o.kind, source_id: o.sourceId ?? null, source: o.sourceName ?? '', guest: o.source, name: o.name })),
    worst: inGroup
      .sort((a, b) => Number(!['ok', 'paused'].includes(b.sla)) - Number(!['ok', 'paused'].includes(a.sla)) || (b.age_s ?? Infinity) / b.rpo_s - (a.age_s ?? Infinity) / a.rpo_s)
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
  const newest = new Map<string, Json>();
  for (const s of snaps.filter((x) => x.local)) {
    const k = `${s.tenant}/${s.source}`;
    if ((newest.get(k)?.time ?? -1) < s.time) newest.set(k, s);
  }
  const consistency: Record<string, number> = { application: 0, crash: 0, inconsistent: 0, unknown: 0 };
  for (const s of newest.values()) consistency[s.consistency ?? 'unknown'] += 1;
  return {
    generated: t,
    days,
    protection: prot,
    consistency,
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

// ---- forwarding (14a): header values write-only; weakening an enabled sink needs approval
function pubForwarding(f: Json = db.forwarding): Json {
  const v = structuredClone(f);
  if (v.https) v.https.headers = Object.fromEntries(Object.keys(v.https.headers ?? {}).map((k) => [k, null]));
  return v;
}
on('GET', '/settings/forwarding', (c) => (need(c.user, 'admin', 'security_officer'), [200, pubForwarding()]));
on('PUT', '/settings/forwarding', async (c) => {
  const u = need(c.user, 'admin');
  const old = db.forwarding;
  const pin = (v: unknown, w: string) => {
    if (v === null || v === undefined || String(v).trim() === '') return null;
    const h = String(v).replace(/:/g, '').trim();
    if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new HttpError(400, `${w}.pin_sha256: 64 hex digits (SHA-256 of the certificate)`);
    return h.toLowerCase();
  };
  const pem = (v: unknown, w: string) => {
    if (v === null || v === undefined || String(v).trim() === '') return null;
    if (!String(v).includes('-----BEGIN CERTIFICATE-----')) throw new HttpError(400, `${w}.ca_pem: PEM certificate(s), at most 64 KiB`);
    return String(v);
  };
  const s = c.body.syslog;
  const h = c.body.https;
  let syslog: Json | null = null;
  if (s) {
    if (!/^[A-Za-z0-9.:[\]-]{1,253}$/.test(s.host ?? '')) throw new HttpError(400, 'syslog.host: host name or IP address');
    const facility = s.facility ?? 13;
    if (!(Number.isInteger(facility) && facility >= 0 && facility <= 23)) throw new HttpError(400, 'syslog.facility: 0..=23');
    const app = s.app_name ?? 'nexus';
    if (!/^[!-~]{1,48}$/.test(app)) throw new HttpError(400, 'syslog.app_name: 1..=48 printable ASCII characters, no spaces');
    syslog = { enabled: s.enabled ?? true, host: s.host, port: s.port ?? 6514, ca_pem: pem(s.ca_pem, 'syslog'), pin_sha256: pin(s.pin_sha256, 'syslog'), app_name: app, facility };
  }
  let https: Json | null = null;
  if (h) {
    if (!/^https:\/\/[^/@\s]+(\/\S*)?$/.test(h.url ?? '')) throw new HttpError(400, 'https.url: https://host[:port]/path, without user info');
    const batch = h.batch_max ?? 100;
    if (!(Number.isInteger(batch) && batch >= 1 && batch <= 1000)) throw new HttpError(400, 'https.batch_max: 1..=1000');
    const headers: Json = {};
    for (const [k, v] of Object.entries(h.headers ?? {})) {
      if (v === null) {
        const prev = old.https?.url === h.url ? old.https.headers?.[k] : undefined;
        if (prev === undefined) throw new HttpError(400, `https.headers: a value for ${k} is required (new header or URL changed)`);
        headers[k] = prev;
      } else headers[k] = v;
    }
    https = { enabled: h.enabled ?? true, url: h.url, headers, batch_max: batch, ca_pem: pem(h.ca_pem, 'https'), pin_sha256: pin(h.pin_sha256, 'https') };
  }
  const next = { syslog, https };
  const same = (a: Json, b: Json | null, keys: string[]) => !!a && !!b && b.enabled && keys.every((k) => JSON.stringify(a[k]) === JSON.stringify(b[k]));
  const weaker =
    (old.syslog?.enabled && !same(old.syslog, syslog, ['host', 'port', 'ca_pem', 'pin_sha256'])) ||
    (old.https?.enabled && !same(old.https, https, ['url', 'ca_pem', 'pin_sha256', 'headers']));
  if (weaker) return quorum(u, 'settings.forwarding', { forwarding: next, old: pubForwarding(old) });
  db.forwarding = next;
  const shown = pubForwarding();
  await audit(u.name, 'settings.forwarding', 'settings/forwarding', shown);
  return [200, shown];
});
on('POST', '/settings/forwarding/test', async (c) => {
  const u = need(c.user, 'admin');
  const f = db.forwarding;
  const out: Json = {};
  if (f.syslog) out.syslog = /bad|invalid/.test(f.syslog.host) ? `error: connecting ${f.syslog.host}:${f.syslog.port}: connection refused` : 'ok';
  if (f.https) out.https = /bad|invalid/.test(f.https.url) ? 'error: HTTP status client error (401 Unauthorized)' : 'ok';
  if (!f.syslog && !f.https) out.forwarding = 'error: no sink configured';
  await audit(u.name, 'job.create', 'job/0', { kind: 'forward_test', params: {} });
  return [200, out];
});
// ---- Phase 14e reports: CSV downloads and scheduled reports (docs/control-plane.md "Reports")
const REPORT_TYPES = ['protection', 'failed', 'sla', 'storage'];
const isoTime = (ts: number | null | undefined) => (ts ? new Date(ts * 1000).toISOString().replace('.000Z', 'Z') : '');
/** RFC 4180 like reports::Table::csv (formula-like text neutralised). */
function toCsv(columns: string[], rows: unknown[][]): string {
  const field = (v: unknown) => {
    let s = v === null || v === undefined ? '' : String(v);
    if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
  };
  return [columns, ...rows].map((r) => r.map(field).join(',') + '\r\n').join('');
}
const hours = (s: number) => Math.round(s / 360) / 10;
const ratio3 = (r: number | null) => (r === null ? '' : Math.round(r * 1000) / 1000);
function reportTable(u: User, kind: string, scope: string | null, from: number, to: number): [string[], unknown[][]] {
  const t = now();
  const v: User = { ...u, tenant: scope };
  if (kind === 'protection' || kind === 'sla') {
    const snaps = byTenant(v, db.snapshots as any[]);
    // one row per object; an object in several groups lists them all (shortest RPO)
    const merged = new Map<string, Obj & { groups: string[] }>();
    for (const o of protectedObjects(v).filter((x) => x.inGroup)) {
      const k = `${o.tenant}/${o.source}`;
      const m = merged.get(k);
      if (!m) merged.set(k, { ...o, groups: [o.group ?? ''] });
      else {
        m.rpo_s = Math.min(m.rpo_s, o.rpo_s);
        m.paused = m.paused && o.paused;
        if (!m.groups.includes(o.group ?? '')) m.groups.push(o.group ?? '');
      }
    }
    const objs = [...merged.values()].map((o) => {
        const mine = snaps.filter((s) => s.tenant === o.tenant && o.names.includes(s.source)).sort((a, b) => b.time - a.time);
        const last = mine[0];
        const age = last ? t - last.time : null;
        const sla = !last ? 'never' : (age as number) > o.rpo_s * 1.5 ? (o.paused ? 'paused' : 'breach') : 'ok';
        return { o, last, age, sla, groups: o.groups.join(' ') };
      });
    if (kind === 'protection')
      return [
        ['tenant', 'groups', 'object', 'kind', 'source', 'rpo_hours', 'last_good', 'age_hours', 'status', 'local', 'offsite', 'verified', 'consistency'],
        objs.map(({ o, last, age, sla, groups }) => [
          o.tenant, groups, o.name, o.kind, last?.source ?? o.names[0], hours(o.rpo_s), isoTime(last?.time), age === null ? '' : hours(age), sla,
          last ? (last.local ? 'yes' : 'no') : '', last ? (last.offsite ? 'yes' : 'no') : '', isoTime(last?.verified),
          o.kind === 'pve' || !last ? 'unknown' : 'consistent',
        ]),
      ];
    const rows: [number, unknown[]][] = [];
    for (const { o, last, sla, groups } of objs) {
      const limit = o.rpo_s * 1.5;
      if (sla === 'breach' && last) {
        const s = Math.max(last.time + limit, from);
        const e = Math.min(t, to);
        if (s < e) rows.push([s, ['rpo_breach', o.tenant, groups, o.name, isoTime(s), '', hours(e - s), hours(limit), `ongoing: no good backup since ${isoTime(last.time)}`]]);
      }
    }
    for (const a of db.alerts.filter((x) => x.kind === 'sla_missed' && x.ts >= from && x.ts < to && (!scope || x.tenant === scope)))
      rows.push([a.ts, ['sla_missed', a.tenant ?? '', /group (\S+)/.exec(a.message)?.[1] ?? '', '', isoTime(a.ts), '', '', '', a.message]]);
    rows.sort((a, b) => a[0] - b[0]);
    return [['type', 'tenant', 'groups', 'object', 'start', 'end', 'hours', 'target_hours', 'detail'], rows.map((r) => r[1])];
  }
  if (kind === 'failed') {
    const jobs = db.jobs.filter((j) => j.state === 'failed' && j.finished && j.finished >= from && j.finished < to && (!scope || j.tenant === scope));
    const target = (p: Json) => {
      const g = db.groups.find((x) => x.id === p.group_id);
      if (g) return `group ${g.name}`;
      const s = db.sources.find((x) => x.id === p.source_id);
      if (s) return `source ${s.name}`;
      return p.agent_id ? `agent ${p.agent_id}` : p.vmid ? `guest ${p.vmid}` : '';
    };
    const errLine = (log: string) => {
      const lines = log.split('\n').map((l) => l.trim()).filter(Boolean);
      return (lines.find((l) => /error|failed|fatal/i.test(l)) ?? lines.at(-1) ?? '').slice(0, 300);
    };
    return [
      ['job', 'tenant', 'kind', 'target', 'created', 'finished', 'attempt', 'error'],
      jobs.sort((a, b) => a.finished! - b.finished!).map((j) => [j.id, j.tenant, j.kind, target(j.params), isoTime(j.created), isoTime(j.finished), j.attempt ?? 1, errLine(j.log || j.fail || '')]),
    ];
  }
  const s = storageStats(v);
  const sums = (x: Json) => [x.logical, x.data_in, x.stored, x.saved, ratio3(x.dedup), ratio3(x.compression), ratio3(x.reduction)];
  return [
    ['level', 'tenant', 'group', 'sources', 'snapshots', 'logical_bytes', 'data_in_bytes', 'stored_bytes', 'saved_bytes', 'dedup', 'compression', 'reduction', 'used_bytes', 'quota_bytes', 'growth_7d_bytes', 'growth_30d_bytes', 'growth_90d_bytes'],
    [
      ...s.tenants.map((x) => ['tenant', x.tenant, '', '', x.snapshots, ...sums(x), x.used, x.quota_bytes ?? '', x.growth.d7, x.growth.d30, x.growth.d90]),
      ...s.groups.map((g) => ['group', g.tenant, g.group ?? '', g.sources, g.snapshots, ...sums(g), '', '', '', '', '']),
    ],
  ];
}
function reportRange(q: URLSearchParams): [number, number] {
  const when = (v: string, what: string, end: boolean) => {
    if (/^-?\d+$/.test(v)) return Number(v);
    const ms = /^\d{4}-\d{2}-\d{2}$/.test(v) ? Date.parse(`${v}T00:00:00Z`) : NaN;
    if (Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== v) throw new HttpError(400, `${what}: YYYY-MM-DD or unix seconds`);
    return ms / 1000 + (end ? DAY : 0);
  };
  const to = q.get('to') ? when(q.get('to')!, 'to', true) : now();
  const from = q.get('from') ? when(q.get('from')!, 'from', false) : to - 7 * DAY;
  if (from >= to) throw new HttpError(400, 'from must be before to');
  if (to - from > 400 * DAY) throw new HttpError(400, 'range: at most 400 days');
  return [from, to];
}
on('GET', '/reports/:file', async (c, [file]) => {
  const u = need(c.user);
  const kind = /^([a-z]+)\.csv$/.exec(file)?.[1] ?? '';
  if (!REPORT_TYPES.includes(kind)) throw new HttpError(404, 'not found');
  const want = c.query.get('tenant') || null;
  if (u.tenant && want && want !== u.tenant) throw new HttpError(403, 'forbidden');
  const scope = u.tenant ?? want;
  const [from, to] = reportRange(c.query);
  const [cols, rows] = reportTable(u, kind, scope, from, to);
  await audit(u.name, 'report.export', `report/${kind}`, { type: kind, from, to, tenant: scope, rows: rows.length });
  c.res.setHeader('Content-Disposition', `attachment; filename="nexus-${kind}${scope ? `-${scope}` : ''}-${isoDay(to - 1)}.csv"`);
  return [200, toCsv(cols, rows), 'text/csv; charset=utf-8'];
});
const reportsView = () => ({
  smtp: !!db.alertSettings.smtp?.host,
  reports: db.reports.map((r) => {
    const j = [...db.jobs].reverse().find((x) => x.kind === 'report_send' && x.params.name === r.name);
    return { ...r, last: j ? { job_id: j.id, state: j.state, created: j.created, finished: j.finished, requested_by: j.requested_by } : null };
  }),
});
on('GET', '/settings/reports', (c) => (need(c.user, 'admin', 'security_officer'), [200, reportsView()]));
on('PUT', '/settings/reports', async (c) => {
  const u = need(c.user, 'admin');
  const list = c.body.reports;
  if (!Array.isArray(list)) throw new HttpError(400, 'reports: array required');
  if (list.length > 32) throw new HttpError(400, 'reports: at most 32');
  if (list.length && !db.alertSettings.smtp?.host) throw new HttpError(400, 'scheduled reports are mailed through the SMTP server: configure it under Settings → Alert delivery first');
  const names = new Set<string>();
  const out: Json[] = [];
  for (const r of list) {
    const what = (m: string) => new HttpError(400, `report ${r.name}: ${m}`);
    const extra = Object.keys(r).find((k) => !['name', 'types', 'schedule', 'timezone', 'recipients', 'tenant'].includes(k));
    if (extra) throw new HttpError(400, `unknown field \`${extra}\``);
    if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$/.test(String(r.name))) throw new HttpError(400, 'name: [A-Za-z0-9._-]{1,64}');
    if (names.has(r.name)) throw what('names must be unique');
    names.add(r.name);
    const types = r.types ?? [];
    if (!types.length || new Set(types).size !== types.length || types.some((x: string) => !REPORT_TYPES.includes(x))) throw what('types: one or more of protection, failed, sla, storage, each once');
    const recipients = r.recipients ?? [];
    if (!recipients.length || recipients.length > 16) throw what('recipients: 1..=16 mail addresses');
    const bad = recipients.find((x: string) => !mailRe.test(x));
    if (bad) throw what(`recipients: "${bad}" is not a mail address`);
    const sch = parseSchedule(String(r.schedule));
    if (!sch) throw what(`bad schedule "${r.schedule}"`);
    if (sch.kind === 'hours') throw what('schedule: a report runs on weekdays (`Mon 07:00`, `daily 07:00`) or monthly (`monthly 1 07:00`)');
    const tz = String(r.timezone ?? 'UTC');
    try {
      new Intl.DateTimeFormat('en', { timeZone: tz });
    } catch {
      throw what(`unknown time zone "${tz}"`);
    }
    if (r.tenant && !db.tenants.some((x) => x.name === r.tenant)) throw what(`unknown tenant ${r.tenant}`);
    out.push({ name: r.name, types, schedule: r.schedule, timezone: tz, recipients, tenant: r.tenant ?? null });
  }
  db.reports = out;
  await audit(u.name, 'settings.reports', 'settings/reports', { reports: out });
  return [200, reportsView()];
});
on('POST', '/settings/reports/:name/send', async (c, [name]) => {
  const u = need(c.user, 'admin');
  const r = find(db.reports, (x) => x.name === decodeURIComponent(name), 'report');
  if (db.jobs.some((j) => j.kind === 'report_send' && j.params.name === r.name && ['queued', 'running'].includes(j.state))) throw new HttpError(409, 'this report is already being sent');
  const sch = parseSchedule(r.schedule);
  const period = sch ? schedulePeriod(r.schedule) : 7 * DAY;
  const p = { name: r.name, from: now() - period, to: now() };
  const j = addJob('report_send', '-', p, u.name, {
    plan: [`composing report ${r.name}: ${r.types.join(', ')}`, `mailing to ${r.recipients.join(', ')} via ${db.alertSettings.smtp?.host ?? '-'}`],
    duration: 3,
  });
  await audit(u.name, 'job.create', `job/${j.id}`, { kind: 'report_send', params: p });
  return [202, { job_id: j.id }];
});
/** A sent report: the result and `report.sent`, like the scheduler. */
function reportSent(j: Job) {
  const r = db.reports.find((x) => x.name === j.params.name);
  j.result = r
    ? { name: r.name, types: r.types, tenant: r.tenant, recipients: r.recipients, from: j.params.from, to: j.params.to, attachments: r.types.map((k: string) => `${r.name}-${k}-${isoDay(j.params.to - 1)}.csv`), rows: 42 }
    : null;
  void audit('scheduler', 'report.sent', `report/${j.params.name}`, { job: j.id, summary: j.result });
}
function seedReports(t: number) {
  db.reports = [
    { name: 'weekly-ops', types: ['protection', 'failed', 'sla'], schedule: 'Mon 07:00', timezone: 'Europe/Berlin', recipients: ['ops@example.com', 'it-lead@example.com'], tenant: null },
    { name: 'acme-monthly', types: ['protection', 'storage'], schedule: 'monthly 1 06:00', timezone: 'Europe/Berlin', recipients: ['it@acme.example.com'], tenant: 'acme' },
  ];
  // last Monday's weekly run (sent) and the monthly one
  const monday = Math.floor((t / DAY - ((Math.floor(t / DAY) + 3) % 7))) * DAY + 5 * 3600;
  for (const [r, at] of [[db.reports[0], monday], [db.reports[1], t - 11 * DAY]] as [Json, number][]) {
    const j = addJob('report_send', '-', { name: r.name, from: at - 7 * DAY, to: at }, 'scheduler', { state: 'ok', created: at, started: at, finished: at + 4, log: `report ${r.name} mailed to ${r.recipients.join(', ')}` });
    j.result = { name: r.name, types: r.types, recipients: r.recipients, rows: 37 };
  }
}

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
const MAPPING_ROLES = ['admin', 'security_officer', 'operator', 'tenant_user', 'viewer'];
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
  db.sessions.set(sid, { id: nextId(), userId: x.id, csrf: rand(16), created: now(), last: now(), ip: CLIENT_IP, ua: String(c.headers['user-agent'] ?? '').slice(0, 256) });
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
    client_secret_expires: typeof b.client_secret_expires === 'number' && b.client_secret_expires > 0 ? b.client_secret_expires : null,
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

// ---- alert delivery (§3; 13f notification rules)
const pubAlerts = () => {
  const a = structuredClone(db.alertSettings);
  if (a.smtp) {
    a.smtp.password_set = !!a.smtp.password;
    delete a.smtp.password;
  }
  for (const r of a.rules) {
    const h = r.channels.webhook?.headers;
    if (h) for (const k of Object.keys(h)) h[k] = null;
  }
  return a;
};
const TEMPLATE_FIELDS = ['id', 'ts', 'first_ts', 'last_ts', 'count', 'severity', 'kind', 'message', 'hint', 'tenant', 'host', 'alert_url'];
/** Like catalog::alerting::check_template: placeholders JSON-escaped, the result must be JSON. */
function checkTemplate(tpl: string): string | null {
  const sample: Json = { id: 42, ts: 1, first_ts: 1, last_ts: 2, count: 3, severity: 'critical', kind: 'job_failed', message: 'a "quoted"\nline', hint: 'x', tenant: '', host: 'nexus', alert_url: 'https://nexus/#/alerts?id=42' };
  let bad: string | null = null;
  const out = tpl.replace(/\{\{([^}]*)\}\}/g, (_, f: string) => {
    const k = f.trim();
    if (!TEMPLATE_FIELDS.includes(k)) bad = `unknown placeholder {{${k}}}`;
    return JSON.stringify(String(sample[k] ?? '')).slice(1, -1);
  });
  if (bad) return bad;
  try {
    JSON.parse(out);
    return null;
  } catch (e) {
    return `does not render to valid JSON: ${(e as Error).message}`;
  }
}
const mailRe = /^[^@\s]+@[^@\s]+$/;
on('GET', '/settings/alerts', (c) => (need(c.user, 'admin', 'security_officer'), [200, pubAlerts()]));
on('PUT', '/settings/alerts', async (c) => {
  const u = need(c.user, 'admin');
  const b = c.body;
  const old = db.alertSettings;
  let smtp = null;
  if (b.smtp) {
    const s = b.smtp;
    if (!String(s.host ?? '').trim()) throw new HttpError(400, 'smtp.host: required');
    if (!(Number.isInteger(s.port) && s.port > 0 && s.port < 65536)) throw new HttpError(400, 'smtp.port: 1..65535');
    if (!mailRe.test(String(s.from ?? ''))) throw new HttpError(400, 'smtp.from: a mail address');
    smtp = { host: s.host, port: s.port, starttls: !!s.starttls, from: s.from, user: String(s.user ?? ''), password: s.password || old.smtp?.password || '' };
  }
  const rules = (b.rules ?? []) as Json[];
  const names = new Set<string>();
  for (const r of rules) {
    const what = (m: string) => new HttpError(400, `rule ${r.name}: ${m}`);
    if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$/.test(String(r.name)) || names.has(r.name)) throw new HttpError(400, 'rules.name: unique, [A-Za-z0-9._-]{1,64}');
    names.add(r.name);
    if (!['info', 'warning', 'critical'].includes(r.min_severity)) throw what('min_severity: info, warning or critical');
    const email = r.channels?.email ?? [];
    if (email.some((x: string) => !mailRe.test(x))) throw what('email: up to 16 mail addresses');
    if (email.length && !smtp) throw what('email needs the SMTP server (smtp)');
    const w = r.channels?.webhook;
    if (w) {
      if (!/^https?:\/\/[^@\s/]+\S*$/.test(String(w.url))) throw what('webhook.url: http(s)://host[:port]/path, without user info');
      if (w.template) {
        const e = checkTemplate(w.template);
        if (e) throw what(`webhook.template: ${e}`);
      }
      const prev = old.rules.find((o: Json) => o.name === r.name)?.channels.webhook;
      for (const [h, v] of Object.entries(w.headers ?? {})) {
        if (v === null && !(prev && prev.url === w.url && prev.headers?.[h])) throw what(`webhook.headers: a value for ${h} is required (new header or URL changed)`);
        if (v === '') throw what('webhook.headers: values of 1..=4096 printable characters');
        w.headers[h] = v === null ? prev.headers[h] : 'sealed:demo';
      }
    }
  }
  const reminder = Number(b.reminder_hours ?? 24);
  if (!(reminder >= 0 && reminder <= 720)) throw new HttpError(400, 'reminder_hours: 0 (never) ..= 720');
  db.alertSettings = { smtp, rules, reminder_hours: reminder, retention_days: b.retention_days ?? old.retention_days };
  const shown = pubAlerts();
  await audit(u.name, 'settings.alerts', 'settings/alerts', shown);
  return [200, shown];
});
on('POST', '/settings/alerts/test', async (c) => {
  const u = need(c.user, 'admin');
  const a = db.alertSettings;
  const only = c.body?.rule as string | undefined;
  const out: Json = {};
  const rules = a.rules.filter((r: Json) => !only || r.name === only);
  if (only && !rules.length) out.rule = `error: no rule named ${only}`;
  for (const r of rules) {
    const key = (ch: string) => (only ? ch : `${r.name}/${ch}`);
    const w = r.channels.webhook;
    if (w) out[key('webhook')] = /bad|invalid/.test(w.url) ? 'error: HTTP 404 from the webhook' : 'ok';
    if (r.channels.email.length)
      out[key('email')] = !a.smtp ? 'error: no SMTP server configured' : /bad|invalid/.test(a.smtp.host) ? `error: ${a.smtp.host}:${a.smtp.port}: connection refused` : 'ok';
  }
  await audit(u.name, 'job.create', 'job/0', { kind: 'alert_test', params: only ? { rule: only } : {} });
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
on('GET', '/updates/registry', (c) => (need(c.user, 'admin', 'security_officer', 'operator'), [200, { configured: !!db.pullAuth, username: db.pullAuth?.username ?? null }]));
on('PUT', '/updates/registry', async (c) => {
  const u = need(c.user, 'admin');
  const b = c.body as { username?: string; token?: string };
  if (!b.username || !b.token || /\s/.test(b.username + b.token)) return [400, { error: 'username and token: printable characters, no spaces' }];
  db.pullAuth = { username: b.username };
  await audit(u.name, 'update.registry_auth', 'appliance/update', { username: b.username });
  return [200, { configured: true, username: b.username }];
});
on('DELETE', '/updates/registry', async (c) => {
  const u = need(c.user, 'admin');
  db.pullAuth = null;
  await audit(u.name, 'update.registry_auth_removed', 'appliance/update', {});
  return [200, { configured: false, username: null }];
});
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

// ---------------------------------------------------------------- Phase 14d: API tokens, web certificate

const p14 = {
  tokens: [] as { id: number; user_id: number; name: string; prefix: string; scope: 'read' | 'operator'; expires: number; created: number; last_used: number | null; last_ip: string | null }[],
  cert: {
    identity: null as Json | null,
    web: null as Json[] | null,
    prev: null as Json[] | null,
    pending: null as Json | null,
  },
};
const fpHex = () => rand(32).toUpperCase().replace(/(..)(?=.)/g, '$1:');
const certInfo = (subject: string, issuer: string, sans: string[], from: number, to: number, selfSigned = false, ca = false): Json => ({
  subject, issuer, sans, not_before: from, not_after: to, sha256: fpHex(), self_signed: selfSigned, ca,
});
const pemOf = (label: string, n: number) => {
  const body = b64(randomBytes(n)).replace(/(.{64})/g, '$1\n').trim();
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
};

function seedPhase14d2(t: number) {
  const admin = db.users.find((u) => u.name === 'admin')!;
  const op = db.users.find((u) => u.name === 'op')!;
  p14.tokens.push(
    { id: nextId(), user_id: admin.id, name: 'monitoring', prefix: rand(4), scope: 'read', expires: t + 86400 * 300, created: t - 86400 * 65, last_used: t - 240, last_ip: '198.51.100.20' },
    { id: nextId(), user_id: admin.id, name: 'ci-restore-test', prefix: rand(4), scope: 'operator', expires: t + 86400 * 5, created: t - 86400 * 85, last_used: t - 86400 * 2, last_ip: '198.51.100.31' },
    { id: nextId(), user_id: op.id, name: 'ansible', prefix: rand(4), scope: 'operator', expires: t + 86400 * 120, created: t - 86400 * 10, last_used: null, last_ip: null },
  );
  const sans = ['backup.example.com', '198.51.100.5'];
  p14.cert.identity = certInfo('CN=backup.example.com, O=NexusBackup appliance', 'CN=backup.example.com, O=NexusBackup appliance', sans, t - 86400 * 455, t + 86400 * 3200, true);
  p14.cert.web = [
    certInfo('CN=backup.example.com', 'CN=Example Corp Issuing CA 1, O=Example Corp', sans, t - 86400 * 40, t + 86400 * 325),
    certInfo('CN=Example Corp Issuing CA 1, O=Example Corp', 'CN=Example Corp Root CA, O=Example Corp', [], t - 86400 * 900, t + 86400 * 2700, false, true),
  ];
  db.alerts.push(
    mkAlert({ ts: t - 86400 * 3, severity: 'info', kind: 'cert_expiry', key: `cert_expiry:token:${p14.tokens[1].id}`, message: 'API token ci-restore-test of admin expires in 5 day(s)' }),
    mkAlert({ ts: t - 86400 * 6, severity: 'warning', kind: 'cert_expiry', key: 'cert_expiry:oidc_secret', message: 'The OIDC client secret (create a new one at the IdP, enter it in Settings → Single sign-on) expires in 24 day(s)' }),
  );
  db.oidc.client_secret_expires = t + 86400 * 24;
}

const pubToken = (x: (typeof p14.tokens)[number]) => ({
  id: x.id, user: db.users.find((u) => u.id === x.user_id)?.name ?? '?', name: x.name, prefix: x.prefix, scope: x.scope,
  expires: x.expires, created: x.created, last_used: x.last_used, last_ip: x.last_ip,
});
on('GET', '/auth/tokens', (c) => {
  const u = need(c.user);
  const all = c.query.get('all') === 'true';
  if (all) need(c.user, 'admin');
  return [200, p14.tokens.filter((x) => all || x.user_id === u.id).map(pubToken).sort((a, b) => a.user.localeCompare(b.user) || a.name.localeCompare(b.name))];
});
on('POST', '/auth/tokens', async (c) => {
  const u = need(c.user);
  const { name = '', scope = '', days = 0, current_password, current_totp } = c.body;
  if (!NAME_RE.test(String(name))) throw new HttpError(400, 'name: must match [A-Za-z0-9._-]{1,64} without a leading dot');
  if (!Number.isInteger(days) || days < 1 || days > 365) throw new HttpError(400, 'days: 1..=365');
  if (scope !== 'read' && scope !== 'operator') throw new HttpError(400, 'scope: read or operator');
  if (scope === 'operator' && (u.role === 'security_officer' || u.role === 'viewer')) throw new HttpError(400, 'scope: operator tokens need the admin, operator or tenant user role');
  if (u.auth !== 'oidc' && (current_password !== u.password || !/^\d{6}$/.test(String(current_totp ?? ''))))
    throw new HttpError(current_password === undefined ? 400 : 403, 're-authentication failed: wrong current password or TOTP code');
  if (p14.tokens.some((x) => x.user_id === u.id && x.name === name)) throw new HttpError(409, 'conflicts with existing data (duplicate name or still referenced)');
  const secret = rand(32);
  const x = { id: nextId(), user_id: u.id, name, prefix: rand(4), scope, expires: now() + days * 86400, created: now(), last_used: null, last_ip: null };
  p14.tokens.push(x);
  await audit(u.name, 'token.create', `token/${u.name}/${name}`, { id: x.id, prefix: x.prefix, scope, expires: x.expires });
  return [201, { ...pubToken(x), token: `nxt_${x.prefix}_${secret}` }];
});
on('DELETE', '/auth/tokens/:id', async (c, [id]) => {
  const u = need(c.user);
  const x = p14.tokens.find((t) => String(t.id) === id && (t.user_id === u.id || u.role === 'admin'));
  if (!x) throw new HttpError(404, 'not found');
  p14.tokens.splice(p14.tokens.indexOf(x), 1);
  await audit(u.name, 'token.revoke', `token/${pubToken(x).user}/${x.name}`, { id: x.id });
  return [200, { ok: true }];
});

const certStatus = () => {
  const c = p14.cert;
  return {
    active: c.web ? 'imported' : 'self_signed',
    chain: structuredClone(c.web ?? [c.identity]),
    identity: structuredClone(c.identity),
    pending: structuredClone(c.pending),
    can_revert: !!c.web || !!c.prev,
    previous: !!c.prev,
    pins: { replication_identity: c.identity?.sha256 ?? null, replication_peers: db.replPeers.filter((p) => p.state === 'enrolled').length },
  };
};
const MOCK_NAME_RE = /^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$|^[0-9.:a-f]+$/;
on('GET', '/certificate', (c) => (need(c.user, 'admin', 'security_officer'), [200, certStatus()]));
on('POST', '/certificate/csr', async (c) => {
  const u = need(c.user, 'admin');
  const cn = String(c.body.cn ?? '').trim().toLowerCase();
  const sans = [cn, ...(Array.isArray(c.body.sans) ? c.body.sans.map((s: unknown) => String(s).trim().toLowerCase()) : [])].filter((s, i, a) => s && a.indexOf(s) === i);
  for (const s of sans) if (!MOCK_NAME_RE.test(s)) throw new HttpError(400, `cn: "${s}" is neither a DNS name nor an IP address`);
  p14.cert.pending = { cn, sans, created: now(), csr_pem: pemOf('CERTIFICATE REQUEST', 300) };
  await audit(u.name, 'tls.csr', 'tls/web', { pending: { cn, sans } });
  return [200, { csr_pem: p14.cert.pending.csr_pem, pending: p14.cert.pending }];
});
on('POST', '/certificate/install', async (c) => {
  const u = need(c.user, 'admin');
  const pem = String(c.body.chain_pem ?? '');
  const p = p14.cert.pending;
  if (!p) throw new HttpError(400, 'no pending key: generate a CSR first');
  const n = (pem.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
  if (!n) throw new HttpError(400, 'no certificate found (paste PEM: -----BEGIN CERTIFICATE-----)');
  const t = now();
  const chain = [certInfo(`CN=${p.cn}`, 'CN=Example Corp Issuing CA 1, O=Example Corp', p.sans, t - 3600, t + 86400 * 397)];
  if (n > 1) chain.push(certInfo('CN=Example Corp Issuing CA 1, O=Example Corp', 'CN=Example Corp Root CA, O=Example Corp', [], t - 86400 * 900, t + 86400 * 2700, false, true));
  const warnings = n > 1 ? ['the issuer CN=Example Corp Root CA, O=Example Corp is not included: clients must trust it (or the root above it) already'] : [];
  p14.cert.prev = p14.cert.web;
  p14.cert.web = chain;
  p14.cert.pending = null;
  await audit(u.name, 'tls.install', 'tls/web', { subject: chain[0].subject, sha256: chain[0].sha256, not_after: chain[0].not_after, warnings });
  return [200, { chain, warnings }];
});
on('POST', '/certificate/revert', async (c) => {
  const u = need(c.user, 'admin');
  const k = p14.cert;
  if (!k.web && !k.prev) throw new HttpError(400, 'nothing to revert: the self-signed certificate is in use and there is no previous one');
  [k.web, k.prev] = [k.prev, k.web];
  const active = k.web ? 'imported' : 'self_signed';
  await audit(u.name, 'tls.revert', 'tls/web', { active });
  return [200, { active }];
});

// ---- diagnostics (Phase 14b): nexus-diag picks a request up after ~1 s and finishes after ~3 s
function diagChecks(t: number): Json[] {
  const c = (id: string, title: string, status: string, severity: number, detail: string) =>
    ({ id, title, status, severity, detail, manual: `15-troubleshooting-faq.md#check-${id.replace(/\./g, '-')}` });
  const day = (d: number) => new Date((t + d * 86400) * 1000).toISOString().slice(0, 10);
  return [
    c('disk.store', 'Disk space: /var/lib/nexus/chunkstore', 'pass', 1, '/var/lib/nexus/chunkstore: 58 % used, 1.7 TiB of 4.0 TiB free'),
    c('disk.var', 'Disk space: /var', 'pass', 1, '/var: 58 % used, 1.7 TiB of 4.0 TiB free'),
    c('disk.root', 'Disk space: /sysroot', 'pass', 1, '/sysroot: 31 % used, 27.5 GiB of 40.0 GiB free'),
    c('disk.boot', 'Disk space: /boot', 'pass', 1, '/boot: 42 % used, 557 MiB of 960 MiB free'),
    c('time.sync', 'Time synchronisation', 'pass', 1, 'stratum 2, offset +0.4 ms, normal, reference C035676C'),
    c('time.nts', 'Authenticated time sources (NTS)', 'pass', 1, '4 NTS source(s)'),
    c('egress', 'Outbound firewall', 'pass', 1, 'default-deny output chain loaded, allow-list sync active'),
    c('keyd', 'Key daemon', 'pass', 1, 'key daemon running, socket present'),
    c('tls.cert', 'Web certificate', 'warn', 2, `web certificate expires on ${day(21)} (21 days)`),
    c('audit.chain', 'Audit log hash chain', 'pass', 1, `${db.audit.length} entries, hash chain intact`),
    c('catalog.integrity', 'Catalog integrity', 'pass', 1, 'quick_check ok'),
    c('selinux', 'SELinux mode', 'pass', 1, 'enforcing'),
    c('systemd.failed', 'Failed system services', 'pass', 1, 'no failed units'),
    c('bootc', 'OS image (bootc)', 'pass', 1, `booted ${db.updates.booted?.version}, rollback ${db.updates.rollback?.version}`),
    c('smart', 'Disk health (SMART)', 'skip', 1, 'smartctl not installed'),
  ];
}
function seedDiag(t: number) {
  db.diag.push({ id: rand(16), kind: 'checks', by: 'admin', state: 'done', since: null, until: null, created: t - 2 * 3600 - 6, finished: t - 2 * 3600, error: null, checks: diagChecks(t), bundle: null });
}
function diagView(u: User, x: Json): Json | null {
  if (x.kind === 'bundle' && x.by !== u.name) return null;
  const t = now();
  if (x.state === 'queued' && t - x.queued >= 1) x.state = 'running';
  if (x.state === 'running' && t - x.queued >= 3) {
    Object.assign(x, { state: 'done', created: x.queued, finished: t, checks: diagChecks(t) });
    if (x.kind === 'bundle') {
      const token = rand(32);
      const body = `nexus-support bundle (mock) ${x.id}: ${new Date(x.since * 1000).toISOString()} .. ${new Date(x.until * 1000).toISOString()}\n`;
      db.downloads.set(token, { owner: x.by, filename: `nexus-support-${x.id}.tar.gz`, body, expires: t + 86400 });
      x.bundle = { bytes: 184_320 + Math.floor(Math.random() * 40_000), url: `/api/v1/downloads/${token}` };
    }
  }
  const { queued: _q, ...rest } = x;
  return { ...rest, expires: x.created ? x.created + 86400 : undefined };
}
const diagSubmit = async (u: User, kind: string, since: number | null, until: number | null) => {
  if (db.diag.some((x) => x.state === 'queued')) throw new HttpError(409, 'a diagnostics request is waiting to run; try again in a minute');
  const x = { id: rand(16), kind, by: u.name, state: 'queued', since, until, created: null, finished: null, error: null, checks: null, bundle: null, queued: now() };
  db.diag.unshift(x);
  await audit(u.name, `diag.${kind}`, `diag/${x.id}`, kind === 'bundle' ? { since, until } : {});
  return [202, { id: x.id, state: 'queued' }] as [number, Json];
};
const diagReader = (c: { user: User | null }) => {
  const u = need(c.user, 'admin', 'security_officer');
  if (u.tenant) throw new HttpError(403, 'appliance-wide');
  return u;
};
on('GET', '/diagnostics', (c) => {
  const u = diagReader(c);
  return [200, { items: db.diag.map((x) => diagView(u, x)).filter(Boolean) }];
});
on('POST', '/diagnostics/checks', (c) => diagSubmit(diagReader(c), 'checks', null, null));
on('POST', '/diagnostics/bundle', (c) => {
  const u = need(c.user, 'admin');
  const until = c.body.until ?? now();
  const since = c.body.since ?? until - 86400;
  if (!(since < until) || until > now() + 3600) throw new HttpError(400, 'since must be before until, and until not in the future');
  if (until - since > 31 * 86400) throw new HttpError(400, 'the time range is limited to 31 days');
  return diagSubmit(u, 'bundle', since, until);
});
on('GET', '/diagnostics/:id', (c, [id]) => {
  const u = diagReader(c);
  const v = diagView(u, find(db.diag, (x) => x.id === id, 'diagnostics run'));
  if (!v) throw new HttpError(404, 'diagnostics run not found');
  return [200, v];
});

// ---------------------------------------------------------------- hardware (Phase 16a/b)
// What nexus-disks reports (status.json + ops.json), with the web-api's `issues` and `summary`.
// Rebuilds, reshapes and self-tests advance with mock time; layout requests go through quorum().

function hwAttr(id: number, name: string, value: number, worst: number, thresh: number, raw: number, failing = false): Json {
  return { id, name, value, worst, thresh, raw, failing };
}
function hwSmartAta(o: { temp: number; poh: number; realloc?: number; pending?: number; offline?: number; failed?: boolean; ssd?: boolean; last?: Json; checked: number }): Json {
  const r = o.realloc ?? 0;
  const p = o.pending ?? 0;
  const off = o.offline ?? 0;
  const attrs = o.ssd
    ? [hwAttr(5, 'Reallocated_Sector_Ct', 100, 100, 10, r), hwAttr(9, 'Power_On_Hours', 98, 98, 0, o.poh), hwAttr(12, 'Power_Cycle_Count', 99, 99, 0, 38),
      hwAttr(177, 'Wear_Leveling_Count', 97, 97, 0, 31), hwAttr(194, 'Temperature_Celsius', 100 - o.temp + 31, 61, 0, o.temp), hwAttr(241, 'Total_LBAs_Written', 99, 99, 0, 9483712044)]
    : [hwAttr(1, 'Raw_Read_Error_Rate', o.failed ? 1 : 200, o.failed ? 1 : 200, 51, o.failed ? 48211 : 0, !!o.failed), hwAttr(3, 'Spin_Up_Time', 176, 175, 21, 8175),
      hwAttr(5, 'Reallocated_Sector_Ct', o.failed ? 120 : r ? 199 : 200, o.failed ? 120 : 199, 140, r, !!o.failed), hwAttr(9, 'Power_On_Hours', 79, 79, 0, o.poh),
      hwAttr(194, 'Temperature_Celsius', 112, 101, 0, o.temp), hwAttr(197, 'Current_Pending_Sector', 200, 200, 0, p),
      hwAttr(198, 'Offline_Uncorrectable', 100, 253, 0, off), hwAttr(199, 'UDMA_CRC_Error_Count', 200, 200, 0, 0)];
  return {
    available: true, health: o.failed ? 'failed' : 'passed', temperature: o.temp, power_on_hours: o.poh, reallocated: r, pending: p,
    offline_uncorrectable: off, percentage_used: null, media_errors: null, critical_warning: null, available_spare: null,
    self_test: { running: false, remaining: null, last: o.last ?? { type: o.ssd ? 'Short offline' : 'Extended offline', status: 'Completed without error', passed: true, hours: o.poh - 96 } },
    attributes: attrs, error: null, standby: false, checked: o.checked,
  };
}
function hwSmartNvme(used: number, poh: number, temp: number, checked: number): Json {
  const nv: Json = {
    critical_warning: 0, temperature: temp, available_spare: 100, available_spare_threshold: 10, percentage_used: used, data_units_read: 9418265,
    data_units_written: 21983410, power_cycles: 41, power_on_hours: poh, unsafe_shutdowns: 3, media_errors: 0, num_err_log_entries: 0,
  };
  return {
    available: true, health: 'passed', temperature: temp, power_on_hours: poh, reallocated: null, pending: null, offline_uncorrectable: null,
    percentage_used: used, media_errors: 0, critical_warning: 0, available_spare: 100,
    self_test: { running: false, remaining: null, last: { type: 'Short', status: 'Completed without error', passed: true, hours: poh - 26 } },
    attributes: Object.entries(nv).map(([name, raw]) => ({ id: null, name, value: null, worst: null, thresh: null, raw, failing: false })),
    error: null, standby: false, checked,
  };
}
function hwDisk(name: string, model: string, serial: string, size: number, type: string, transport: string, role: string, array: string | null, smart: Json, extra: Json = {}): Json {
  return {
    name, path: `/dev/${name}`, model, serial, wwn: type === 'nvme' ? `eui.002538${serial.slice(-6).toLowerCase()}` : `0x50014ee2${serial.slice(-6).toLowerCase()}`,
    size, type, transport, rotational: type === 'hdd', removable: false, role, array, why: null, smart, ...extra,
  };
}
function hwOp(op: string, state: string, by: string, created: number, detail: string | null, params: Json = {}, quorum_id: number | null = null, error: string | null = null): Json {
  return { id: rand(16), op, state, by, quorum_id, created, finished: state === 'queued' || state === 'running' ? null : created + 2, detail, error, params };
}

function seedHardware(t: number) {
  const TB4 = 4000787030016;
  const HDD = 'WDC WD40EFPX-68C6CN0';
  const hdd = (name: string, serial: string, role: string, array: string | null, o: Json = {}) =>
    hwDisk(name, HDD, serial, TB4, 'hdd', 'sata', role, array, hwSmartAta({ temp: 36 + (name.charCodeAt(2) % 4), poh: 15500 + name.charCodeAt(2), checked: t - 1200, ...o }));
  const ssd = (name: string, serial: string) =>
    hwDisk(name, 'Samsung SSD 870 EVO 250GB', serial, 250059350016, 'ssd', 'sata', 'system', 'md127', hwSmartAta({ temp: 31, poh: 9120, ssd: true, checked: t - 1200 }));
  const nvme = (name: string, serial: string, used: number) =>
    hwDisk(name, 'Samsung SSD 990 PRO 1TB', serial, 1000204886016, 'nvme', 'nvme', 'empty', null, hwSmartNvme(used, 1488, 41, t - 1200));
  db.hardware = {
    scanned: t - 120,
    smart_scanned: t - 1200,
    tools: { smartctl: true, mdadm: true },
    store: { path: '/var/lib/nexus/chunkstore', array: 'md126', array_uuid: '3f0c1a2b:4d5e6f70:81920a1b:2c3d4e5f', mounted: true, empty: false },
    disks: [
      ssd('sda', 'S6PNNM0T401234A'),
      ssd('sdb', 'S6PNNM0T401235B'),
      hdd('sdc', 'WD-WX12D3456701', 'data', 'md126'),
      hdd('sdd', 'WD-WX12D3456702', 'data', 'md126'),
      hdd('sde', 'WD-WX12D3456703', 'data', 'md126', { realloc: 24, pending: 8 }),
      hdd('sdf', 'WD-WX12D3456704', 'data', 'md126', {
        failed: true, realloc: 1400, pending: 312, offline: 57,
        last: { type: 'Short offline', status: 'Completed: read failure', passed: false, hours: 15519 },
      }),
      hdd('sdg', 'WD-WX12D3456705', 'data', 'md126'),
      hdd('sdh', 'WD-WX12D3456706', 'empty', null, { poh: 120 }),
      nvme('nvme0n1', 'S7DNNJ0W100001X', 3),
      nvme('nvme1n1', 'S7DNNJ0W100002Y', 4),
      hwDisk('sdi', 'WD Elements 25A2', '575832314131313', 2000398934016, 'hdd', 'usb', 'in_use', null,
        { available: false, health: null, temperature: null, power_on_hours: null, reallocated: null, pending: null, offline_uncorrectable: null,
          percentage_used: null, media_errors: null, critical_warning: null, available_spare: null, self_test: null, attributes: [],
          error: '/dev/sdi: Unknown USB bridge [0x1058:0x25a2 (0x1021)]', standby: false, checked: t - 1200 },
        { removable: true, why: 'has partitions' }),
    ],
    arrays: [
      {
        name: 'md126', path: '/dev/md126', md_name: 'nexus-data', uuid: '3f0c1a2b:4d5e6f70:81920a1b:2c3d4e5f', role: 'data', level: 'raid6',
        raid_devices: 4, size: 8001574060032, used_dev_size: 4000587055104, bitmap: 'Internal', mounts: ['/var/lib/nexus/chunkstore'],
        fs: { type: 'xfs', uuid: '0e7d8c9b-aaaa-4bbb-8ccc-1234567890ab', size: 8000500318208, used: 3871043584000 },
        members: [
          { disk: 'sdc', dev: 'sdc', serial: 'WD-WX12D3456701', state: 'active', slot: 0 },
          { disk: 'sdd', dev: 'sdd', serial: 'WD-WX12D3456702', state: 'active', slot: 1 },
          { disk: 'sde', dev: 'sde', serial: 'WD-WX12D3456703', state: 'active', slot: 2 },
          { disk: 'sdg', dev: 'sdg', serial: 'WD-WX12D3456705', state: 'rebuilding', slot: 3 },
          { disk: 'sdf', dev: 'sdf', serial: 'WD-WX12D3456704', state: 'faulty', slot: null },
        ],
        // the hot spare sdg took over when sdf failed; the rebuild runs for about 8 h
        sync: { action: 'recover', base: 41, t0: t, secs: 5 * 3600 },
      },
      {
        name: 'md127', path: '/dev/md127', md_name: 'root', uuid: '9a8b7c6d:5e4f3a2b:1c0d9e8f:7a6b5c4d', role: 'system', level: 'raid1',
        raid_devices: 2, size: 248352203776, used_dev_size: 248352203776, bitmap: 'Internal', mounts: ['/sysroot', '/var', '/etc'],
        fs: { type: 'xfs', uuid: '6a1f0b2c-1d2e-4f30-8a41-5b6c7d8e9f00', size: 247278460928, used: 22548578304 },
        members: [
          { disk: 'sda', dev: 'sda3', serial: 'S6PNNM0T401234A', state: 'active', slot: 0 },
          { disk: 'sdb', dev: 'sdb3', serial: 'S6PNNM0T401235B', state: 'active', slot: 1 },
        ],
        sync: null,
      },
    ],
    ops: [
      hwOp('add_spare', 'done', 'admin', t - 86400 * 30, 'WD-WX12D3456705 added to md126 as a hot spare', { array: '3f0c1a2b:4d5e6f70:81920a1b:2c3d4e5f', disk: 'WD-WX12D3456705' }, 31),
      hwOp('selftest', 'done', 'admin', t - 86400 * 2, 'short self-test started on WD-WX12D3456704, about 2 minutes', { disk: 'WD-WX12D3456704', type: 'short' }),
      hwOp('scan', 'done', 'op', t - 3 * 3600, 'rescan requested'),
    ],
  };
  db.alerts.push(
    mkAlert({
      ts: t - 3 * 3600, last_ts: t - 120, count: 37, severity: 'critical', kind: 'disk', key: 'disk:WD-WX12D3456704',
      message: 'Disk sdf (WDC WD40EFPX-68C6CN0, WD-WX12D3456704): SMART health check failed; 312 pending, 1400 reallocated, 57 offline-uncorrectable sectors',
    }),
    mkAlert({
      ts: t - 3 * 3600, last_ts: t - 120, count: 37, severity: 'critical', kind: 'disk', key: 'disk:md:nexus-data',
      message: 'Array md126 (nexus-data, raid6): degraded: 3 of 4 devices active, failed member sdf (WD-WX12D3456704)',
    }),
    mkAlert({
      ts: t - 3 * 3600, last_ts: t - 120, count: 37, severity: 'info', kind: 'disk', key: 'disk:md:nexus-data:sync',
      message: 'Array md126 (nexus-data, raid6): rebuilding 41.0 % (about 295 min left)',
    }),
    mkAlert({
      ts: t - 86400 * 4, last_ts: t - 1200, count: 96, severity: 'warning', kind: 'disk', key: 'disk:WD-WX12D3456703',
      message: 'Disk sde (WDC WD40EFPX-68C6CN0, WD-WX12D3456703): 8 pending, 24 reallocated sectors', acked_by: 'op',
      note: 'Replacement disk ordered.',
    }),
  );
}

/** Advances rebuilds / reshapes / self-tests to mock time; finished ones settle. */
function hwAdvance() {
  const h = db.hardware;
  const t = now();
  for (const a of h.arrays) {
    const s = a.sync;
    if (!s) continue;
    const pct = Math.min(100, s.base + ((100 - s.base) * (t - s.t0)) / s.secs);
    if (pct < 100) continue;
    a.sync = null;
    for (const m of a.members) if (m.state === 'rebuilding') m.state = 'active';
    if (s.action === 'reshape' && s.grow) {
      a.raid_devices += 1;
      const data = a.level === 'raid6' ? a.raid_devices - 2 : a.raid_devices - 1;
      a.size = a.used_dev_size * data;
      if (a.fs) a.fs.size = a.size - 1073741824;
      h.ops.push(hwOp('growfs', 'done', 'nexus-disks', t, `file system on ${a.name} grown to the new array size`, { array: a.uuid }));
    }
  }
  for (const d of h.disks) {
    const st = d.smart?.self_test;
    if (!st?.running) continue;
    const left = st.until - t;
    if (left > 0) {
      st.remaining = Math.max(10, Math.ceil((left / st.secs) * 10) * 10);
      continue;
    }
    const nv = d.type === 'nvme';
    d.smart.self_test = {
      running: false, remaining: null,
      last: { type: nv ? (st.kind === 'long' ? 'Extended' : 'Short') : st.kind === 'long' ? 'Extended offline' : 'Short offline', status: 'Completed without error', passed: true, hours: d.smart.power_on_hours },
    };
  }
}

function hwArrayView(a: Json): Json {
  const s = a.sync;
  const t = now();
  const progress = s ? Math.min(99.9, s.base + ((100 - s.base) * (t - s.t0)) / s.secs) : null;
  const finish = s ? Math.max(1, Math.round((s.secs - (t - s.t0)) / 60)) : null;
  const inSlot = a.members.filter((m: Json) => m.slot !== null && m.state !== 'spare' && m.state !== 'removed');
  const active = a.members.filter((m: Json) => m.state === 'active' && m.slot !== null).length;
  const faulty = a.members.filter((m: Json) => m.state === 'faulty');
  const degraded = active < a.raid_devices || inSlot.length < a.raid_devices;
  const action = s?.action ?? null;
  const state = action === 'recover' ? 'recovering' : action === 'reshape' ? 'reshaping' : action === 'resync' ? 'resyncing' : degraded ? 'degraded' : 'clean';
  const words = ['clean', degraded ? 'degraded' : '', state === 'recovering' ? 'recovering' : state === 'reshaping' ? 'reshaping' : state === 'resyncing' ? 'resyncing' : ''].filter(Boolean);
  const issues: Json[] = [];
  if (degraded) {
    issues.push({
      severity: 'critical',
      message: `degraded: ${active} of ${a.raid_devices} devices active` + (faulty.length ? `, failed member ${faulty.map((m: Json) => `${m.dev} (${m.serial})`).join(', ')}` : ''),
    });
  } else if (faulty.length) {
    issues.push({ severity: 'warning', message: `${faulty.length} failed member(s) still listed: ${faulty.map((m: Json) => m.dev).join(', ')} (replace or remove it)` });
  }
  if (action && progress !== null) {
    const what = { recover: 'rebuilding', reshape: 'reshaping', resync: 'resyncing' }[action as string] ?? action;
    issues.push({ severity: 'info', message: `${what} ${progress.toFixed(1)} % (about ${finish} min left)` });
  }
  const { sync: _s, ...rest } = a;
  return {
    ...rest, state, degraded, state_detail: words.join(', '), active_devices: active, failed_devices: faulty.length,
    spare_devices: a.members.filter((m: Json) => m.state === 'spare' || m.state === 'rebuilding').length,
    action, progress: progress === null ? null : Math.round(progress * 10) / 10, finish_minutes: finish, issues,
  };
}

function hwDiskIssues(d: Json): Json[] {
  const s = d.smart;
  const out: Json[] = [];
  if (!s?.available) return out;
  if (s.health === 'failed') out.push({ severity: 'critical', message: 'SMART health check failed' });
  const p = s.pending ?? 0;
  const r = s.reallocated ?? 0;
  const o = s.offline_uncorrectable ?? 0;
  if (p || r || o) {
    out.push({ severity: 'warning', message: [p && `${p} pending`, r && `${r} reallocated`, o && `${o} offline-uncorrectable`].filter(Boolean).join(', ') + ' sectors' });
  }
  if (s.critical_warning) out.push({ severity: 'warning', message: `NVMe critical warning 0x${s.critical_warning.toString(16)}` });
  if ((s.percentage_used ?? 0) >= 90) out.push({ severity: 'warning', message: `NVMe wear ${s.percentage_used} %` });
  if (s.media_errors) out.push({ severity: 'warning', message: `${s.media_errors} media errors` });
  const limit = d.type === 'hdd' ? 55 : 70;
  if (s.temperature !== null && s.temperature > limit) out.push({ severity: 'warning', message: `temperature ${s.temperature} °C (above ${limit} °C)` });
  if (s.self_test?.last && !s.self_test.last.passed && !s.self_test.running) out.push({ severity: 'warning', message: `last self-test: ${s.self_test.last.status}` });
  return out;
}

function hwView(): Json {
  hwAdvance();
  const h = db.hardware;
  // the mock's own self-test bookkeeping (until, secs, kind) stays inside
  const test = (st: Json) => st && (({ until: _u, secs: _s, kind: _k, ...x }) => x)(st);
  const disks = h.disks.map((d: Json) => ({ ...d, issues: hwDiskIssues(d), smart: d.smart && { ...d.smart, self_test: test(d.smart.self_test) } }));
  const arrays = h.arrays.map(hwArrayView);
  const all = [...disks, ...arrays].flatMap((x: Json) => x.issues);
  const crit = all.filter((i: Json) => i.severity === 'critical').length;
  const warn = all.filter((i: Json) => i.severity === 'warning').length;
  return {
    available: true, stale: false, scanned: h.scanned, smart_scanned: h.smart_scanned, tools: h.tools, store: h.store,
    summary: { state: crit ? 'critical' : warn ? 'warning' : 'ok', disks: disks.length, arrays: arrays.length, warnings: warn, critical: crit },
    disks, arrays, ops: [...h.ops].reverse(),
  };
}

function hwReader(c: Ctx): User {
  const u = need(c.user, 'admin', 'security_officer', 'operator', 'viewer');
  if (u.tenant) throw new HttpError(403, 'forbidden');
  return u;
}
const hwDiskBySerial = (serial: unknown) => {
  const d = db.hardware.disks.find((x: Json) => x.serial === serial);
  if (!d) throw new HttpError(404, `no disk with serial ${String(serial)}`);
  return d;
};
const hwInfo = (d: Json) => ({ serial: d.serial, model: d.model, size: d.size, name: d.name });
const hwTyped = (confirm: unknown) => new Set(String(confirm ?? '').split(/[\s,]+/).filter(Boolean));
function hwEmpty(d: Json, minSize?: number) {
  if (d.role !== 'empty') throw new HttpError(409, `disk ${d.serial} (${d.name}) is not empty: ${d.role}${d.why ? `, ${d.why}` : ''}`);
  if (minSize && d.size < minSize) throw new HttpError(409, `disk ${d.serial} (${d.name}) is smaller than the array members`);
}
function hwManaged(name: string): Json {
  const a = db.hardware.arrays.find((x: Json) => x.name === name);
  if (!a) throw new HttpError(404, 'array not found');
  if (a.role !== 'data' && a.role !== 'metadata') throw new HttpError(409, `${a.name} is not a data or metadata array: shown only`);
  return a;
}

on('GET', '/hardware', (c) => {
  hwReader(c);
  return [200, hwView()];
});
on('POST', '/hardware/scan', async (c) => {
  const u = need(c.user, 'admin', 'operator');
  if (u.tenant) throw new HttpError(403, 'forbidden');
  const o = hwOp('scan', 'done', u.name, now(), 'rescan requested');
  db.hardware.ops.push(o);
  db.hardware.scanned = db.hardware.smart_scanned = now();
  for (const d of db.hardware.disks) if (d.smart) d.smart.checked = now();
  await audit(u.name, 'hardware.scan', `hardware/${o.id}`, {});
  return [202, { id: o.id, state: 'queued' }];
});
on('POST', '/hardware/selftest', async (c) => {
  const u = need(c.user, 'admin');
  const { disk, type } = c.body;
  if (type !== 'short' && type !== 'long') throw new HttpError(400, 'type: short or long');
  const d = hwDiskBySerial(disk);
  if (!d.smart?.available) throw new HttpError(409, `SMART is not available on ${d.name}`);
  if (d.smart.self_test?.running) throw new HttpError(409, `a self-test is running on ${d.name}`);
  const secs = type === 'short' ? 120 : d.type === 'hdd' ? 465 * 60 : 1800;
  d.smart.self_test = { ...(d.smart.self_test ?? { last: null }), running: true, remaining: 90, until: now() + secs, secs, kind: type };
  const o = hwOp('selftest', 'done', u.name, now(), `${type} self-test started on ${d.serial}, about ${Math.round(secs / 60)} minutes`, { disk: d.serial, type });
  db.hardware.ops.push(o);
  await audit(u.name, 'hardware.selftest', `disk/${d.serial}`, { type, device: d.name });
  return [202, { id: o.id, state: 'queued' }];
});
on('POST', '/hardware/arrays', async (c) => {
  const u = need(c.user, 'admin');
  const { role, level, disks, confirm } = c.body;
  if (role === 'metadata') throw new HttpError(400, 'the metadata tier is a follow-up: only the data role can be created');
  if (role !== 'data') throw new HttpError(400, 'role: data');
  const min: Record<string, number> = { raid1: 2, raid5: 3, raid6: 4, raid10: 4 };
  if (!min[level]) throw new HttpError(400, 'level: raid1, raid5, raid6 or raid10');
  if (!Array.isArray(disks) || new Set(disks).size !== disks.length) throw new HttpError(400, 'disks: a list of distinct serial numbers');
  if (disks.length < min[level]) throw new HttpError(400, `${level} needs at least ${min[level]} disks`);
  if (level === 'raid10' && disks.length % 2) throw new HttpError(400, 'raid10 needs an even number of disks');
  const typed = hwTyped(confirm);
  if (typed.size !== disks.length || !disks.every((s: string) => typed.has(s))) throw new HttpError(400, 'type the serial numbers of the selected disks to confirm');
  const ds = disks.map(hwDiskBySerial);
  if (db.hardware.arrays.some((a: Json) => a.role === 'data')) throw new HttpError(409, 'a data array exists already: grow it or add spares');
  if (db.hardware.store.empty !== true) throw new HttpError(409, 'the store is not empty: a data array is only created while the store holds no backups');
  ds.forEach((d: Json) => hwEmpty(d));
  return quorum(u, 'disks.create_array', { op: 'create_array', role, level, disks, disk_info: ds.map(hwInfo) });
});
for (const kind of ['spare', 'replace', 'grow']) {
  on('POST', `/hardware/arrays/:name/${kind}`, async (c, [name]) => {
    const u = need(c.user, 'admin');
    const a = hwManaged(decodeURIComponent(name));
    const d = hwDiskBySerial(c.body.disk);
    if (String(c.body.confirm ?? '').trim() !== d.serial) throw new HttpError(400, 'type the serial number of the new disk to confirm');
    hwEmpty(d, a.used_dev_size);
    const v = hwArrayView(a);
    const failed = kind === 'replace' ? (c.body.failed ?? null) : undefined;
    if (kind === 'grow' && (!['raid5', 'raid6'].includes(a.level) || v.state !== 'clean')) {
      throw new HttpError(409, `${a.name} is ${a.level}, ${v.state}: only a clean raid5 or raid6 array grows by a disk`);
    }
    if (kind === 'replace') {
      if (failed !== null && !a.members.some((m: Json) => m.serial === failed)) throw new HttpError(409, `${failed} is not a member of ${a.name}`);
      if (failed === null && !v.degraded && !a.members.some((m: Json) => m.state === 'faulty')) {
        throw new HttpError(409, `${a.name} has no failed member: add the disk as a spare, or name the member to replace`);
      }
    }
    const op = { spare: 'add_spare', replace: 'replace', grow: 'grow' }[kind]!;
    const params: Json = { op, array: a.uuid, array_name: a.name, disk: d.serial, disk_info: [hwInfo(d)] };
    if (kind === 'replace') params.failed = failed;
    return quorum(u, `disks.${op}`, params);
  });
}

/** An approved disks.* request: what nexus-disks would do (web-executed quorum action). */
function hwExecute(action: string, p: Json, by: string, qid: number) {
  const h = db.hardware;
  const t = now();
  const disk = (s: string) => h.disks.find((d: Json) => d.serial === s);
  const q = qid || null;
  if (action === 'disks.create_array') {
    const name = 'md125';
    const ds = p.disks.map(disk);
    const min = Math.min(...ds.map((d: Json) => d.size));
    const n = ds.length;
    const dataDisks = p.level === 'raid1' ? 1 : p.level === 'raid5' ? n - 1 : p.level === 'raid6' ? n - 2 : Math.floor(n / 2);
    h.arrays.unshift({
      name, path: `/dev/${name}`, md_name: 'nexus-data', uuid: rand(16).replace(/(.{8})(?=.)/g, '$1:'), role: 'data', level: p.level,
      raid_devices: n, size: min * dataDisks, used_dev_size: min, bitmap: 'Internal', mounts: [h.store.path],
      fs: { type: 'xfs', uuid: rand(16).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5'), size: min * dataDisks - 1073741824, used: 0 },
      members: ds.map((d: Json, i: number) => ({ disk: d.name, dev: d.name, serial: d.serial, state: 'active', slot: i })),
      sync: { action: 'resync', base: 0, t0: t, secs: 6 * 3600 },
    });
    for (const d of ds) Object.assign(d, { role: 'data', array: name });
    Object.assign(h.store, { array: name, array_uuid: h.arrays[0].uuid, mounted: true });
    h.ops.push(hwOp('create_array', 'done', by, t, `${p.level} ${name} from ${n} disks, XFS, mounted at ${h.store.path}; the initial sync runs in the background`, p, q));
    return;
  }
  const a = h.arrays.find((x: Json) => x.uuid === p.array);
  const d = disk(p.disk);
  if (!a || !d) return;
  Object.assign(d, { role: a.role, array: a.name });
  if (action === 'disks.add_spare') {
    const degraded = hwArrayView(a).degraded;
    a.members.push({ disk: d.name, dev: d.name, serial: d.serial, state: degraded ? 'rebuilding' : 'spare', slot: degraded ? a.raid_devices - 1 : null });
    if (degraded) a.sync = { action: 'recover', base: 0, t0: t, secs: 8 * 3600 };
    h.ops.push(hwOp('add_spare', 'done', by, t, `${d.serial} added to ${a.name}${degraded ? ' (rebuild started)' : ' as a hot spare'}`, p, q));
  } else if (action === 'disks.replace') {
    const old = a.members.filter((m: Json) => (p.failed ? m.serial === p.failed : m.state === 'faulty'));
    const working = old.some((m: Json) => m.state === 'active');
    if (!working) {
      a.members = a.members.filter((m: Json) => !old.includes(m));
      for (const m of old) Object.assign(disk(m.serial) ?? {}, { role: 'in_use', array: null, why: 'contains a signature: linux_raid_member' });
    }
    // a free slot is rebuilt at once; otherwise (another disk is already rebuilding it) the new disk waits as a spare
    const used = new Set(a.members.filter((m: Json) => m.slot !== null).map((m: Json) => m.slot));
    const free = [...Array(a.raid_devices).keys()].find((i) => !used.has(i));
    a.members.push({ disk: d.name, dev: d.name, serial: d.serial, state: working || free !== undefined ? 'rebuilding' : 'spare', slot: working ? null : (free ?? null) });
    if (!a.sync && a.members.some((m: Json) => m.state === 'rebuilding')) a.sync = { action: 'recover', base: 0, t0: t, secs: 8 * 3600 };
    h.ops.push(hwOp('replace', 'done', by, t, working ? `${p.failed} is being replaced by ${d.serial} in ${a.name}` : `${old.map((m: Json) => m.serial).join(', ') || 'failed member'} removed from ${a.name}, ${d.serial} added: rebuild started`, p, q));
  } else if (action === 'disks.grow') {
    a.members.push({ disk: d.name, dev: d.name, serial: d.serial, state: 'active', slot: a.raid_devices });
    a.sync = { action: 'reshape', base: 0, t0: t, secs: 20 * 3600, grow: true };
    h.ops.push(hwOp('grow', 'done', by, t, `${a.name} reshaping to ${a.raid_devices + 1} devices; the file system grows when the reshape has finished`, p, q));
  }
}

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
      const lim = db.security.session;
      if (now() - sess.last > lim.idle_min * 60 || now() - sess.created > lim.absolute_h * 3600) db.sessions.delete(sid!);
      else {
        sess.last = now();
        user = db.users.find((u) => u.id === sess.userId && !u.disabled && !(u.expires && u.expires <= now())) ?? null;
      }
    }
    if (method !== 'GET' && path !== '/auth/login' && !path.startsWith('/auth/activate/') && user && req.headers['x-csrf-token'] !== sess?.csrf) {
      throw new HttpError(403, 'CSRF token missing or invalid');
    }
    const dl = /^\/downloads\/([0-9a-f]+)$/.exec(path);
    if (dl && method === 'GET') {
      const u = need(user);
      if (!canDownload(u)) throw new HttpError(403, 'this account may not download files');
      const d = db.downloads.get(dl[1]);
      if (!d || d.expires < now()) throw new HttpError(404, 'download not found or expired');
      if (d.owner !== u.name) throw new HttpError(403, 'only the requester can download this file');
      res.setHeader('Content-Disposition', `attachment; filename="${d.filename}"`);
      return send(200, d.body, 'application/octet-stream');
    }
    if (path === '/audit.csv' && method === 'GET') {
      const u = need(user, 'admin', 'security_officer');
      res.setHeader('Content-Disposition', 'attachment; filename="nexus-audit.csv"');
      return send(200, await auditCsv(u, url.searchParams), 'text/csv; charset=utf-8');
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
      const [status, out, type] = await h({ method, path, query: url.searchParams, body, raw, headers: req.headers, user, sid, res }, mm.slice(1));
      return send(status, out, type);
    }
    throw new HttpError(404, 'no such endpoint');
  } catch (e) {
    if (e instanceof HttpError) return send(e.status, { error: e.message });
    console.error(e);
    return send(500, { error: 'internal error' });
  }
}

// ---------------------------------------------------------------- console root access (14c)
// web-api: crates/web-api/src/console.rs; the gate on tty2 is simulated by POST /mock/console-gate.
const CONSOLE_TTL = 24 * 3600;
let consoleShell: Json | null = null;
/** quorum id -> code hash (issued), plus what the gate / a revocation did with it */
const consoleCodes = new Map<number, { hash: string; outcome: 'used' | 'revoked' | null }>();
const consoleNorm = (s: string) =>
  s.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
function consoleStatus(q: Json, t = now()): string {
  const fresh = q.decided_at && q.decided_at + CONSOLE_TTL > t;
  if (q.state === 'pending' || q.state === 'rejected') return q.state;
  if (q.state === 'approved') return fresh ? 'approved' : 'expired';
  if (q.state === 'executed') return consoleCodes.get(q.id)?.outcome ?? (fresh ? 'issued' : 'expired');
  return 'expired';
}
const consoleRows = () => db.quorum.filter((q) => q.action === 'console.unlock').sort((a, b) => b.id - a.id);
const consoleView = (q: Json) => ({
  id: q.id, hours: q.params.hours, reason: q.params.reason, requested_by: q.requested_by, created: q.created,
  decided_by: q.decided_by, decided_at: q.decided_at, code_expires: q.decided_at ? q.decided_at + CONSOLE_TTL : null,
  status: consoleStatus(q),
});
function consoleAdmin(c: Ctx, ...roles: Role[]): User {
  const u = need(c.user, ...roles);
  if (u.tenant) throw new HttpError(403, 'forbidden');
  return u;
}
function seedConsole(t: number) {
  // an earlier, used console session: approved by the security officer
  const q = {
    id: nextId(), action: 'console.unlock', params: { hours: 2, reason: 'Storage controller firmware: collect vendor logs (case 4711)' },
    requested_by: 'admin', created: t - 86400 * 33, decided_by: 'so', decided_at: t - 86400 * 33 + 1200, state: 'executed',
  };
  db.quorum.push(q);
  consoleCodes.set(q.id, { hash: 'seeded', outcome: 'used' });
  db.alerts.push(
    mkAlert({
      ts: t - 86400 * 33 + 1500, severity: 'critical', kind: 'console_root_shell',
      message: `root shell opened on the appliance console with one-time code #${q.id} (requested by admin, approved by so; reason: ${q.params.reason}), for up to 2 h`,
      acked_by: 'so', resolved_at: t - 86400 * 33 + 9000, resolved_by: 'so', note: 'Vendor logs collected, shell closed after 40 min.',
    }),
  );
}
on('GET', '/console/unlock', (c) => {
  consoleAdmin(c, 'admin', 'security_officer');
  return [200, consoleRows().slice(0, 50).map(consoleView)];
});
on('POST', '/console/unlock', async (c) => {
  const u = consoleAdmin(c, 'admin');
  const hours = Number(c.body.hours);
  const reason = String(c.body.reason ?? '').trim();
  if (!Number.isInteger(hours) || hours < 1 || hours > 8) throw new HttpError(400, 'hours: 1 to 8');
  if (!reason || reason.length > 500) throw new HttpError(400, 'reason: 1 to 500 characters');
  return quorum(u, 'console.unlock', { hours, reason });
});
on('POST', '/console/unlock/:id/code', async (c, [id]) => {
  const u = consoleAdmin(c, 'admin');
  const q = find(consoleRows(), (x) => x.id === Number(id), 'console unlock request');
  if (q.requested_by !== u.name) throw new HttpError(403, 'only the requester sees the code');
  const st = consoleStatus(q);
  if (['issued', 'used', 'revoked'].includes(st)) throw new HttpError(409, 'the code of this request was already shown');
  if (st !== 'approved') throw new HttpError(409, `request is ${st}`);
  const a = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const code = Array.from({ length: 4 }, () => Array.from(randomBytes(5), (x) => a[x & 31]).join('')).join('-');
  consoleCodes.set(q.id, { hash: await sha256(consoleNorm(code)), outcome: null });
  q.state = 'executed';
  const solo = q.decided_by === q.requested_by;
  db.alerts.push(
    mkAlert({
      ts: now(), severity: 'critical', kind: 'console_unlock',
      message: `console unlock code issued to ${u.name} for a root shell of up to ${q.params.hours} h on the appliance console (${solo ? 'approvals disabled' : `approved by ${q.decided_by}`}; reason: ${q.params.reason})`,
    }),
  );
  const expires = q.decided_at + CONSOLE_TTL;
  await audit(u.name, 'console.unlock_code', `console-unlock/${q.id}`, { hours: q.params.hours, approved_by: q.decided_by, expires });
  return [200, { id: q.id, code, hours: q.params.hours, expires }];
});
on('DELETE', '/console/unlock/:id', async (c, [id]) => {
  const u = consoleAdmin(c, 'admin', 'security_officer');
  const q = find(consoleRows(), (x) => x.id === Number(id), 'console unlock request');
  const st = consoleStatus(q);
  if (st !== 'approved' && st !== 'issued') throw new HttpError(409, `request is ${st}`);
  q.state = 'executed';
  consoleCodes.set(q.id, { hash: consoleCodes.get(q.id)?.hash ?? '', outcome: 'revoked' });
  await audit(u.name, 'console.unlock_revoke', `console-unlock/${q.id}`, { was: st });
  return [200, { id: q.id, status: 'revoked' }];
});
// MOCK ONLY (no such endpoint on the appliance): what the console gate on tty2 does with a code,
// for the demo and the manual's pictures. {code} opens a shell, {end: true} ends it.
on('POST', '/mock/console-gate', async (c) => {
  if (c.body.end) {
    if (consoleShell) await audit('console', 'console.root_shell_end', 'console', { how: 'exit', unlock: consoleShell.unlock });
    consoleShell = null;
    return [200, { ok: true }];
  }
  const h = await sha256(consoleNorm(String(c.body.code ?? '')));
  const q = consoleRows().find((x) => consoleCodes.get(x.id)?.hash === h && consoleStatus(x) === 'issued');
  if (!q) throw new HttpError(403, 'not accepted');
  consoleCodes.get(q.id)!.outcome = 'used';
  const at = now();
  const alert = mkAlert({
    ts: at, severity: 'critical', kind: 'console_root_shell',
    message: `root shell opened on the appliance console with one-time code #${q.id} (requested by ${q.requested_by}, approved by ${q.decided_by}; reason: ${q.params.reason}), for up to ${q.params.hours} h`,
  });
  db.alerts.push(alert);
  consoleShell = { at, until: at + q.params.hours * 3600, method: 'code', unlock: q.id, requested_by: q.requested_by, alert: alert.id };
  await audit('console', 'console.root_shell', `console-unlock/${q.id}`, { method: 'code', hours: q.params.hours, unlock: q.id });
  return [200, consoleShell];
});

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
      [t - 86400 * 8, 'admin', 'settings.forwarding', 'settings/forwarding', { syslog: { host: 'siem.example.com', port: 6514 }, https: null }],
    ];
    // the scheduler's daily anchor (head seq + hash leave the box with the forwarding)
    for (let d = 7; d >= 1; d--) hist.push([t - 86400 * d - 3000, 'scheduler', 'audit.anchor', 'audit/chain', { head_seq: 0, head_hash: '' }]);
    for (const q of [...db.quorum].filter((x) => x.state === 'pending').sort((a, b) => a.created - b.created))
      hist.push([q.created, q.requested_by, 'quorum.request', `quorum/${q.id}`, { action: q.action, params: q.params }]);
    hist.sort((a, b) => a[0] - b[0]);
    for (const [ts, actor, action, target, details] of hist) {
      const head = db.audit[db.audit.length - 1];
      const d = action === 'audit.anchor' ? { head_seq: head?.seq ?? 0, head_hash: head?.hash ?? '0'.repeat(64) } : details;
      await audit(actor, action, target, d, ts);
    }
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

// ---------------------------------------------------------------- legal holds (Phase 15c)

/** Set by a security officer (immediate); release = approval `snapshot.hold_release`. */
function openHold(tenant: string, source: string, time: number): Json | undefined {
  return db.holds.find((h) => h.tenant === tenant && h.source === source && h.time === time && ['active', 'advisory'].includes(h.state));
}
function activeHold(tenant: string, source: string, time: number): Json | undefined {
  const h = openHold(tenant, source, time);
  return h?.state === 'active' ? h : undefined;
}
function holdView(h: Json | undefined): Json | null {
  if (!h) return null;
  const q = db.quorum.find((x) => x.action === 'snapshot.hold_release' && ['pending', 'approved'].includes(x.state) && x.params.hold_id === h.id);
  return { ...h, release_quorum: q?.id ?? null };
}
/** The snapshot an alert offers to hold (anomaly: the last one before it; advisory: its own). */
function alertSnapshot(a: Json): Json | null {
  if (a.kind === 'anomaly') {
    const m = /last snapshot before: (\S+)\/(\d+)/.exec(a.message);
    return m && a.tenant ? { tenant: a.tenant, source: m[1], time: Number(m[2]) } : null;
  }
  if (a.kind === 'legal_hold_advisory') {
    const m = /^legal_hold_advisory:([^/]+)\/(.+)\/(\d+)$/.exec(a.key ?? '');
    return m ? { tenant: m[1], source: m[2], time: Number(m[3]) } : null;
  }
  return null;
}
function holdReason(b: Json): string {
  const r = typeof b?.reason === 'string' ? b.reason.trim() : '';
  if (!r || r.length > 500 || /[\u0000-\u001f]/.test(r)) throw new HttpError(400, 'reason: 1 to 500 characters, one line');
  return r;
}
/** Holds one snapshot; applies an advisory. null if already held. */
function holdOne(tenant: string, source: string, time: number, reason: string, by: string): Json | null {
  const open = openHold(tenant, source, time);
  if (open?.state === 'active') return null;
  if (open) {
    const from = { advisory_from: open.origin, primary_held_by: open.held_by };
    Object.assign(open, { state: 'active', reason, held_by: by, held_at: now() });
    for (const a of db.alerts)
      if (a.key === `legal_hold_advisory:${tenant}/${source}/${time}` && !a.resolved_at) Object.assign(a, { resolved_at: now(), resolved_by: by, auto: true });
    return { id: open.id, ...from };
  }
  const h = { id: nextId(), tenant, source, time, state: 'active', reason, held_by: by, held_at: now(), origin: null, released_by: null, approved_by: null, released_at: null };
  db.holds.push(h);
  return { id: h.id };
}
on('POST', '/snapshots/:tenant/:source/:time/hold', async (c, [tenant, source, time]) => {
  const u = need(c.user, 'security_officer');
  const [tn, src, tm] = [decodeURIComponent(tenant), decodeURIComponent(source), Number(time)];
  if (u.tenant && u.tenant !== tn) throw new HttpError(403, 'forbidden');
  const reason = holdReason(c.body);
  find(db.snapshots, (y) => y.tenant === tn && y.source === src && y.time === tm, 'snapshot');
  const out = holdOne(tn, src, tm, reason, u.name);
  if (!out) throw new HttpError(409, 'snapshot is already under a legal hold');
  await audit(u.name, 'snapshot.hold', `snapshot/${tn}/${src}/${tm}`, { reason, ...out });
  return [201, out];
});
on('DELETE', '/snapshots/:tenant/:source/:time/hold', (c, [tenant, source, time]) => {
  const u = need(c.user, 'security_officer', 'admin');
  const [tn, src, tm] = [decodeURIComponent(tenant), decodeURIComponent(source), Number(time)];
  if (u.tenant && u.tenant !== tn) throw new HttpError(403, 'forbidden');
  const h = activeHold(tn, src, tm);
  if (!h) throw new HttpError(404, 'snapshot is not under a legal hold');
  if (holdView(h)!.release_quorum) throw new HttpError(409, 'a release of this hold is already requested');
  return quorum(u, 'snapshot.hold_release', { tenant: tn, source: src, time: tm, hold_id: h.id });
});
on('POST', '/holds', async (c) => {
  const u = need(c.user, 'security_officer');
  const { tenant, source = null, from, to } = c.body ?? {};
  if (u.tenant && u.tenant !== tenant) throw new HttpError(403, 'forbidden');
  if (!Number.isInteger(from) || !Number.isInteger(to) || from > to) throw new HttpError(400, 'from must not be after to');
  const reason = holdReason(c.body);
  const held: string[] = [];
  for (const s of db.snapshots.filter((x) => x.tenant === tenant && (!source || x.source === source) && x.time >= from && x.time <= to))
    if (holdOne(s.tenant, s.source, s.time, reason, u.name)) held.push(`${s.source}/${s.time}`);
  if (held.length) await audit(u.name, 'snapshot.hold', `tenant/${tenant}`, { reason, source, from, to, snapshots: held });
  return [200, { held: held.length, snapshots: held }];
});
on('GET', '/holds', (c) => {
  const u = need(c.user);
  const st = c.query.get('state');
  return [200, byTenant(u, db.holds as any[]).filter((h) => !st || h.state === st).map(holdView).sort((a, b) => b!.id - a!.id)];
});
function seedHolds(t: number) {
  const of = (tenant: string, source: string, n: number) =>
    db.snapshots.filter((s) => s.tenant === tenant && s.source === source).sort((a, b) => b.time - a.time)[n];
  // a litigation hold on an older initech snapshot
  const lit = of('initech', 'vm-100', 6);
  db.holds.push({
    id: nextId(), tenant: 'initech', source: 'vm-100', time: lit.time, state: 'active', reason: 'Litigation hold, case 2026-17 (legal department)',
    held_by: 'so', held_at: t - 86400 * 4, origin: null, released_by: null, approved_by: null, released_at: null,
  });
  // the change-rate anomaly on acme/vm-301 names the last good snapshot ("Hold last good snapshot")
  const [bad, good] = [of('acme', 'vm-301', 0), of('acme', 'vm-301', 1)];
  db.alerts.push(
    mkAlert({
      ts: bad.time + 1500, severity: 'critical', kind: 'anomaly', key: 'anomaly:acme/vm-301', tenant: 'acme',
      message: `change-rate anomaly on acme/vm-301: snapshot ${bad.time}: 21.4 GiB new data that does not compress (1.01, usually 2.08): possibly encrypted; last snapshot before: vm-301/${good.time}`,
    }),
  );
  // the primary hq-primary holds a replicated globex snapshot: advisory here
  const adv = db.snapshots.filter((s) => s.tenant === 'globex').sort((a, b) => b.time - a.time)[3];
  db.holds.push({
    id: nextId(), tenant: 'globex', source: adv.source, time: adv.time, state: 'advisory', reason: 'Tax audit 2026 (hold all globex data)',
    held_by: 'legal-hq', held_at: t - 86400, origin: 'hq-primary', released_by: null, approved_by: null, released_at: null,
  });
  db.alerts.push(
    mkAlert({
      ts: t - 3 * 3600, severity: 'warning', kind: 'legal_hold_advisory', key: `legal_hold_advisory:globex/${adv.source}/${adv.time}`, tenant: 'globex',
      message: `primary hq-primary holds globex/${adv.source}/${adv.time} under a legal hold (Tax audit 2026 (hold all globex data), set by legal-hq); not applied here`,
    }),
  );
}
