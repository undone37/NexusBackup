// Shapes of the /api/v1 resources (docs/control-plane.md). Times are unix seconds.
// JSON columns of the catalog (offsite, config, gfs, guests, params, details) arrive parsed.

import type { BlackoutWindow, RateWindow, Span } from './schedule';

export type Role = 'admin' | 'security_officer' | 'operator' | 'tenant_admin' | 'tenant_user' | 'viewer';

/** Phase 19b: policy tiers (templates; shown in the SLA report and the tenant overview). */
export type Tier = 'bronze' | 'silver' | 'gold';

/** "View as tenant" (Phase 19b): the admin's session acts in this role within the tenant. */
export interface Impersonation {
  tenant: string;
  role: 'viewer' | 'tenant_admin';
}

export interface User {
  id: number;
  name: string;
  role: Role;
  tenant: string | null;
  disabled: boolean;
  created?: number;
  pending_activation?: boolean;
  activation_expires?: number | null;
  /** Phase 12: `oidc` users sign in through the IdP (no password / TOTP here) */
  auth?: 'local' | 'oidc';
  /** Phase 14d: may download restored files (explicit or the role's default) */
  can_download?: boolean;
  /** no sign-in from then on (unix time); null = never */
  expires?: number | null;
  last_login?: number | null;
}

/** One-time activation code (or half of it) as returned by user create / new_activation / approve. */
export interface Activation {
  name?: string;
  code: string;
  parts: number;
  part: number;
  expires: number | null;
  /** "/#/activate?name=…" — prefix with location.origin */
  path: string;
}

export interface ApprovalsState {
  enabled: boolean;
  possible_approvers: number;
  recommend: boolean;
  /** Phase 14d: approvals on, but fewer than three people could approve */
  few_approvers?: boolean;
  pending_disable: number | null;
}

export interface GcPending {
  tenant: string;
  job: number;
  reason: string;
  created: number;
}

/** Hetzner Storage Box (SFTP). */
export interface SftpRemote {
  type: 'sftp';
  host: string;
  port?: number;
  user: string;
  /** path of the SSH private key on the appliance (no inline SSH keys) */
  key_file: string;
  host_key: string;
  base_dir?: string;
}

/** S3 with optional Object Lock (docs/s3-offsite.md). */
export interface S3Remote {
  type: 's3';
  /** https://host[:port] */
  endpoint: string;
  region: string;
  bucket: string;
  prefix?: string;
  access_key: string;
  /** write-only: sealed to the scheduler, never returned by GET */
  secret_key?: string;
  secret_key_set?: boolean;
  path_style?: boolean;
  /** PEM: CA or pinned endpoint certificate (on-prem endpoints) */
  ca_pem?: string;
  storage_class_packs?: string;
  storage_class_meta?: string;
  /** bucket has Object Lock: compliance retention on every object */
  lock?: boolean;
}

/** `tenants.offsite`; `{}` = no offsite copy. Older UI versions stored the SFTP fields flat. */
export interface TenantOffsite {
  remote?: SftpRemote | S3Remote;
  /** bytes per second over all uploaders */
  bwlimit?: number | null;
  /** Phase 17a: pause / limit windows in `timezone` */
  windows?: RateWindow[];
  timezone?: string;
  uploaders?: number;
  host?: string;
  port?: number;
  user?: string;
  key_file?: string;
  host_key?: string;
  base_dir?: string;
}

export interface Tenant {
  name: string;
  offsite: TenantOffsite;
  /** soft storage quota in bytes (Phase 13d); null = none */
  quota_bytes?: number | null;
  /** Phase 17f: deactivated (no backups, offsite, replication; its accounts are refused) */
  disabled?: boolean;
  disabled_at?: number | null;
  disabled_by?: string | null;
  disabled_reason?: string | null;
  /** Phase 19b: immutable 128-bit id (32 hex), used for replication matching */
  uid?: string;
  /** Phase 19b: policies the provider assigned (a tenant admin may use only these) */
  policies?: number[];
  /** tiers of the assigned policies */
  tiers?: Tier[];
}

/** A deleted tenant name (Phase 19b): never re-created. */
export interface TenantTombstone {
  name: string;
  uid: string | null;
  deleted_at: number;
  deleted_by: string;
}

/** `GET /policies/templates` (Phase 19b). */
export interface PolicyTemplate {
  tier: Tier;
  name: string;
  schedule: string;
  gfs: Gfs;
  offsite: boolean;
}

/** Config of a `pve` source. */
export interface SourceConfig {
  host: string;
  port: number;
  ca_pem?: string;
  token_id: string;
  /** write-only: never returned by GET */
  token_secret?: string;
  token_secret_set?: boolean;
  nodes: Record<string, unknown>;
  storage: string;
  fleecing_storage: string;
  /** Phase 18: fleecing space guard (absent fields = defaults 15 % / 20 GiB / 5 %) */
  fleecing_guard?: { min_free_pct?: number; min_free_gib?: number; cancel_free_pct?: number; interval_secs?: number };
  /** Phase 22b: at most this many guests of the source at once (caps the groups' parallel guests, 1..=8) */
  max_parallel?: number;
  /** Phase 22b: at most n guests at once with a disk on the PVE storage */
  storage_caps?: Record<string, number>;
  read_limit?: ReadLimit;
}

/** Phase 22b: appliance-side read limit of a source (bytes/s + `limit` windows in `timezone`). */
export interface ReadLimit {
  bwlimit?: number;
  windows?: { days: string[]; from: string; to: string; action: 'limit'; rate_bytes: number }[];
  timezone?: string;
}

/** Phase 22b: sizing note of share / TrueNAS sources (newest backup's entries, RAM estimate). */
export interface SourceSizing {
  entries: number;
  est_ram_bytes: number;
  mem_total: number | null;
  warn: boolean;
}

/** Phase 22b: the restore-priority switch (GET /restore-priority). */
export interface RestorePriority {
  active: boolean;
  until?: number;
  since?: number;
  by?: string;
  reason?: string;
  max_hours: number;
}

/** Config of a `linux` source (a host with an enrolled backup agent). No secrets. */
export interface LinuxSourceConfig {
  agent_id: string;
  /** absolute paths, 1..=64 */
  paths: string[];
  /** glob patterns, 0..=256 */
  excludes: string[];
  /** run the agent's pre/post hooks */
  hooks: boolean;
  /** Phase 15e: include roots, regex excludes, nested mounts (agents of this release) */
  include?: string[];
  exclude_regex?: string[];
  cross_mounts?: boolean;
  skip_fstypes?: string[];
}

/** Config of a `truenas` source (docs/truenas-connector.md). Secrets are write-only. */
export interface TrueNasSourceConfig {
  host: string;
  port: number;
  connect_addr?: string;
  /** the TrueNAS certificate (pinned) and/or its CA */
  ca_pem: string;
  /** TrueNAS user owning the API key (privilege: SNAPSHOT_WRITE, SNAPSHOT_DELETE, DATASET_READ) */
  user: string;
  /** API key: write-only */
  token_secret?: string;
  token_secret_set?: boolean;
  ssh: {
    host: string;
    port: number;
    user: string;
    /** pinned SSH host key `ssh-ed25519 AAAA…` */
    host_key: string;
    /** appliance private key: write-only */
    key_pem?: string;
    key_pem_set?: boolean;
    public_key?: string;
    from?: string;
  };
  datasets: string[];
  recursive: boolean;
  sudo: boolean;
  zfs_sudo: boolean;
  /** Phase 22b "use existing snapshots": prefix of the periodic snapshots to back up (e.g. `auto-`) */
  existing_snapshots?: string;
  read_limit?: ReadLimit;
  /** returned by the API: the line for the TrueNAS user's "SSH public key" field */
  authorized_keys?: string;
}

/**
 * Config of an `nfs` or `smb` share source (docs/nas-connector.md). Optional
 * fields are omitted when unset; SMB secrets (`password`, `keytab` base64) are
 * write-only (`password_set` / `keytab_set` in answers).
 */
export interface ShareSourceConfig {
  host: string;
  port?: number;
  /** NFS: 3 | 4.0 | 4.1 | 4.2; SMB: 2.1 | 3 | 3.0 | 3.02 | 3.1.1 */
  version?: string;
  /** NFS export path */
  export?: string;
  /** NFSv3 mountd port */
  mount_port?: number;
  /** SMB */
  share?: string;
  user?: string;
  domain?: string;
  sec?: 'ntlmssp' | 'krb5';
  sign?: boolean;
  seal?: boolean;
  password?: string;
  password_set?: boolean;
  keytab?: string;
  keytab_set?: boolean;
  principal?: string;
  /** NAS snapshot directory below the share root */
  snapshot_dir?: string;
  snapshot_prefix?: string;
  snapshot_order?: 'name' | 'mtime';
  excludes?: string[];
  /** Phase 15e: include roots (share paths) and regex excludes */
  include?: string[];
  exclude_regex?: string[];
  threads?: number;
  xattrs?: boolean;
  timeout_secs?: number;
  read_limit?: ReadLimit;
}

interface SourceBase {
  id: number;
  tenant: string;
  name: string;
  /** Phase 13b: null = active, -1 = indefinitely, else unix time */
  maintenance_until?: number | null;
  /** Phase 22b (share / TrueNAS sources): other listed sources backing up the same paths */
  overlaps?: { id: number; name: string }[];
  sizing?: SourceSizing | null;
}
export type PveSource = SourceBase & { kind: 'pve'; config: SourceConfig };
export type LinuxSource = SourceBase & { kind: 'linux'; config: LinuxSourceConfig };
export type TrueNasSource = SourceBase & { kind: 'truenas'; config: TrueNasSourceConfig };
export type NfsSource = SourceBase & { kind: 'nfs'; config: ShareSourceConfig };
export type SmbSource = SourceBase & { kind: 'smb'; config: ShareSourceConfig };
export type ShareSource = NfsSource | SmbSource;
/**
 * Source of a plugin kind (`plugin:<kind>`, docs/plugin-system.md). `config` follows the kind's
 * `config_schema`; secret fields are write-only (GET returns `<field>_set: boolean` instead).
 */
export type PluginSource = SourceBase & { kind: `plugin:${string}`; config: Record<string, unknown> };
export type Source = PveSource | LinuxSource | TrueNasSource | NfsSource | SmbSource | PluginSource;
export type SourceKind = Source['kind'];

/** Linux backup agent (docs/agent-protocol.md). `id` is 16 hex chars. */
export interface Agent {
  id: string;
  tenant: string;
  name: string;
  host: string;
  port: number;
  /** null = not enrolled yet */
  enrolled_at: number | null;
  cert_sha256: string | null;
  /** expiry of the current one-time enrollment token (null = none) */
  token_expires: number | null;
  last_seen: number | null;
  version: string | null;
  os: string | null;
  /** Phase 15f: limits sent with every backup ({} = none) */
  limits: AgentLimits | Record<string, never>;
  /** validity of the current certificate (reported by each session; null = not yet known) */
  cert_issued: number | null;
  cert_expires: number | null;
  /** a renewed certificate was issued but no session confirmed it yet */
  cert_renewal_pending: boolean;
  /** Phase 24a endpoint status (scheduler poll every 2 min; null = never polled) */
  reachable?: boolean | null;
  last_poll?: number | null;
  power?: AgentPower | null;
  ui_policy?: AgentUiPolicy | Record<string, never>;
  ui_policy_version?: number;
  /** version the agent has stored (null = not yet delivered) */
  ui_policy_seen?: number | null;
  laptop?: AgentLaptop | Record<string, never>;
  /** a skipped / failed scheduled run waits for the agent (run_missed) */
  missed_at?: number | null;
  /** last "back up now" request from the endpoint */
  last_request?: AgentRequest | null;
  /** Phase 26: reach via this edge proxy (direct first, then the edge; null = direct only) */
  edge_id?: string | null;
  /** route of the last successful session: direct | edge */
  via?: string | null;
  /** edge setting the agent confirmed (`host:port`; null = none pushed yet) */
  edge_pushed?: string | null;
  /** Phase 27 (protocol v1.8 host facts, null = not reported yet / older agent) */
  arch?: string | null;
  /** bundle | deb | rpm | msi | manual */
  install?: string | null;
  gui_version?: string | null;
  /** "1.8" with chunked updates, "1.7" = older (single-frame binary updates only); null = unknown */
  protocol?: string | null;
  tags?: string[];
  update_target?: string | null;
  update_state?: AgentUpdateState | null;
  update_error?: string | null;
  update_attempts?: number;
  update_at?: number | null;
}

/** Phase 27: per-agent update state (docs/agent-update-plan.md "Implementation") */
export type AgentUpdateState = 'pending' | 'sending' | 'installing' | 'ok' | 'failed' | 'rolled_back';

export interface AgentArtifact {
  /** relative path in the release (linux-x86_64/nexus-agent_0.2.0_amd64.deb, ...) */
  name: string;
  /** binary | deb | rpm | msi | desktop-deb | desktop-rpm | bundle | exe */
  kind: string;
  os: string;
  arch: string;
  version: string;
  size: number;
  sha256: string;
}

export interface AgentRelease {
  version: string;
  source: 'image' | 'upload';
  signed: boolean;
  /** name of the pinned key that verified the manifest */
  key: string | null;
  error: string | null;
  protocol: string | null;
  min_appliance: string | null;
  released: string | null;
  notes: string | null;
  artifacts: AgentArtifact[];
}

export interface AgentReleases {
  /** newest signed release (null = none) */
  recommended: string | null;
  releases: AgentRelease[];
}

export interface AgentDownload {
  token: string;
  url: string;
  name: string;
  size: number;
  sha256: string;
  expires: number;
}

export interface RolloutScope {
  tenant?: string;
  group_id?: number;
  os?: string;
  tag?: string;
  agents?: string[];
}

export interface UpdateWindow {
  days: string[];
  from: string;
  to: string;
}

export type RolloutState = 'pending_approval' | 'running' | 'paused' | 'cancelled' | 'done' | 'rejected';
export type RolloutItemState = 'waiting' | 'queued' | 'running' | 'ok' | 'failed' | 'skipped' | 'cancelled';

export interface RolloutCounts {
  total: number;
  waiting: number;
  queued: number;
  running: number;
  ok: number;
  failed: number;
  skipped: number;
  cancelled: number;
}

export interface Rollout {
  id: number;
  version: string;
  scope: RolloutScope;
  canary: number;
  canary_pct: number | null;
  soak_minutes: number;
  concurrency: number;
  max_failures: number;
  max_failure_pct: number;
  windows: UpdateWindow[];
  rollback: boolean;
  automatic: boolean;
  state: RolloutState;
  reason: string | null;
  /** 0 = canary wave, 1 = the rest */
  wave: number;
  quorum_id: number | null;
  created: number;
  created_by: string;
  finished: number | null;
  counts: RolloutCounts;
}

export interface RolloutItem {
  agent_id: string;
  name: string;
  tenant: string;
  wave: number;
  state: RolloutItemState;
  job_id: number | null;
  attempts: number;
  error: string | null;
  from_version: string | null;
  version: string | null;
  updated: number | null;
}

export interface RolloutDetail extends Rollout {
  items: RolloutItem[];
}

export interface AgentUpdateSetting {
  tenant: string;
  /** null / 0 = the whole tenant */
  group_id: number | null;
  mode: 'manual' | 'automatic';
  windows: UpdateWindow[];
  canary: number;
  soak_minutes: number;
  updated: number | null;
  updated_by: string | null;
}

/** Phase 26: what the edge's control link reports (docs/edge.md) */
export interface EdgeHealth {
  version: string;
  uptime_secs: number;
  cert_sha256?: string;
  agents_online: string[];
  connections: number;
  relays: number;
  refused: number;
  rate_limited: number;
  configured: boolean;
}

/** Phase 26: an edge proxy for roaming agents (Settings → Edges, admins) */
export interface Edge {
  id: string;
  name: string;
  /** control address the appliance dials */
  host: string;
  port: number;
  /** address the agents dial */
  public_host: string;
  public_port: number;
  /** pinned edge certificate (null = not enrolled) */
  cert_sha256: string | null;
  enrolled_at: number | null;
  token_expires: number | null;
  last_seen: number | null;
  online: boolean;
  version: string | null;
  health: EdgeHealth | null;
  log: string[];
  /** agents routed through this edge */
  agents: number;
}

/** POST /edges, POST /edges/{id}/token: the one-time token, shown once */
export interface EdgeToken {
  id: string;
  name?: string;
  token: string;
  expires: number;
  setup: string;
}

export interface AgentPower {
  on_battery: boolean | null;
  battery_percent: number | null;
  metered: boolean | null;
  network_name: string | null;
}

/** PUT /agents/{id}/ui-policy (admins): branding / visibility of the endpoint UIs */
export interface AgentUiPolicy {
  accent: string;
  header: string;
  hide_backup_now: boolean;
  hide_tray: boolean;
}

/** PUT /agents/{id}/laptop: skip scheduled runs on battery / metered networks, catch up missed runs */
export interface AgentLaptop {
  min_battery: number;
  skip_metered: boolean;
  run_missed: boolean;
  retry_hours: number;
}

export interface AgentRequest {
  id: string;
  queued_at: number | null;
  received: number;
  jobs: number[];
  refused: string | null;
}

/** GET /agents/{id}/sessions: what the endpoint UI shows (newest first) */
export interface AgentSession {
  job: number;
  kind: 'Backup' | 'Restore';
  started: number;
  ended: number;
  result: 'Success' | 'Warning' | 'Failed' | 'Cancelled';
  read_bytes: number;
  transferred_bytes: number;
  new_bytes: number;
  warnings: number;
  first_error: string;
  snapshot_time: number | null;
  /** the agent acknowledged it (null = waits for the next poll) */
  delivered: number | null;
}

/** PUT /agents/{id}/limits: bytes/s (0 = unlimited, else >= 65536) and nice 0..19 */
export interface AgentLimits {
  bwlimit: number;
  nice: number;
}

/** One-time enrollment token: only in the answer of POST /agents and POST /agents/{id}/token. */
export interface AgentToken {
  token: string;
  install_command: string;
  token_expires: number;
}

export type AgentStatus = 'enrolled' | 'pending' | 'expired';

/** Phase 19a: bare-metal recovery / P2V session (GET /rescue). */
export type RescueState = 'issued' | 'waiting' | 'running' | 'done' | 'failed' | 'cancelled' | 'expired';
export interface RescueP2v {
  source_id: number;
  node: string;
  vmid: number;
  name: string;
  storage: string;
  iso: string;
  iso_storage: string;
  bridge: string;
  memory: number;
  cores: number;
  appliance: string;
  appliance_sha256: string;
  /** the created VM (once the p2v job made it) */
  vm?: { vmid: number; node: string; config_volid: string };
}
export interface RescueSession {
  id: string;
  tenant: string;
  agent_id: string;
  agent_name: string | null;
  token_expires: number;
  state: RescueState;
  /** where the rescue console listens (after its check-in) */
  host: string | null;
  port: number | null;
  disks: { path: string; size: number }[];
  checked_in: number | null;
  snapshot_time: number | null;
  reboot: boolean;
  step: 'apply' | 'restore' | 'finish' | null;
  job_id: number | null;
  p2v: RescueP2v | null;
  message: string | null;
  created: number;
  created_by: string;
  token_valid: boolean;
}

/** Phase 24d: fleet secret (GET /fleets; the secret itself only in the POST answer) */
export interface Fleet {
  id: string;
  name: string;
  tenant: string;
  created: number;
  created_by: string;
  expires: number;
  max_uses: number | null;
  uses: number;
  revoked: boolean;
  auto_accept: boolean;
  port: number;
  /** CIDR (≤ /22 resp. /118), addresses or host names the scheduler scans */
  ranges: string[];
  /** template group (protection group of a linux source) for new agents */
  group: string | null;
  group_rules: { pattern: string; group: string }[];
  last_scan: number | null;
  /** candidates awaiting acceptance */
  awaiting: number;
}

export interface FleetCreated extends Fleet {
  secret: string;
  install: { linux: string; linux_file: string; windows: string };
}

/** An agent found by a fleet scan (GET /fleet/candidates) */
export interface FleetCandidate {
  id: number;
  fleet_id: string;
  fleet: string;
  tenant: string;
  host: string;
  port: number;
  hostname: string;
  os: string;
  version: string;
  first_seen: number;
  last_seen: number;
  state: 'awaiting' | 'accepted' | 'rejected';
  agent_id: string | null;
}

export type Overwrite = 'never' | 'if_older' | 'always';

export interface Gfs {
  /** Phase 18b: keep every snapshot of the last N hours (absent/0 = off) */
  recent?: number;
  daily: number;
  weekly: number;
  monthly: number;
  yearly: number;
}

export interface Policy {
  id: number;
  name: string;
  schedule: string;
  gfs: Gfs;
  offsite: boolean;
  /** Phase 13b run control */
  retry: { count: number; delay_min: number };
  blackout: BlackoutWindow[];
  sla_minutes: number | null;
  /** Phase 15d */
  require_consistency?: RequireConsistency;
  /** Phase 15e: global excludes for every agent and share source of the policy's groups */
  file_filters: FileFilters;
  /** Phase 19b: policy tier (Bronze/Silver/Gold) or none */
  tier?: Tier | null;
}

export interface FileFilters {
  exclude: string[];
  exclude_regex: string[];
}

export interface Group {
  id: number;
  tenant: string;
  source_id: number;
  policy_id: number;
  name: string;
  /** pve: VM/CT IDs; linux: exactly `[source.config.agent_id]`; truenas: datasets of the source; nfs/smb: none (the share). Empty for mode all/tags. */
  guests: (number | string)[];
  /** IANA zone of the schedule and blackout windows */
  timezone: string;
  /** GET /groups only: null = active, -1 = indefinitely, else unix time */
  paused_until?: number | null;
  /** of the group's source */
  maintenance_until?: number | null;
  blackout_active?: boolean;
  /** GET /groups only: the guests a backup covers now (mode all/tags resolved from the inventory) */
  resolved_guests?: (number | string)[];
  /** Phase 13c: explicit = `guests`; all = every inventory guest of the source; tags = guests with any `selector` tag */
  mode: GroupMode;
  /** mode tags: `pool:x`, `tag:y`, `node:n`, `type:qemu`, … */
  selector: string[];
  /** guest ids never protected by this group (mode all/tags) */
  exclude: string[];
  /** pve groups: list the VM/CT file systems after each backup (sandboxed parser, Phase 31) for the file search; default on */
  index_files?: boolean;
  /** Phase 15e (PVE groups): disk keys not backed up, `*` = every guest, else per vmid */
  exclude_disks: Record<string, string[]>;
  /** placeholder: a restore recreates excluded disks empty; omit: left out of the restored config */
  exclude_disks_mode: 'placeholder' | 'omit';
  /** guests backed up at once (PVE and plugin groups), 1..8 */
  parallel_guests: number;
  /** Phase 28, GET /groups only: scheduled YARA scan (policy schedule grammar), null = off */
  scan_schedule?: string | null;
  /** minutes per scheduled scan, null = the scanner's default (240) */
  scan_budget_min?: number | null;
  /** record the SHA-256 of every file in the name index (IOC hash hunt) */
  file_hashes?: boolean;
  /** Phase 29, GET /groups only: days between full reads (change-tracking check); null = the default, 0 = off */
  full_read_days?: number | null;
  /** the default for this group's kind (90 PVE VMs, 30 agents / NAS / TrueNAS) */
  full_read_default?: number;
}

/** Phase 29: GET /full-reads (one row per source). */
export interface FullRead {
  tenant: string;
  source: string;
  next_due: number | null;
  last_at: number | null;
  last_snapshot: number | null;
  last_job: number | null;
  result: 'clean' | 'drift' | 'no_baseline' | null;
  changed: number | null;
  unreported: number | null;
  unreported_bytes: number | null;
  details: { tracker?: string; examples?: string[]; compared?: number; baseline?: number | null; [k: string]: unknown } | null;
  last_clean_at: number | null;
}

/** Phase 29: one snapshot of a scan back (`job.result.scanned[]`). */
export interface ScanBackItem {
  time: number;
  /** the ordinary `snapshot_scan` job of this snapshot (details: GET /scans) */
  job: number;
  matches_total: number;
  complete: boolean;
  /** ended at the first match */
  stopped: boolean;
}

/** Phase 29: `job.result` of a `scan_back` job. */
export interface ScanBackResult {
  source: string;
  from: number;
  scanned: ScanBackItem[];
  recommended: number | null;
  truncated: boolean;
}

/** Phase 29: incident-mode / lockdown freezes. */
export interface Freeze {
  config?: boolean;
  deletions: boolean;
  restores: boolean;
}

/** Phase 29: GET /auth/me `freeze` (appliance-wide accounts). */
export interface FreezeBanner {
  config: boolean;
  deletions: boolean;
  restores: boolean;
  tenants: { tenant: string; deletions: boolean; restores: boolean }[];
}

/** Phase 29: GET /auth/me `step_up`. */
export interface StepUpState {
  since: number;
  until: number;
  reason: string;
  done: boolean;
}

/** Phase 29: GET /risk (active marks). */
export interface RiskMark {
  user_id: number;
  user: string;
  role: string;
  tenant: string | null;
  since: number;
  until: number;
  reason: string;
}

export type GroupMode = 'explicit' | 'all' | 'tags';

/** One guest of `GET /sources/{id}/inventory`. */
export interface InventoryGuest {
  guest: string;
  name: string;
  kind: string;
  tags: string[];
  seen: number;
  /** set when the guest was no longer listed */
  gone: number | null;
  /** names of the groups protecting it */
  groups: string[];
}

export interface Inventory {
  source_id: number;
  kind: string;
  /** false: the source kind has no inventory (linux, nfs, smb, plugin kinds without guests) */
  inventory: boolean;
  /** last successful listing; null = never */
  refreshed: number | null;
  guests: InventoryGuest[];
}

export type JobState = 'queued' | 'running' | 'ok' | 'failed' | 'cancelled';
export type JobKind =
  | 'backup'
  | 'restore'
  | 'restore_ct'
  | 'instant_recover'
  | 'instant_disk'
  | 'files_list'
  | 'files_get'
  | 'offsite'
  | 'retention'
  | 'gc'
  | 'verify'
  | 'chunk_repair'
  | 'restore_files'
  | 'agent_update'
  | 'agent_enroll'
  | 'agent_renew'
  | 'plugin_validate'
  | 'plugin_guests'
  | 'plugin_backup'
  | 'plugin_restore'
  | 'plugin_mount'
  | 'replica_enroll'
  | 'replica_sync'
  | 'inventory'
  | 'file_search'
  | 'file_index'
  | 'file_changes'
  | 'snapshot_diff'
  | 'offsite_list'
  | 'offsite_restore'
  | 'offsite_attach'
  | 'fleet_scan'
  | 'hash_hunt'
  | 'scan_back';

/** One snapshot of an `offsite_list` result (Phase 17d, `nexus-offsite list --json`). */
export interface OffsiteListed {
  source: string;
  time: number;
  /** logical size; null when the snapshot is not in this appliance's offsite inventory */
  size: number | null;
  /** offsite retention lock (0 = none / unknown) */
  lock_until: number;
  /** in this appliance's offsite inventory */
  inventory: boolean;
  /** its manifest is on the offsite target */
  remote: boolean;
  /** a copy is in the local store */
  local: boolean;
}

/** One hit of a `file_search` job: one version of a file (same path, size, mtime) and the snapshots that hold it. */
export interface SearchMatch {
  source: string;
  /** relative, no leading slash (the Files page path is `/` + path) */
  path: string;
  kind: 'file' | 'dir' | 'symlink' | 'other';
  size: number;
  mtime: number;
  /** snapshot times holding this version, newest first */
  times: number[];
}

/** `job.result` of a finished `file_search` job (POST /search). */
export interface SearchResult {
  matches: SearchMatch[];
  /** snapshots searched */
  scanned: number;
  /** snapshots without a file index (VM/CT disks of groups without index_files) */
  unindexed: number;
  /** the limit or the time budget was hit */
  truncated: boolean;
  elapsed_ms: number;
}

/** Phase 31b: index state of a snapshot (GET /snapshots, GET /files/search `snapshots`). */
export type IndexState = 'indexed' | 'pending' | 'partial' | 'failed' | 'off' | 'unindexed';

/** One version of a file in the search index (same size and mtime across consecutive snapshots). */
export interface FileVersion {
  size: number;
  mtime: number;
  /** first snapshot holding this version */
  first: number;
  /** first indexed snapshot without it; null = still present in the newest indexed snapshot */
  gone: number | null;
  /** local snapshots holding this version, newest first; empty = those snapshots were deleted */
  times: number[];
}

/** One hit of GET /files/search: a path in one source with its versions (newest first). */
export interface FileHit {
  source: string;
  /** guest path as shown (`/home/…`, `C:/Users/…`, `vol3/…`) */
  path: string;
  /** file-browser path without a leading slash (Files page, files_get, restores) */
  browse: string;
  kind: 'file' | 'dir' | 'symlink' | 'other';
  versions: FileVersion[];
}

export interface IndexSnap {
  time: number;
  state: IndexState;
  reason?: string | null;
}

/** GET /files/search */
export interface FileSearchResult {
  hits: FileHit[];
  next: string | null;
  elapsed_ms: number;
  /** snapshots waiting to be indexed */
  pending: number;
  /** every local snapshot of each hit source, newest first */
  snapshots: Record<string, IndexSnap[]>;
}

export interface IndexTenantStatus {
  tenant: string;
  /** file versions */
  docs: number;
  /** sealed index size on disk */
  bytes: number;
  sources: number;
  snapshots_indexed: number;
  snapshots_pending: number;
  oldest_pending: number | null;
  snapshots_unindexed: number;
  last_sync: number | null;
  error: string | null;
}

/** GET /files/index-status */
export interface IndexStatus {
  available: boolean;
  paused?: boolean;
  free_bytes?: number;
  floor_bytes?: number;
  cache_bytes?: number;
  cache_limit?: number;
  tenants?: IndexTenantStatus[];
}

/** GET/PUT /groups/{id}/index-rules */
export interface IndexRules {
  id: number;
  /** leave out the default system folders */
  defaults: boolean;
  include: string[];
  exclude: string[];
  default_excludes: string[];
}

/** One entry of `nexus-pve files … ls` (crates/pve/src/files.rs `Entry`); agents use the same shape. */
export interface FileEntry {
  name: string;
  kind: 'file' | 'dir' | 'symlink' | 'hardlink' | 'other';
  size: number;
  mtime: number;
  mode?: number;
  uid?: number;
  gid?: number;
  link?: string | null;
}

/** Structured job result (`jobs.result`, docs/control-plane.md); null until the job finished ok. */
export interface JobResult {
  /** files_list: directory entries */
  entries?: FileEntry[] | number;
  /** files_get */
  download_token?: string;
  format?: 'tar' | 'zip';
  size?: number;
  expires?: number;
  /** backup: committed snapshots (+ source/time when exactly one) */
  snapshots?: { source: string; time: number; consistent?: boolean; transferred_bytes?: number; warnings?: number }[];
  /** plugin backups (contract v1.7): items skipped with an error — the job is ok with warnings */
  warnings?: number;
  source?: string;
  time?: number;
  /** agent / share backups: false = no snapshot of the source (live read) or files changed while read */
  consistent?: boolean;
  transferred_bytes?: number;
  /** plugin_validate */
  valid?: boolean;
  field?: string;
  message?: string;
  /** plugin_guests */
  guests?: PluginGuest[];
  /** plugin_restore: restore id */
  restore?: string;
  /** plugin_restore / plugin_mount */
  summary?: string;
  /** plugin_mount: how to reach the mount (plugin-defined) */
  info?: unknown;
}

export interface Job {
  id: number;
  kind: JobKind;
  tenant: string;
  params: Record<string, unknown>;
  state: JobState;
  requested_by: string;
  created: number;
  started: number | null;
  finished: number | null;
  log?: string;
  result?: JobResult | null;
  /** Phase 13b: retry chain and cancel request of a running job */
  attempt?: number;
  retry_of?: number | null;
  not_before?: number | null;
  cancel_by?: string | null;
  /** live progress of a running job (scheduler, docs/control-plane.md "Live progress"); null otherwise */
  progress?: JobProgress | null;
}

/** Aggregated `progress {json}` lines of the connector (crates/scheduler/src/progress.rs). */
export interface JobProgress {
  item?: string | null;
  label?: string | null;
  item_index?: number | null;
  items?: number | null;
  items_done?: number;
  part?: string | null;
  part_index?: number | null;
  parts?: number | null;
  /** bytes of the current part */
  done?: number | null;
  total?: number | null;
  entries?: number | null;
  /** Estimated entries of the part (file index walk), null = unknown */
  entries_total?: number | null;
  item_percent?: number | null;
  percent?: number | null;
  /** bytes moved so far over all items */
  bytes?: number;
  /** bytes/s over about the last 10 s */
  rate?: number | null;
  eta?: number | null;
  item_eta?: number | null;
  elapsed?: number;
  updated?: number;
  /** items in flight when several run at once (parallel guests) */
  active?: { item?: string | null; label?: string | null; item_index?: number | null; part?: string | null; done?: number | null; total?: number | null; percent?: number | null }[];
}

export interface Snapshot {
  tenant: string;
  source: string;
  time: number;
  size: number;
  local: boolean;
  offsite: boolean;
  lock_until: number;
  /** time of the last successful verify, null = never verified */
  verified: number | null;
  /** replication source the snapshot came from (null = local backup) */
  origin?: string | null;
  /** open legal hold (15c): `active` (enforced) or `advisory` (reported by the primary) */
  hold?: LegalHold | null;
  /** Phase 15d: null = not recorded (before 15d, replicated or offsite-only) */
  consistency?: Consistency | null;
  /** Phase 18b: plugin snapshot metadata (e.g. PostgreSQL's recoverable range), null = none */
  meta?: SnapshotMeta | null;
  /** Phase 21a: change-rate or file-level anomaly flag (kept after a security officer cleared it) */
  anomaly?: SnapshotAnomaly | null;
  /** flagged and not cleared */
  anomalous?: boolean;
  /** Phase 21d: number of referenced chunks that failed verify (null = healthy) */
  damaged?: number | null;
  damaged_at?: number | null;
  /** Phase 21e: the latest YARA scan, null = never scanned */
  scan?: SnapshotScanSummary | null;
  /** Phase 31b: file index state (null = not applicable) and the reason of partial / failed */
  index_state?: IndexState | null;
  index_reason?: string | null;
  /** Phase 28: verdict of the latest scan, null = unscanned */
  scan_state?: ScanState | null;
  /** Phase 29: anomaly or scan hit, not cleared (production restores need approval `restore.infected`) */
  flagged?: boolean;
  /** Phase 29: the recommended restore point of the source's newest scan back (unix time, this snapshot) */
  clean_point?: number | null;
}

export type ScanState = 'clean' | 'hit' | 'incomplete';

/** One uploaded IOC hash list (GET /hash-lists, Phase 28). */
export interface HashList {
  name: string;
  count: number;
  sha256: string;
  uploaded_by: string;
  uploaded_at: number;
}

/** One file version of a hash hunt result. */
export interface HuntMatch {
  source: string;
  path: string;
  size: number;
  sha256: string;
  lists: string[];
  /** snapshot times holding it, newest first */
  times: number[];
}

/** `job.result` of a `hash_hunt` job. */
export interface HuntResult {
  matches: HuntMatch[];
  scanned: number;
  unhashed: number;
  truncated: boolean;
  hashes: number;
  elapsed_ms: number;
}

/** GET /lockdowns (active tenant lockdowns, Phase 28). */
export interface LockdownInfo {
  tenant: string;
  since: number;
  by: string;
  reason: string;
  lift_quorum: number | null;
  /** Phase 29 */
  freeze?: Freeze | null;
  freeze_lift_quorum?: number | null;
}

/** GET /auth/devices. */
export interface LoginDevice {
  fingerprint: string;
  family: string;
  prefix: string;
  first_seen: number;
  last_seen: number;
}

export interface SnapshotScanSummary {
  job: number;
  finished: number;
  matches: number;
  /** false: the time budget ran out */
  complete: boolean;
}

/** Restore option `scan_first` (Phase 21e): on a hit, refuse or restore with the NICs down. */
export type ScanFirst = 'refuse' | 'link_down';

/** One admin-supplied YARA rule file (GET /scan/rules). */
export interface YaraRule {
  name: string;
  size: number;
  sha256: string;
  uploaded_by: string;
  uploaded_at: number;
}

/** One finished scan (GET /scans). */
export interface SnapshotScan {
  job: number;
  tenant: string;
  source: string;
  time: number;
  finished: number;
  rules: string;
  files: number;
  skipped: number;
  errors: number;
  complete: boolean;
  matches_total: number;
  matches: { rule: string; path: string }[];
}

export interface SnapshotAnomaly {
  reason: string;
  at: number | null;
  cleared_by: string | null;
  cleared_at: number | null;
  note: string | null;
}

/** One changed path of a `snapshot_diff` job (POST /snapshots/diff). */
export interface DiffEntry {
  path: string;
  change: 'added' | 'changed' | 'deleted';
  kind: 'file' | 'dir' | 'symlink' | 'other';
  size: number;
  mtime: number;
  old_size: number | null;
  old_mtime: number | null;
}

/** `job.result` of a `snapshot_diff` job; `indexed: false` = a name index is missing. */
export interface DiffResult {
  indexed: boolean;
  base: number | null;
  time: number;
  added?: number;
  changed?: number;
  deleted?: number;
  /** entries of the selected change type */
  total?: number;
  offset?: number;
  limit?: number;
  entries?: DiffEntry[];
}

/** Phase 30: per-source sensitivity of the anomaly checks. */
export type Sensitivity = 'low' | 'medium' | 'high';

/** GET /stats/trends: the last 30 runs of one source, oldest first. */
export interface SourceTrend {
  tenant: string;
  source: string;
  /** Phase 30 */
  sensitivity: Sensitivity;
  runs: {
    time: number;
    new_plain: number;
    new_stored: number;
    files_changed: number | null;
    anomalous: boolean;
    /** Phase 30: bytes read and the backup's duration (null: older connector) */
    read: number;
    secs: number | null;
  }[];
}

/** Plugin snapshot metadata (protocol v1.6 `SnapshotMeta`); known keys are shown. */
export interface SnapshotMeta {
  /** point-in-time restore range: unix seconds and positions (PostgreSQL LSNs; `unit: "binlog"` = MySQL/MariaDB `file:position`, Phase 23b) */
  recoverable?: { from_time: number; to_time: number; from_lsn: string; to_lsn: string; timeline?: number; unit?: string };
  /** Phase 22b: VM identity of a `vm-` snapshot; `changed` = the VMID was reused (new chain) */
  identity?: {
    vmgenid: string | null;
    smbios_uuid: string | null;
    changed: boolean;
    previous: { vmgenid: string | null; smbios_uuid: string | null } | null;
  };
  /** Phase 22b: the TrueNAS snapshot a `nas-` snapshot was read from */
  zfs_snapshot?: string;
  [k: string]: unknown;
}

/** Consistency level of a snapshot (docs/control-plane.md "Consistency"). */
export type Consistency = 'application' | 'crash' | 'inconsistent' | 'unknown';

/** Policy option: minimum consistency of group backups. */
export interface RequireConsistency {
  mode: 'off' | 'warn' | 'fail';
  level: 'application' | 'crash';
}

/** A legal hold and its history (Phase 15c, GET /holds). */
export interface LegalHold {
  id: number;
  tenant: string;
  source: string;
  time: number;
  state: 'active' | 'released' | 'advisory' | 'withdrawn';
  reason: string;
  held_by: string;
  held_at: number;
  /** replication source that reported it (advisory, or applied from an advisory) */
  origin: string | null;
  released_by: string | null;
  approved_by: string | null;
  released_at: number | null;
  /** pending (or approved, not yet executed) release request */
  release_quorum: number | null;
}

/** The snapshot an alert offers to put on hold (anomaly, legal-hold advisory). */
export interface SnapshotRef {
  tenant: string;
  source: string;
  time: number;
}

/** Primary: an enrolled (or pending) secondary appliance (docs/replication.md). */
export interface ReplicationPeer {
  id: string;
  name: string;
  tenants: string[];
  state: 'pending' | 'approved' | 'enrolled' | 'revoked';
  cert_sha256: string | null;
  keyd_fingerprint: string | null;
  token_expires: number | null;
  enrolled_at: number | null;
  last_seen: number | null;
  revoked: number | null;
  created: number;
  created_by: string;
  /** exported DEK versions per tenant */
  keys: Record<string, { versions: number[]; created: number }>;
  enroll_failures: number;
}

export interface ReplicationTenantStatus {
  last_ok?: number;
  last_error?: string | null;
  last_error_at?: number;
  imported?: number;
  bytes?: number;
  remote?: number;
  key_versions?: number[];
  job?: number;
}

/** Secondary: a primary this appliance pulls from. */
export interface ReplicationSource {
  id: number;
  name: string;
  url: string;
  peer_id: string;
  cert_pin: string;
  tenants: string[];
  schedule: string;
  gfs: Gfs;
  bwlimit: number | null;
  state: 'enrolling' | 'enrolled' | 'failed';
  cert_sha256: string | null;
  keyd_fingerprint: string | null;
  created: number;
  last_sync: number | null;
  status: Record<string, ReplicationTenantStatus>;
  /** Phase 17a: bandwidth windows, sync window (none = always), their time zone */
  windows: RateWindow[];
  sync_window: Span[];
  timezone: string;
  /** Phase 17b "close vault now": null = open, -1 = until reopened, else unix time */
  closed_until: number | null;
  closed_by: string | null;
  closed_at: number | null;
}

export type QuorumState = 'pending' | 'approved' | 'rejected' | 'executed' | 'expired';

export interface QuorumRequest {
  id: number;
  action: string;
  params: Record<string, unknown>;
  requested_by: string;
  created: number;
  expires?: number;
  decided_by: string | null;
  decided_at: number | null;
  state: QuorumState;
}

export interface AuditEntry {
  seq: number;
  ts: number;
  actor: string;
  action: string;
  target: string;
  details: unknown;
  prev_hash: string;
  hash: string;
}

/** Setting `forwarding` (GET/PUT /settings/forwarding); header values are write-only (null = stored). */
export interface ForwardingSettings {
  syslog: { enabled: boolean; host: string; port: number; ca_pem: string | null; pin_sha256: string | null; app_name: string; facility: number } | null;
  https: {
    enabled: boolean;
    url: string;
    headers: Record<string, string | null>;
    batch_max: number;
    ca_pem: string | null;
    pin_sha256: string | null;
    /** Phase 18: body format (default json_array) and the Splunk index */
    format?: 'json_array' | 'splunk_hec';
    index?: string | null;
  } | null;
}

/** GET /audit/forwarding: delivery state per configured sink. */
export interface ForwardingStatus {
  head_seq: number;
  sinks: {
    sink: 'syslog' | 'https';
    dest: string;
    enabled: boolean;
    audit_seq: number;
    event_seq: number;
    last_ok: number | null;
    last_error: string | null;
    last_error_ts: number | null;
    failing_since: number | null;
  }[];
}

export interface AuditVerify {
  ok: boolean;
  entries?: number;
  error?: string;
}

/** GET /alerts (13f lifecycle): `ts` = `first_ts`; open while `resolved_at` is null. */
export interface Alert {
  id: number;
  ts: number;
  first_ts: number;
  last_ts: number;
  count: number;
  severity: 'info' | 'warning' | 'critical';
  kind: string;
  /** Phase 18: stable category of the kind (security, backup, replication, hardware, system) */
  category: string;
  key: string | null;
  tenant: string | null;
  message: string;
  /** English "what to do" (the UI prefers t.alerts.hints[kind]) */
  hint: string;
  acked_by: string | null;
  resolved_at: number | null;
  resolved_by: string | null;
  note: string | null;
  /** resolved by the appliance (the problem went away) */
  auto: boolean;
  /** 15c: the snapshot a security officer may put on hold from the alert */
  snapshot?: SnapshotRef | null;
}

export interface LoginResponse {
  csrf: string;
  user: User;
  /** a console root shell is running (14c; GET /auth/me) */
  console_shell?: ConsoleShell | null;
  /** Phase 17c: vault mode is on (restores and downloads need approval) */
  vault_mode?: boolean;
  /** Phase 19b: "view as tenant" is active in this session */
  impersonating?: Impersonation | null;
  /** Phase 21b: incident mode is active (appliance-wide accounts only) */
  incident?: IncidentBanner | null;
  /** Phase 29: frozen configuration / deletions / restores (appliance-wide accounts) */
  freeze?: FreezeBanner | null;
  /** Phase 29: the account is marked by a risk signal: sensitive requests need a step-up */
  step_up?: StepUpState | null;
}

/** Phase 21b: the incident banner (GET /auth/me, /dashboard). */
export interface IncidentBanner {
  since: number;
  by: string;
  reason: string;
}

/** Phase 21b: GET /incident (the active or the last incident). */
export interface Incident {
  active: boolean;
  since?: number;
  by?: string;
  reason?: string;
  hold?: { tenants: string[]; sources: string[]; from: number; to: number } | null;
  held?: string[];
  paused?: { id: number; prev: number | null }[];
  sessions_ended?: number;
  tokens_revoked?: number;
  ended_at?: number;
  ended_by?: string;
  approved_by?: string;
  resumed?: number;
  leave_quorum: number | null;
  /** Phase 29: active freezes of incident mode, and a pending lift request */
  freeze?: Freeze | null;
  freeze_lift_quorum?: number | null;
}

/** `GET /vault` (Phase 17c); `checks` and the requests only for appliance-wide roles. */
export interface VaultState {
  enabled: boolean;
  since: number | null;
  by: string | null;
  ready?: boolean;
  checks?: {
    secondary: { ok: boolean; sources: number };
    no_local_tenants: { ok: boolean; tenants: string[] };
    no_peers: { ok: boolean; peers: number };
    approvals: { ok: boolean };
    web_restricted: { ok: boolean; allow: string[] };
  };
  pending_enable?: number | null;
  pending_disable?: number | null;
  approved_disable?: number | null;
}

// ---------------------------------------------------------------- console root access (14c)

export type ConsoleUnlockStatus = 'pending' | 'rejected' | 'expired' | 'approved' | 'issued' | 'used' | 'revoked';
export interface ConsoleUnlock {
  id: number;
  hours: number;
  reason: string;
  requested_by: string;
  created: number;
  decided_by: string | null;
  decided_at: number | null;
  code_expires: number | null;
  status: ConsoleUnlockStatus;
}
export interface ConsoleCode {
  id: number;
  code: string;
  hours: number;
  expires: number;
}
export interface ConsoleShell {
  at: number;
  until: number;
  method: 'code' | 'recovery_key';
  unlock: number | null;
  requested_by: string | null;
  alert: number;
}

// ---------------------------------------------------------------- tenant recovery key (17e)

export type TenantKeyRequestStatus = 'pending' | 'rejected' | 'approved' | 'expired' | 'shown';
export interface TenantKeyInfo {
  tenant: string;
  /** null: no tenant recovery key (only the appliance recovery key restores this tenant) */
  key: { kid: string; set_at: number; requested_by: string; approved_by: string } | null;
  requests: {
    id: number;
    requested_by: string;
    created: number;
    decided_by: string | null;
    decided_at: number | null;
    show_until: number | null;
    status: TenantKeyRequestStatus;
  }[];
}
export interface TenantKeyShown {
  tenant: string;
  key: string;
  kid: string;
  replaced: string | null;
}

// ---------------------------------------------------------------- plugins (docs/plugin-system.md)

/** JSON-Schema subset of `config_schema` / `params_schema`. */
export interface JsonSchema {
  type?: 'object' | 'string' | 'integer' | 'boolean' | 'array';
  properties?: Record<string, JsonSchema>;
  required?: string[];
  /** arrays: items are strings, or objects of scalar properties (contract v1.6) */
  items?: JsonSchema;
  maxItems?: number;
  enum?: (string | number)[];
  minimum?: number;
  maximum?: number;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  format?: 'hostname' | 'port' | 'password' | string;
  title?: string;
  description?: string;
  default?: unknown;
}

export interface PluginRestore {
  id: string;
  title: string;
  params_schema?: JsonSchema;
  app_specific?: boolean;
  /** manifest v1.4: which snapshots the restore applies to (default `any`) */
  applies_to?: 'guest' | 'source' | 'any';
  /** manifest v1.6: may run with another source of the same kind (job `target_source_id`) */
  target_source?: boolean;
}

export interface PluginEndpoint {
  /** JSON pointers into the source config */
  host: string;
  port?: string;
  default_port?: number;
  proto?: string;
  /** fixed host used when the config field is empty (contract v1.3) */
  default_host?: string;
}

export interface PluginKind {
  kind: string;
  title: string;
  config_schema: JsonSchema;
  secret_fields?: string[];
  endpoints?: PluginEndpoint[];
  guests?: { title: string; list: boolean } | null;
  backup?: { incremental?: boolean; consistent?: string };
  restores: PluginRestore[];
}

export interface PluginSandbox {
  network?: string;
  tmp_mb?: number;
  memory_mb?: number;
  cpu_quota?: number;
}

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  publisher: string;
  api: number;
  kinds: PluginKind[];
  sandbox?: PluginSandbox;
}

export type PluginState = 'pending' | 'approved' | 'installed' | 'failed' | 'rejected' | 'removing' | 'removed';

/** One entry of GET /plugins per (id, version). */
export interface Plugin {
  id: string;
  name: string;
  version: string;
  publisher: string;
  state: PluginState;
  current: boolean;
  enabled: boolean;
  /** key name / fingerprint that verified the signature */
  signer: string;
  sha256: string;
  bin_sha256: string;
  size: number;
  manifest: PluginManifest;
  uploaded_by: string;
  uploaded_at: number;
  installed_at: number | null;
  error: string | null;
  quorum_id: number | null;
}

/** 202 answer of POST /plugins. */
export interface PluginUpload {
  quorum_id: number;
  plugin: Plugin;
  upgrade_from: string | null;
}

export interface PluginKey {
  fingerprint: string;
  publisher: string;
  /** PEM */
  public_key: string;
  builtin: boolean;
  /** builtin (project) keys: file name */
  name?: string;
  added_by?: string;
  approved_by?: string | null;
  added_at?: number;
}

/** One guest of a plugin source (`plugin_guests` job result). */
export interface PluginGuest {
  id: string;
  title: string;
  size?: number;
  /** v1.5: e.g. `type:user`, `license:none` */
  tags?: string[];
}

// ---------------------------------------------------------------- Phase 12 (docs/phase12-contract.md)

export type Sla = 'ok' | 'breach' | 'never' | 'paused' | 'deactivated';

/** GET /dashboard?days=7|30 (§1). Byte counts; ratios and forecasts are null when unknown. */
export interface Dashboard {
  /** Phase 21b: incident mode is active */
  incident?: IncidentBanner | null;
  /** Phase 15d: newest local snapshot per source, counted per level */
  consistency?: Record<string, number>;
  generated: number;
  days: number;
  protection: {
    objects: number;
    protected: number;
    unprotected: number;
    sla_ok: number;
    sla_breach: number;
    /** behind the RPO, but every group of the object is paused (no breach) */
    sla_paused?: number;
    /** Phase 17f: objects of deactivated tenants, and those tenants */
    sla_deactivated?: number;
    deactivated_tenants?: string[];
    never: number;
    /** Phase 13c: what no group protects (inventory guests, agents, shares), at most 200 */
    unprotected_list?: {
      tenant: string;
      kind: string;
      source_id: number | null;
      source: string;
      guest: string | null;
      name: string;
    }[];
    worst: {
      source: string;
      name: string;
      kind: string;
      tenant: string;
      last_ok: number | null;
      age_s: number | null;
      rpo_s: number;
      sla: Sla;
    }[];
  };
  jobs: {
    success_rate: number | null;
    total: number;
    ok: number;
    warning: number;
    failed: number;
    per_day: { day: string; ok: number; warning: number; failed: number }[];
    failed_by_kind: { kind: string; failed: number }[];
  };
  capacity: {
    total: number;
    used: number;
    free: number;
    logical: number;
    physical: number;
    reduction: number | null;
    dedup: number | null;
    compression: number | null;
    per_day: { day: string; used: number; logical: number }[];
    forecast_full_days: number | null;
  };
  offsite: {
    tenants: number;
    lag_max_s: number | null;
    lagging: number;
    lock_coverage: number | null;
    replication_lag_max_s: number | null;
    last_verify: number | null;
    verify_failed: number;
  };
  /** Phase 25: the newest restore test result per guest within the window */
  /** Phase 29: full reads (change-tracking check) */
  full_reads?: { sources: number; verified: number; drift: number; never: number; oldest_verified: number | null };
  restore_tests?: { tested: number; passed: number; failed: number; last: number | null; failing: { tenant: string; source: string; finished: number }[] };
}

/** GET /auth/oidc (no session). */
export interface OidcPublic {
  enabled: boolean;
  label?: string;
  /** Phase 23a: some tenant has its own IdP ("sign in with your organisation") */
  organizations?: boolean;
}

export interface OidcMapping {
  group: string;
  role: Role;
  tenants: string[];
}

/** GET/PUT /settings/oidc (§2). `client_secret` is write-only. */
export interface OidcSettings {
  enabled: boolean;
  issuer: string;
  client_id: string;
  client_secret_set?: boolean;
  client_secret?: string;
  scopes: string[];
  username_claim: string;
  groups_claim: string;
  label: string;
  mappings: OidcMapping[];
  /** Phase 14d: when the client secret expires at the IdP (unix time; expiry alerts) */
  client_secret_expires?: number | null;
  /** Phase 23a, tenant IdPs only (GET/PUT /tenants/{name}/oidc): e-mail domains of its users */
  domains?: string[];
}

export type Severity = 'info' | 'warning' | 'critical';

/** One notification rule (13f). Webhook header values are write-only: null = keep. */
export interface AlertRule {
  name: string;
  min_severity: Severity;
  /** empty = every kind / tenant */
  kinds: string[];
  tenants: string[];
  channels: {
    email: string[];
    webhook: { url: string; headers: Record<string, string | null>; template: string | null } | null;
  };
}

/** GET/PUT /settings/alerts (§3, 13f). `smtp.password` is write-only. */
export interface AlertSettings {
  smtp: {
    host: string;
    port: number;
    starttls: boolean;
    from: string;
    user: string;
    password_set?: boolean;
    password?: string;
  } | null;
  rules: AlertRule[];
  /** 0 = never remind */
  reminder_hours: number;
  retention_days: Record<Severity, number>;
}

/** GET /ssh-keys (§4): public halves only. */
export interface SshKey {
  name: string;
  purpose: string;
  public_key: string;
  fingerprint: string;
  created: number;
  /** assumption: after a rotation the old key, still valid until retired */
  previous?: { public_key: string; fingerprint: string; created: number } | null;
}

export interface UpdateImage {
  version: string;
  digest?: string;
  since?: number;
}

/** GET /updates (§5): `nexus-update status --json`. */
export interface UpdatesStatus {
  booted: UpdateImage;
  staged: UpdateImage | null;
  available: UpdateImage | null;
  channel: string;
  /** "Sun 03:00 120" = weekday, start, minutes */
  window: string;
  last_check: number;
  status: 'idle' | 'checking' | 'staged' | 'error' | 'blocked' | string;
  error: string | null;
  rollback: UpdateImage | null;
  /** pre-update checks that refused the last stage / apply (status "blocked") */
  blocked?: Pick<DiagCheck, 'id' | 'title' | 'severity' | 'detail' | 'manual'>[];
}

/** One self-check of nexus-diag (Settings → Diagnostics, pre-update checks). */
export interface DiagCheck {
  id: string;
  title: string;
  status: 'pass' | 'warn' | 'fail' | 'skip';
  /** 1 info, 2 warning, 3 error, 4 critical (>= 3 failing blocks updates) */
  severity: 1 | 2 | 3 | 4;
  detail: string;
  /** anchor in the user manual, e.g. "15-troubleshooting-faq.md#check-disk-var" */
  manual: string;
}

/** one config_backup / config_upload job (GET /settings/config-backup) */
export interface ConfigBackupRun {
  id: number;
  kind: 'config_backup' | 'config_upload';
  state: string;
  created: number;
  finished: number | null;
  requested_by: string;
  target: string | null;
  result: { bytes?: number; files?: string[] | number } | null;
}

/** GET /settings/config-backup */
export interface ConfigBackupStatus {
  appliance_id: string | null;
  last_success: number | null;
  running: boolean;
  latest: { appliance: string; created: number; bytes: number; sha256: string | null; files: number | null } | null;
  targets: { tenant: string; last: ConfigBackupRun | null; last_ok: number | null }[];
  runs: ConfigBackupRun[];
}

/** GET /diagnostics/{id} */
export interface DiagRun {
  id: string;
  kind: 'checks' | 'bundle';
  by: string;
  state: 'queued' | 'running' | 'done' | 'error';
  since: number | null;
  until: number | null;
  created: number | null;
  finished: number | null;
  error: string | null;
  expires?: number;
  checks: DiagCheck[] | null;
  bundle: { bytes: number; url: string } | null;
}

/** Summed `backup_stats` of kept snapshots (GET /storage, docs/storage-accounting.md). */
export interface StorageSum {
  snapshots: number;
  logical: number;
  data_in: number;
  stored: number;
  saved: number;
  dedup: number | null;
  compression: number | null;
  reduction: number | null;
}

export interface StorageGrowth {
  d7: number | null;
  d30: number | null;
  d90: number | null;
}

export interface Storage {
  generated: number;
  totals: StorageSum & { snapshots_all: number; used: number; growth: StorageGrowth };
  tenants: (StorageSum & { tenant: string; quota_bytes: number | null; used: number | null; quota_used: number | null; growth: StorageGrowth })[];
  groups: (StorageSum & { tenant: string; group_id: number | null; group: string | null; sources: number })[];
  per_day: { day: string; used: number; logical: number }[];
}

/** Setting `anomaly` (GET/PUT /settings/anomaly). */
export interface AnomalySettings {
  enabled: boolean;
  factor: number;
  history: number;
  floor_bytes: number;
  /** Phase 21a: extra ransom-note file name globs */
  ransom_notes?: string[];
}

/** Phase 14d: GET /auth/sessions, GET /sessions. */
export interface SessionInfo {
  id: number;
  user_id: number;
  user: string;
  ip: string;
  user_agent: string;
  created: number;
  last_seen: number;
  current: boolean;
}

/** Phase 14d: GET /settings/security. */
export interface SecuritySettings {
  session: { idle_min: number; absolute_h: number };
  dormant_days: number;
  /** Phase 21b: concurrent sessions per account (default 5) */
  max_sessions: number;
  /** Phase 21b: DEK rotation reminder after this many days (0 = off, default 365) */
  dek_rotation_days: number;
  login_banner: string;
  mgmt_allow: string[];
  client_ip: string;
  client_allowed: boolean;
  pending: { session: number | null; mgmt_allow: number | null };
}

/** Phase 21c: one of my passkeys (GET /auth/passkeys). */
export interface Passkey {
  id: number;
  name: string;
  alg: 'ES256' | 'EdDSA';
  rp_id: string;
  created: number;
  last_used: number | null;
}

/** Phase 21c: GET /settings/passkeys (`rp_id` = effective host name, null if this page was opened by IP). */
export interface PasskeySettings {
  policy: { require_privileged: boolean; rp_id: string };
  rp_id: string | null;
  without_passkey: string[];
  pending: number | null;
}

/** Phase 16c: one inbound service of GET /firewall (allow empty = any address). */
export interface FirewallService {
  id: string;
  ports: string;
  lockout: boolean;
  available: boolean;
  can_disable: boolean;
  enabled: boolean;
  allow: string[];
  /** what nftables holds now (nexus-nft-sync status); null = unknown */
  effective: { v4: string[]; v6: string[] } | null;
  pending: number | null;
}

/** Phase 16c: a recent blocked inbound attempt. */
export interface FirewallDrop {
  src: string;
  proto: string;
  port: number;
  last_seen: number;
  packets: number;
}

/** Phase 16c: GET /firewall. */
export interface FirewallState {
  services: FirewallService[];
  client_ip: string;
  client_allowed: boolean;
  status_ts: number | null;
  status_stale: boolean;
  /** automatic outbound allow-list (read-only) */
  outbound: { endpoints: string[]; dns: string[]; nts: string[] } | null;
  drops: FirewallDrop[];
}

/** Phase 14d: an API token (`nxt_…`); the secret is only in the create answer. */
export interface ApiToken {
  id: number;
  user: string;
  name: string;
  prefix: string;
  scope: 'read' | 'operator';
  expires: number;
  created: number;
  last_used: number | null;
  last_ip: string | null;
  /** POST /auth/tokens only: shown once */
  token?: string;
}

/** Phase 14d: one certificate of the served chain (GET /certificate). */
export interface CertInfo {
  subject: string;
  issuer: string;
  sans: string[];
  not_before: number;
  not_after: number;
  /** SHA-256, upper case, colon separated */
  sha256: string;
  self_signed: boolean;
  ca: boolean;
}

export interface CertStatus {
  active: 'imported' | 'self_signed';
  chain: CertInfo[];
  /** the self-signed identity certificate replication secondaries pin */
  identity: CertInfo | null;
  pending: { cn: string; sans: string[]; created: number; csr_pem: string | null } | null;
  can_revert: boolean;
  previous: boolean;
  pins: { replication_identity: string | null; replication_peers: number };
}

/** Phase 14e reports (GET /reports/{type}.csv). */
export type ReportType = 'protection' | 'failed' | 'sla' | 'storage' | 'usage';

/** A scheduled report (setting `reports`, GET/PUT /settings/reports). */
export interface ScheduledReport {
  name: string;
  types: ReportType[];
  schedule: string;
  timezone: string;
  recipients: string[];
  tenant: string | null;
  /** the last `report_send` job (scheduled or "Send now") */
  last?: { job_id: number; state: string; created: number; finished: number | null; requested_by: string } | null;
}

export interface ScheduledReports {
  reports: ScheduledReport[];
  /** an SMTP server is configured (Settings → Alert delivery) */
  smtp: boolean;
}

/** Phase 16a/b hardware (GET /hardware, from nexus-disks; docs/hardware.md). */
export type HwSeverity = 'info' | 'warning' | 'critical';
export interface HwIssue {
  severity: HwSeverity;
  message: string;
}
export interface HwSelfTest {
  running: boolean;
  remaining: number | null;
  last: { type: string; status: string; passed: boolean; hours: number | null } | null;
}
export interface HwSmart {
  available: boolean;
  health: 'passed' | 'failed' | null;
  temperature: number | null;
  power_on_hours: number | null;
  reallocated: number | null;
  pending: number | null;
  offline_uncorrectable: number | null;
  percentage_used: number | null;
  media_errors: number | null;
  critical_warning: number | null;
  available_spare: number | null;
  self_test: HwSelfTest | null;
  attributes: { id: number | null; name: string; value: number | null; worst: number | null; thresh: number | null; raw: string | number; failing: boolean }[];
  error: string | null;
  standby: boolean;
  checked: number;
}
export type HwRole = 'system' | 'data' | 'metadata' | 'in_use' | 'empty';
export interface HwDisk {
  name: string;
  path: string;
  model: string | null;
  serial: string | null;
  wwn: string | null;
  size: number;
  type: 'hdd' | 'ssd' | 'nvme';
  transport: string | null;
  rotational: boolean;
  removable: boolean;
  role: HwRole;
  array: string | null;
  why: string | null;
  issues: HwIssue[];
  smart: HwSmart | null;
}
export type HwMemberState = 'active' | 'spare' | 'rebuilding' | 'faulty' | 'removed';
export interface HwArray {
  name: string;
  path: string;
  md_name: string | null;
  uuid: string | null;
  role: 'data' | 'metadata' | 'system' | null;
  level: string | null;
  state: 'clean' | 'degraded' | 'recovering' | 'resyncing' | 'reshaping' | 'failed' | 'inactive';
  degraded: boolean;
  state_detail: string | null;
  raid_devices: number | null;
  active_devices: number | null;
  failed_devices: number | null;
  spare_devices: number | null;
  size: number | null;
  used_dev_size: number | null;
  bitmap: string | null;
  action: 'recover' | 'resync' | 'reshape' | 'check' | 'repair' | null;
  progress: number | null;
  finish_minutes: number | null;
  members: { disk: string | null; dev: string | null; serial: string | null; state: HwMemberState; slot: number | null }[];
  mounts: string[];
  fs: { type: string; uuid: string; size: number | null; used: number | null } | null;
  issues: HwIssue[];
}
export interface HwOp {
  id: string;
  op: 'scan' | 'selftest' | 'create_array' | 'add_spare' | 'replace' | 'grow' | 'growfs';
  state: 'queued' | 'running' | 'done' | 'refused' | 'error';
  by: string;
  quorum_id: number | null;
  created: number | null;
  finished: number | null;
  detail: string | null;
  error: string | null;
  params: Record<string, unknown>;
}
export interface Hardware {
  available: boolean;
  stale: boolean;
  scanned: number | null;
  smart_scanned: number | null;
  tools: { smartctl: boolean; mdadm: boolean };
  store: { path: string; array: string | null; array_uuid: string | null; mounted: boolean; empty: boolean | null };
  summary: { state: 'ok' | 'warning' | 'critical' | 'unknown'; disks: number; arrays: number; warnings: number; critical: number };
  disks: HwDisk[];
  arrays: HwArray[];
  ops: HwOp[];
}

/** Phase 23a: POST /policies/simulate (restore point simulator). */
export interface Simulation {
  runs: number;
  days: number;
  truncated: boolean;
  series: { run: number; t: number; points: number }[];
  final: {
    points: number;
    peak: number;
    recent: number;
    daily: number;
    weekly: number;
    monthly: number;
    yearly: number;
    oldest: number | null;
    newest: number | null;
  };
  /** null: no measured backups in scope */
  estimate: { sources: number; samples: number; compression: number; full: number; delta: number; stored: number; stored_peak: number } | null;
}

/** Phase 23a: GET /usage?month=YYYY-MM (billing). */
export interface UsageRow {
  tenant: string;
  tenant_uid: string | null;
  objects: number;
  backups: number;
  logical_avg: number | null;
  logical_peak: number | null;
  stored_avg: number | null;
  stored_peak: number | null;
  offsite_avg: number | null;
  offsite_peak: number | null;
  days_sampled: number;
  quota_bytes: number | null;
}
export interface Usage {
  month: string;
  from: number;
  to: number;
  complete: boolean;
  tenants: UsageRow[];
}

// Phase 22a: Settings → Network (GET /network, catalog::network)
export type NetRole = 'management' | 'data' | 'replication';
export interface NetRoute {
  to: string;
  via: string | null;
}
export interface NetIface {
  name: string;
  kind: 'ethernet' | 'bond' | 'vlan';
  ports: string[];
  mode: 'active-backup' | '802.3ad' | null;
  parent: string | null;
  vlan_id: number | null;
  role: NetRole | null;
  mtu: number | null;
  dhcp: boolean;
  addresses: string[];
  gateway: string | null;
  dns: string[];
  routes: NetRoute[];
}
export interface NetConfig {
  interfaces: NetIface[];
  offsite_role: NetRole;
}
export interface NetDevice {
  name: string;
  kind: 'nic' | 'bond' | 'vlan' | 'bridge' | 'other';
  mac: string;
  mtu: number;
  state: string;
  speed: number | null;
  master: string | null;
  addresses: string[];
}
export interface NetMtuResult {
  role: string;
  addr: string;
  dev: string | null;
  expected_dev: string | null;
  mtu: number | null;
  result: 'ok' | 'mismatch' | 'no_reply' | 'no_route';
  path_mtu: number | null;
}
export interface NetOp {
  id: string;
  op: 'apply' | 'mtu_check';
  state: 'queued' | 'running' | 'confirming' | 'done' | 'refused' | 'error' | 'rolled_back';
  by: string;
  quorum_id: number | null;
  created: number | null;
  finished: number | null;
  detail: string | null;
  error: string | null;
}
export interface NetworkState {
  available: boolean;
  stale: boolean;
  scanned: number | null;
  devices: NetDevice[];
  config: NetConfig;
  management: { ifname: string | null; source: 'console' | 'config' } | null;
  reset: number | null;
  pending: { id: string; by: string; deadline: number; remaining: number } | null;
  mtu: { ts: number; results: NetMtuResult[] } | null;
  ops: NetOp[];
  request_pending: number | null;
  confirm_secs: number;
  client_ip: string;
}

// ---- Phase 25: restore tests and recovery plans

/** Checks of a restore test (VMs: guest agent, ports, command; containers: boot timeout only). */
export interface RtChecks {
  boot_timeout?: number;
  agent?: boolean;
  ports?: number[];
  command?: string[];
  expect_exit?: number;
  command_timeout?: number;
}

export interface RtCheck {
  name: string;
  ok: boolean;
  detail: string;
}

/** GET /restore-tests */
export interface RestoreTest {
  id: number;
  tenant: string;
  source: string;
  time: number;
  job_id: number;
  run_id: number | null;
  state: 'passed' | 'failed' | 'cancelled' | 'skipped';
  started: number;
  finished: number;
  target: number | null;
  name: string | null;
  boot_secs: number | null;
  checks: RtCheck[] | null;
  error: string | null;
  destroyed: boolean | null;
}

/** GET /restore-tests/schedules */
export interface RtSchedule {
  group_id: number;
  group: string;
  tenant: string;
  every_days: number;
  node: string;
  storage: string;
  bridge: string | null;
  checks: RtChecks;
  last_run: number | null;
}

export interface PlanStep {
  source: string;
  wave: number;
  delay?: number;
  checks?: RtChecks;
  target?: number;
}

export interface Readiness {
  ok: boolean;
  at: number;
  checks: RtCheck[];
}

/** GET /recovery-plans */
export interface RecoveryPlan {
  id: number;
  tenant: string;
  name: string;
  source_id: number;
  node: string;
  storage: string;
  test_bridge: string | null;
  network_map: Record<string, string>;
  steps: PlanStep[];
  rpo_hours: number;
  readiness: Readiness | null;
  created: number;
  created_by: string;
  last_run: { id: number; mode: 'test' | 'execute'; state: string; started: number; finished: number | null } | null;
}

export interface RunResult {
  source: string;
  time?: number;
  wave?: number;
  target?: number | null;
  name?: string;
  state?: string;
  started?: number;
  finished?: number;
  boot_secs?: number | null;
  checks?: RtCheck[];
  error?: string | null;
  destroyed?: boolean | null;
}

/** GET /recovery-plans/{id}/runs */
export interface RecoveryRun {
  id: number;
  mode: 'test' | 'execute';
  state: 'running' | 'passed' | 'failed' | 'cancelled';
  requested_by: string;
  quorum_id: number | null;
  job_id: number | null;
  results: RunResult[];
  started: number;
  finished: number | null;
}
