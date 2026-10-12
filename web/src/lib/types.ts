// Shapes of the /api/v1 resources (docs/control-plane.md). Times are unix seconds.
// JSON columns of the catalog (offsite, config, gfs, guests, params, details) arrive parsed.

import type { BlackoutWindow } from './schedule';

export type Role = 'admin' | 'security_officer' | 'operator' | 'tenant_user' | 'viewer';

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
  threads?: number;
  xattrs?: boolean;
  timeout_secs?: number;
}

interface SourceBase {
  id: number;
  tenant: string;
  name: string;
  /** Phase 13b: null = active, -1 = indefinitely, else unix time */
  maintenance_until?: number | null;
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
}

/** One-time enrollment token: only in the answer of POST /agents and POST /agents/{id}/token. */
export interface AgentToken {
  token: string;
  install_command: string;
  token_expires: number;
}

export type AgentStatus = 'enrolled' | 'pending' | 'expired';

export type Overwrite = 'never' | 'if_older' | 'always';

export interface Gfs {
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
  | 'files_list'
  | 'files_get'
  | 'offsite'
  | 'retention'
  | 'gc'
  | 'verify'
  | 'restore_files'
  | 'agent_update'
  | 'agent_enroll'
  | 'plugin_validate'
  | 'plugin_guests'
  | 'plugin_backup'
  | 'plugin_restore'
  | 'plugin_mount'
  | 'replica_enroll'
  | 'replica_sync'
  | 'inventory';

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
  snapshots?: { source: string; time: number; consistent?: boolean; transferred_bytes?: number }[];
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
}

export interface LoginResponse {
  csrf: string;
  user: User;
}

// ---------------------------------------------------------------- plugins (docs/plugin-system.md)

/** JSON-Schema subset of `config_schema` / `params_schema`. */
export interface JsonSchema {
  type?: 'object' | 'string' | 'integer' | 'boolean' | 'array';
  properties?: Record<string, JsonSchema>;
  required?: string[];
  /** arrays: items are strings */
  items?: JsonSchema;
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

export type Sla = 'ok' | 'breach' | 'never' | 'paused';

/** GET /dashboard?days=7|30 (§1). Byte counts; ratios and forecasts are null when unknown. */
export interface Dashboard {
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
}

/** GET /auth/oidc (no session). */
export interface OidcPublic {
  enabled: boolean;
  label?: string;
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
  status: 'idle' | 'checking' | 'staged' | 'error' | string;
  error: string | null;
  rollback: UpdateImage | null;
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
  login_banner: string;
  mgmt_allow: string[];
  client_ip: string;
  client_allowed: boolean;
  pending: { session: number | null; mgmt_allow: number | null };
}

/** Phase 14e reports (GET /reports/{type}.csv). */
export type ReportType = 'protection' | 'failed' | 'sla' | 'storage';

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
