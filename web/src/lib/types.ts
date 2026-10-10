// Shapes of the /api/v1 resources (docs/control-plane.md). Times are unix seconds.
// JSON columns of the catalog (offsite, config, gfs, guests, params, details) arrive parsed.

export type Role = 'admin' | 'security_officer' | 'operator' | 'tenant_user';

export interface User {
  id: number;
  name: string;
  role: Role;
  tenant: string | null;
  disabled: boolean;
  created?: number;
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
}
export type PveSource = SourceBase & { kind: 'pve'; config: SourceConfig };
export type LinuxSource = SourceBase & { kind: 'linux'; config: LinuxSourceConfig };
export type TrueNasSource = SourceBase & { kind: 'truenas'; config: TrueNasSourceConfig };
export type NfsSource = SourceBase & { kind: 'nfs'; config: ShareSourceConfig };
export type SmbSource = SourceBase & { kind: 'smb'; config: ShareSourceConfig };
export type ShareSource = NfsSource | SmbSource;
export type Source = PveSource | LinuxSource | TrueNasSource | NfsSource | SmbSource;
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
}

export interface Group {
  id: number;
  tenant: string;
  source_id: number;
  policy_id: number;
  name: string;
  /** pve: VM/CT IDs; linux: exactly `[source.config.agent_id]`; truenas: datasets of the source; nfs/smb: none (the share) */
  guests: (number | string)[];
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
  | 'agent_enroll';

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

export interface Alert {
  id: number;
  ts: number;
  severity: 'info' | 'warning' | 'critical';
  kind: string;
  message: string;
  acked_by: string | null;
}

export interface LoginResponse {
  csrf: string;
  user: User;
}
