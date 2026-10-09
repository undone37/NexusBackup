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

export interface TenantOffsite {
  host?: string;
  port?: number;
  user?: string;
  host_key?: string;
  base_dir?: string;
  bwlimit?: number | null;
  uploaders?: number;
  /** write-only: never returned by GET */
  ssh_key?: string;
  /** set by the server when a key is stored (proposed, see README) */
  ssh_key_set?: boolean;
}

export interface Tenant {
  name: string;
  offsite: TenantOffsite;
}

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

export interface Source {
  id: number;
  tenant: string;
  kind: 'pve';
  name: string;
  config: SourceConfig;
}

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
  guests: number[];
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
  | 'verify';

export interface FileEntry {
  name: string;
  kind: 'file' | 'dir' | 'link';
  size: number;
  mtime: number;
}

/** Proposed `jobs.result` (JSON) — see README "Contract gaps". */
export interface JobResult {
  entries?: FileEntry[];
  download?: string;
  filename?: string;
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
}

export type QuorumState = 'pending' | 'approved' | 'rejected' | 'executed' | 'expired';

export interface QuorumRequest {
  id: number;
  action: string;
  params: Record<string, unknown>;
  requested_by: string;
  created: number;
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
