import type { Role, User } from './types';

// UI-side mirror of the RBAC table. Only used to hide controls — the server decides.
export const can = {
  configure: (u: User | null) => u?.role === 'admin',
  // Phase 21d: fetch bad chunks back from offsite / the replication primary
  repair: (u: User | null) => u?.role === 'admin',
  // Tenant-owned config (sources, agents, groups, the tenant's users): admins, and tenant admins
  // within their own tenant (Phase 19b).
  manageTenant: (u: User | null) => u?.role === 'admin' || u?.role === 'tenant_admin',
  backup: (u: User | null) => u?.role === 'admin' || u?.role === 'operator' || u?.role === 'tenant_admin',
  // viewers: read-only, no job kinds at all (Phase 14d)
  restore: (u: User | null) => !!u && u.role !== 'security_officer' && u.role !== 'viewer',
  // files_get: the account's download privilege (Users page)
  download: (u: User | null) => !!u?.can_download,
  cancelJob: (u: User | null) => u?.role === 'admin' || u?.role === 'operator' || u?.role === 'tenant_admin',
  // approvers: admins and security officers (never the requester — the server checks)
  decideQuorum: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer',
  viewQuorum: (u: User | null) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer' && !u.tenant,
  // Tenant admins list their own requests (Phase 19b); they never decide.
  viewOwnQuorum: (u: User | null) => u?.role === 'tenant_admin',
  // Alerts are appliance-wide (no tenant column); tenant-scoped users get an empty list.
  viewAlerts: (u: User | null) => !!u && !u.tenant,
  // tenant admins: the entries concerning their tenant only (server-side filter, Phase 19b)
  audit: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer' || u?.role === 'tenant_admin',
  verifyAudit: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer',
  // "View as tenant" (Phase 19b): admins only, read-only by default; acting as tenant admin needs approval.
  impersonate: (u: User | null) => u?.role === 'admin',
  ackAlert: (u: User | null) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer' && !u.tenant,
  // Replication peers/sources are appliance-wide: not for tenant-scoped users.
  viewReplication: (u: User | null) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer' && !u.tenant,
  // Plugins are appliance-wide; admins change them, security officers / operators may look.
  viewPlugins: (u: User | null) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer' && !u.tenant,
  syncReplication: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
  // "Close vault now" (17b): admins and security officers; reopening is a request either may make
  closeVault: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer',
  // Legal holds (15c): only security officers set them; officers and admins request a release.
  hold: (u: User | null) => u?.role === 'security_officer',
  releaseHold: (u: User | null) => u?.role === 'security_officer' || u?.role === 'admin',
  // Hardware (16a/b): appliance-wide, read by every non-tenant role; admins request layout changes.
  viewHardware: (u: User | null) => !!u && u.role !== 'tenant_user' && !u.tenant,
  manageHardware: (u: User | null) => u?.role === 'admin',
  scanHardware: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
  // Attach an offsite copy (17d): an admin or a security officer requests, another one approves.
  attachOffsite: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer',
  // YARA scan of a snapshot (21e): admins, operators, tenant admins and security officers
  scan: (u: User | null) => !!u && ['admin', 'operator', 'tenant_admin', 'security_officer'].includes(u.role),
  // File search and index status (Phase 31b): admins, operators, tenant admins and tenant users
  search: (u: User | null) => !!u && ['admin', 'operator', 'tenant_admin', 'tenant_user'].includes(u.role),
  // Phase 28: IOC hash hunts (same roles as scans); tenant lockdown: appliance-wide officers and admins
  hunt: (u: User | null) => !!u && ['admin', 'operator', 'tenant_admin', 'security_officer'].includes(u.role),
  lockdown: (u: User | null) => !u?.tenant && (u?.role === 'admin' || u?.role === 'security_officer'),
  // the IOC hash lists themselves (appliance-wide)
  hashLists: (u: User | null) => !u?.tenant && (u?.role === 'admin' || u?.role === 'security_officer'),
  // Phase 30: per-source anomaly sensitivity (lowering it is an approval; the server decides)
  sensitivity: (u: User | null) => !!u && ['admin', 'security_officer', 'tenant_admin'].includes(u.role),
};

export const ROLES: Role[] = ['admin', 'security_officer', 'operator', 'tenant_admin', 'tenant_user', 'viewer'];
/** Roles a tenant admin may hand out (own tenant only, Phase 19b). */
export const TENANT_ROLES: Role[] = ['tenant_admin', 'tenant_user', 'viewer'];
