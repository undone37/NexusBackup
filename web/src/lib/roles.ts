import type { Role, User } from './types';

// UI-side mirror of the RBAC table. Only used to hide controls — the server decides.
export const can = {
  configure: (u: User | null) => u?.role === 'admin',
  backup: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
  // viewers: read-only, no job kinds at all (Phase 14d)
  restore: (u: User | null) => !!u && u.role !== 'security_officer' && u.role !== 'viewer',
  // files_get: the account's download privilege (Users page)
  download: (u: User | null) => !!u?.can_download,
  cancelJob: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
  // approvers: admins and security officers (never the requester — the server checks)
  decideQuorum: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer',
  viewQuorum: (u: User | null) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer' && !u.tenant,
  // Alerts are appliance-wide (no tenant column); tenant-scoped users get an empty list.
  viewAlerts: (u: User | null) => !!u && !u.tenant,
  audit: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer',
  ackAlert: (u: User | null) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer',
  // Replication peers/sources are appliance-wide: not for tenant-scoped users.
  viewReplication: (u: User | null) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer' && !u.tenant,
  // Plugins are appliance-wide; admins change them, security officers / operators may look.
  viewPlugins: (u: User | null) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer',
  syncReplication: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
  // Legal holds (15c): only security officers set them; officers and admins request a release.
  hold: (u: User | null) => u?.role === 'security_officer',
  releaseHold: (u: User | null) => u?.role === 'security_officer' || u?.role === 'admin',
  // Hardware (16a/b): appliance-wide, read by every non-tenant role; admins request layout changes.
  viewHardware: (u: User | null) => !!u && u.role !== 'tenant_user' && !u.tenant,
  manageHardware: (u: User | null) => u?.role === 'admin',
  scanHardware: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
  // Attach an offsite copy (17d): an admin or a security officer requests, another one approves.
  attachOffsite: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer',
};

export const ROLES: Role[] = ['admin', 'security_officer', 'operator', 'tenant_user', 'viewer'];
