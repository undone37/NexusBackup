import type { Role, User } from './types';

// UI-side mirror of the RBAC table. Only used to hide controls — the server decides.
export const can = {
  configure: (u: User | null) => u?.role === 'admin',
  backup: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
  restore: (u: User | null) => !!u && u.role !== 'security_officer',
  cancelJob: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
  decideQuorum: (u: User | null) => u?.role === 'security_officer',
  viewQuorum: (u: User | null) => !!u && u.role !== 'tenant_user' && !u.tenant,
  // Alerts are appliance-wide (no tenant column); tenant-scoped users get an empty list.
  viewAlerts: (u: User | null) => !!u && !u.tenant,
  audit: (u: User | null) => u?.role === 'admin' || u?.role === 'security_officer',
  ackAlert: (u: User | null) => !!u && u.role !== 'tenant_user',
  // Replication peers/sources are appliance-wide: not for tenant-scoped users.
  viewReplication: (u: User | null) => !!u && u.role !== 'tenant_user' && !u.tenant,
  syncReplication: (u: User | null) => u?.role === 'admin' || u?.role === 'operator',
};

export const ROLES: Role[] = ['admin', 'security_officer', 'operator', 'tenant_user'];
