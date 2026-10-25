// Display names of snapshot sources (GET /names, maintainer request 2026-10-22): a PVE guest is shown by
// its name with `vm-100` muted next to it, agents by their name. Loaded once, refreshed at most every
// minute; until then (or without a name) the id alone is shown.
import { get } from './api';

const names = $state<Record<string, Record<string, string>>>({});
let loading = false;
let at = 0;

function load() {
  if (loading || Date.now() - at < 60_000) return;
  loading = true;
  get<Record<string, Record<string, string>>>('/names')
    .then((r) => {
      for (const t of Object.keys(r)) names[t] = r[t];
      at = Date.now();
    })
    .catch(() => {
      at = Date.now(); // an older appliance or no permission: ids only, no retry storm
    })
    .finally(() => (loading = false));
}

/** Only these have names: PVE guests, agents, plugin sources and VMware VMs. */
const named = (source: string) => /^(vm|ct|host|plugin|vmw|xcp)-/.test(source);

/** The display name of `source` in `tenant` (without a tenant: the name if every tenant agrees). */
export function nameOf(tenant: string | null | undefined, source: string): string | undefined {
  if (!source || !named(source)) return undefined;
  load();
  if (tenant) return names[tenant]?.[source];
  const found = new Set(
    Object.values(names)
      .map((m) => m[source])
      .filter(Boolean),
  );
  return found.size === 1 ? [...found][0] : undefined;
}

/** `erp-app (vm-100)` for text (dialog titles, options, aria labels); the id alone without a name. */
export function labelOf(tenant: string | null | undefined, source: string): string {
  const n = nameOf(tenant, source);
  return n ? `${n} (${source})` : source;
}

/** A PVE guest by its VMID (groups keep bare VMIDs): `erp-app (100)`; the VMID alone without a name. */
export function vmidLabel(tenant: string | null | undefined, vmid: number): string {
  const n = nameOf(tenant, `vm-${vmid}`) ?? nameOf(tenant, `ct-${vmid}`);
  return n ? `${n} (${vmid})` : String(vmid);
}
