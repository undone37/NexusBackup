// Phase 22b: concurrency caps (PVE) and the read limit (PVE, TrueNAS, NFS/SMB) of a source,
// as edited in the source dialog (components/SourceLimits.svelte).
import type { ReadLimit, SourceConfig } from './types';
import type { RateWindow } from './schedule';
import { validRateWindow } from './schedule';

export interface LimitsForm {
  /** '' = no cap */
  max_parallel: string;
  /** `storage=n` per line */
  caps: string;
  /** MB/s, '' = unlimited */
  rate: string;
  windows: RateWindow[];
  tz: string;
}

export function limitsForm(c?: Partial<SourceConfig> & { read_limit?: ReadLimit }): LimitsForm {
  const r = c?.read_limit;
  return {
    max_parallel: c?.max_parallel ? String(c.max_parallel) : '',
    caps: Object.entries(c?.storage_caps ?? {})
      .map(([s, n]) => `${s}=${n}`)
      .join('\n'),
    rate: r?.bwlimit ? String(r.bwlimit / 1e6) : '',
    windows: (r?.windows ?? []).map((w) => ({ ...w, days: [...w.days] })),
    tz: r?.timezone ?? 'UTC',
  };
}

/**
 * Config fields of the form (`max_parallel`, `storage_caps` only for PVE), or an error text.
 * Unset values are left out (the source then has no limit).
 */
export function limitsConfig(f: LimitsForm, pve: boolean): Record<string, unknown> | string {
  const out: Record<string, unknown> = {};
  if (pve) {
    if (f.max_parallel.trim()) {
      const n = Number(f.max_parallel);
      if (!Number.isInteger(n) || n < 1 || n > 8) return 'max_parallel';
      out.max_parallel = n;
    }
    const caps: Record<string, number> = {};
    for (const l of f.caps.split('\n').map((x) => x.trim()).filter(Boolean)) {
      const m = /^([A-Za-z0-9._-]{1,64})\s*=\s*(\d)$/.exec(l);
      if (!m || Number(m[2]) < 1 || Number(m[2]) > 8) return 'storage_caps';
      caps[m[1]] = Number(m[2]);
    }
    if (Object.keys(caps).length) out.storage_caps = caps;
  }
  const rl: ReadLimit = {};
  if (f.rate.trim()) {
    const b = Math.round(Number(f.rate) * 1e6);
    if (!(b > 0)) return 'read_limit';
    rl.bwlimit = b;
  }
  if (f.windows.length) {
    if (!f.windows.every((w) => w.action === 'limit' && validRateWindow(w))) return 'read_limit';
    rl.windows = f.windows.map((w) => ({ days: w.days, from: w.from, to: w.to, action: 'limit', rate_bytes: w.rate_bytes! }));
  }
  if (rl.bwlimit || rl.windows) {
    rl.timezone = f.tz || 'UTC';
    out.read_limit = rl;
  }
  return out;
}
