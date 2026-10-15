// Pure helpers around GET /plugins (docs/plugin-system.md).

import type { Plugin, PluginKind, PluginRestore, Source } from './types';

export const PLUGIN_PREFIX = 'plugin:';

export const isPluginKind = (kind: string) => kind.startsWith(PLUGIN_PREFIX);

/** Compares dotted numeric versions ("1.10.0" > "1.9.3"); pre-release suffixes compare as text. */
export function cmpVersion(a: string, b: string): number {
  const pa = a.split(/[.+-]/);
  const pb = b.split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '0';
    const y = pb[i] ?? '0';
    const nx = Number(x);
    const ny = Number(y);
    const d = Number.isInteger(nx) && Number.isInteger(ny) ? nx - ny : x.localeCompare(y);
    if (d) return Math.sign(d);
  }
  return 0;
}

export interface KindInfo {
  plugin: Plugin;
  kind: PluginKind;
}

/**
 * Source kinds (`plugin:<kind>` → manifest kind) of the current installed version of
 * each plugin. `enabledOnly`: only kinds new sources may use.
 */
export function pluginKinds(plugins: Plugin[], enabledOnly = false): Map<string, KindInfo> {
  const out = new Map<string, KindInfo>();
  for (const p of plugins) {
    if (!p.current || p.state !== 'installed' || (enabledOnly && !p.enabled)) continue;
    for (const k of p.manifest?.kinds ?? []) out.set(PLUGIN_PREFIX + k.kind, { plugin: p, kind: k });
  }
  return out;
}

/**
 * Splits a plugin snapshot source name `plugin-<plugin id>-<source id>[-<guest>]`.
 * Plugin ids never contain an all-digit `-` component, so the first one is the source id.
 */
export function parsePluginSnapshot(name: string): { pluginId: string; sourceId: number; guest: string | null } | null {
  if (!name.startsWith('plugin-')) return null;
  const parts = name.slice(7).split('-');
  const i = parts.findIndex((x) => /^\d+$/.test(x));
  if (i < 1) return null;
  return {
    pluginId: parts.slice(0, i).join('-'),
    sourceId: Number(parts[i]),
    guest: parts.slice(i + 1).join('-') || null,
  };
}

/**
 * Whether a restore of the manifest is offered for a snapshot (manifest v1.4 `applies_to`, default
 * `any`): `plugin-<p>-<sid>-<guest>` snapshots take `guest` restores, `plugin-<p>-<sid>` ones `source`.
 */
export function restoreApplies(r: PluginRestore, guest: string | null): boolean {
  const a = r.applies_to ?? 'any';
  return a === 'any' || (a === 'guest') === !!guest;
}

/** Manifest kind of a plugin snapshot: via its source, else the plugin's only kind. */
export function snapshotKind(name: string, sources: Source[], kinds: Map<string, KindInfo>): KindInfo | null {
  const p = parsePluginSnapshot(name);
  if (!p) return null;
  const src = sources.find((s) => s.id === p.sourceId);
  if (src) return kinds.get(src.kind) ?? null;
  const own = [...kinds.values()].filter((k) => k.plugin.id === p.pluginId);
  return own.length === 1 ? own[0] : null;
}

/** Resolves a JSON pointer ("/host") in a config object. */
export function pointer(obj: unknown, ptr: string): unknown {
  if (!ptr || ptr === '/') return obj;
  let cur: unknown = obj;
  for (const raw of ptr.replace(/^\//, '').split('/')) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (!cur || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}
