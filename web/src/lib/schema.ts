// Form model + client-side validation for the JSON-Schema subset plugins use in
// `config_schema` / `params_schema` (docs/plugin-system.md): an object with `properties`
// and `required`; property types string | integer | boolean | array of strings | array of objects of
// such scalars (contract v1.6, e.g. M365 `apps`: one sub-form per item); enum,
// minimum/maximum, pattern, minLength/maxLength, format hostname | port | password,
// title/description/default. The server validates again; this only gives early feedback.

import { t } from './i18n';
import type { JsonSchema } from './types';

/** Form state: strings/numbers/booleans as edited; arrays as newline-separated text; lists of objects as items. */
export type FormValue = string | number | boolean | null | undefined | FormItem[];
export type FormValues = Record<string, FormValue>;
/** One item of a list of objects: its values and which of its write-only fields are stored. */
export interface FormItem {
  values: FormValues;
  set: Record<string, boolean>;
}

export interface SecretOpts {
  /** write-only fields (kind.secret_fields) */
  secretFields?: string[];
  /** `<field>_set` of the stored config: true = an empty input keeps the stored secret */
  secretSet?: Record<string, boolean>;
}

export const properties = (s: JsonSchema | undefined): [string, JsonSchema][] => Object.entries(s?.properties ?? {});

/** A list of objects (rendered as repeatable sub-forms). */
export const isList = (p: JsonSchema) => p.type === 'array' && p.items?.type === 'object';

export function supported(p: JsonSchema): boolean {
  if (isList(p)) return properties(p.items).every(([, x]) => x.type !== 'array' && x.type !== 'object' && supported(x));
  if (p.type === 'array') return !p.items || p.items.type === undefined || p.items.type === 'string';
  return p.type === 'string' || p.type === 'integer' || p.type === 'boolean';
}

/** `<field>_set` flags of a stored config with write-only fields. */
export function secretFlags(config: Record<string, unknown> | undefined, secretFields: string[] = []) {
  return Object.fromEntries(secretFields.map((f) => [f, config?.[`${f}_set`] === true]));
}

/**
 * Initial form values: the stored config when editing (secrets always start empty),
 * else the schema defaults.
 */
export function initValues(s: JsonSchema | undefined, config?: Record<string, unknown>, secretFields: string[] = []): FormValues {
  const out: FormValues = {};
  for (const [k, p] of properties(s)) {
    const v = secretFields.includes(k) ? undefined : config ? config[k] : p.default;
    if (p.type === 'boolean') out[k] = typeof v === 'boolean' ? v : false;
    else if (isList(p))
      out[k] = Array.isArray(v)
        ? v.map((x) => ({ values: initValues(p.items, x as Record<string, unknown>, secretFields), set: secretFlags(x as Record<string, unknown>, secretFields) }))
        : [];
    else if (p.type === 'array') out[k] = Array.isArray(v) ? v.map(String).join('\n') : '';
    else if (p.type === 'integer') out[k] = typeof v === 'number' ? v : typeof v === 'string' && v !== '' ? Number(v) : null;
    else out[k] = v === undefined || v === null ? '' : String(v);
  }
  return out;
}

const HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;
const IPV6_RE = /^\[?[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*\]?$/;

const validPort = (n: number) => Number.isInteger(n) && n >= 1 && n <= 65535;

function checkString(v: string, p: JsonSchema): string | null {
  if (p.enum && !p.enum.map(String).includes(v)) return t.schema.enum;
  const len = [...v].length;
  if (p.minLength !== undefined && len < p.minLength) return t.schema.minLength(p.minLength);
  if (p.maxLength !== undefined && len > p.maxLength) return t.schema.maxLength(p.maxLength);
  if (p.pattern) {
    let re: RegExp | null = null;
    try {
      re = new RegExp(p.pattern, 'u');
    } catch {
      /* pattern the browser does not understand: leave it to the server */
    }
    if (re && !re.test(v)) return t.schema.pattern;
  }
  if (p.format === 'hostname' && !HOST_RE.test(v) && !IPV6_RE.test(v)) return t.schema.hostname;
  if (p.format === 'port' && !(/^\d{1,5}$/.test(v) && validPort(Number(v)))) return t.schema.port;
  return null;
}

function checkInteger(n: number, p: JsonSchema): string | null {
  if (!Number.isInteger(n)) return t.schema.integer;
  if (p.enum && !p.enum.map(Number).includes(n)) return t.schema.enum;
  if (p.minimum !== undefined && n < p.minimum) return t.schema.minimum(p.minimum);
  if (p.maximum !== undefined && n > p.maximum) return t.schema.maximum(p.maximum);
  if (p.format === 'port' && !validPort(n)) return t.schema.port;
  return null;
}

/**
 * Turns form values into the JSON object to send and validates it. Empty optional
 * fields are omitted; an empty write-only field whose secret is stored is omitted too
 * (= keep the stored secret).
 */
export function buildValue(
  s: JsonSchema | undefined,
  values: FormValues,
  { secretFields = [], secretSet = {} }: SecretOpts = {},
): { value: Record<string, unknown>; errors: Record<string, string> } {
  const value: Record<string, unknown> = {};
  const errors: Record<string, string> = {};
  const required = s?.required ?? [];
  for (const [k, p] of properties(s)) {
    if (!supported(p)) continue;
    const req = required.includes(k);
    const raw = values[k];
    if (p.type === 'boolean') {
      value[k] = !!raw;
      continue;
    }
    if (isList(p)) {
      // errors of item i's field f: `<k>.<i>.<f>`
      const items = Array.isArray(raw) ? raw : [];
      const list = items.map((it, i) => {
        const r = buildValue(p.items, it.values, { secretFields, secretSet: it.set });
        for (const [f, e] of Object.entries(r.errors)) errors[`${k}.${i}.${f}`] = e;
        return r.value;
      });
      if (p.maxItems !== undefined && list.length > p.maxItems) errors[k] = t.schema.maxItems(p.maxItems);
      if (list.length || req) value[k] = list;
      continue;
    }
    if (p.type === 'array') {
      const items = String(raw ?? '')
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean);
      for (const [i, item] of items.entries()) {
        const e = p.items ? checkString(item, p.items) : null;
        if (e) {
          errors[k] = t.schema.line(i + 1, e);
          break;
        }
      }
      if (items.length || req) value[k] = items;
      continue;
    }
    const secret = secretFields.includes(k);
    const empty = raw === null || raw === undefined || (typeof raw === 'string' && (secret ? raw : raw.trim()) === '');
    if (empty) {
      if (secret && secretSet[k]) continue; // keep the stored secret
      if (req) errors[k] = t.schema.required;
      continue;
    }
    if (p.type === 'integer') {
      const n = Number(raw);
      const e = checkInteger(n, p);
      if (e) errors[k] = e;
      else value[k] = n;
      continue;
    }
    // string: secrets are sent verbatim, everything else trimmed
    const str = secret ? String(raw) : String(raw).trim();
    const e = checkString(str, p);
    if (e) errors[k] = e;
    else value[k] = str;
  }
  return { value, errors };
}
