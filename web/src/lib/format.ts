import { t } from './i18n';

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function fmtTime(ts: number | null | undefined): string {
  return ts ? dtf.format(new Date(ts * 1000)) : '—';
}

export function fmtAgo(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return t.ago.never;
  const d = Math.max(0, now - ts);
  if (d < 90) return t.ago.now;
  if (d < 5400) return t.ago.min(Math.round(d / 60));
  if (d < 129600) return t.ago.h(Math.round(d / 3600));
  return t.ago.d(Math.round(d / 86400));
}

/** A time ahead as "in 25 min", "in 3 h", "in 2 d" ("now" when due). */
export function fmtIn(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return '—';
  const d = ts - now;
  if (d < 90) return t.inTime.now;
  if (d < 5400) return t.inTime.min(Math.round(d / 60));
  if (d < 129600) return t.inTime.h(Math.round(d / 3600));
  return t.inTime.d(Math.round(d / 86400));
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

export function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}

/** 0.991 -> "99.1 %" (whole numbers and >= 99.95 % without decimals). */
export function fmtPct(r: number | null | undefined, digits = 1): string {
  if (r === null || r === undefined || !Number.isFinite(r)) return '—';
  const v = r * 100;
  return `${v >= 99.95 || Number.isInteger(v) ? Math.round(v) : v.toFixed(digits)} %`;
}

/** 4.217 -> "4.2×" */
export function fmtRatio(x: number | null | undefined): string {
  return x === null || x === undefined || !Number.isFinite(x) ? '—' : `${x < 10 ? x.toFixed(x < 2 ? 2 : 1) : Math.round(x)}×`;
}

/** Bytes per second as decimal megabytes: "412 MB/s", "3.4 MB/s". */
/** Entries per second (jobs that count files instead of bytes: file index, agent scans). */
export function fmtEntryRate(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  return `${Math.round(n).toLocaleString('en-US')} entries/s`;
}

export function fmtRate(bps: number | null | undefined): string {
  if (bps === null || bps === undefined || !Number.isFinite(bps)) return '—';
  const mb = bps / 1e6;
  return `${mb < 10 ? mb.toFixed(1) : Math.round(mb).toLocaleString('en-US')} MB/s`;
}

/** Seconds as a short duration: "45 s", "15 min", "3 h", "2 d". */
export function fmtDuration(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s)) return '—';
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}

const dayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
const dayLong = new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' });
/** "2026-10-10" -> "Oct 10" (`long`: "Sat, Oct 10"); days are UTC calendar days. */
export function fmtDay(day: string, long = false): string {
  const d = new Date(`${day}T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? day : (long ? dayLong : dayFmt).format(d);
}

/** A "nice" axis maximum (1, 2, 2.5, 5 × 10^n) at or above `v`. */
export function niceMax(v: number): number {
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 1.2, 1.6, 2, 2.4, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

/** Absolute host path: `/srv/x`, or `C:\x` / `C:/x` for Windows agents. */
export const absHostPath = (p: string) => p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p);
