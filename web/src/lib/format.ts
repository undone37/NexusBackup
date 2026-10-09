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
