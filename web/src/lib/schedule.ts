// Policy schedules and blackout windows (Phase 13b; same grammar as crates/catalog/src/schedule.rs):
// `daily HH:MM`, `hourly MM`, `every Nh [at MM]` (N divides 24), `Mon,Wed,Fri HH:MM` / `Mon-Fri HH:MM`,
// `monthly D HH:MM`. Evaluated in the group's time zone by the scheduler.

export const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] as const;
export const EVERY = [1, 2, 3, 4, 6, 8, 12];

export type SchedKind = 'daily' | 'hours' | 'weekdays' | 'monthly';
export interface SchedForm {
  kind: SchedKind;
  /** hours: every N hours (1 = hourly) */
  every: number;
  hour: number;
  minute: number;
  days: string[];
  monthDay: number;
}

const two = (n: number) => String(n).padStart(2, '0');
const HHMM = /^([01]\d|2[0-3]):([0-5]\d)$/;
const MM = /^[0-5]\d$/;

/** Weekday list or range → days (Mon..Sun order), or null. */
function dayList(s: string): string[] | null {
  const out = new Set<string>();
  for (const part of s.split(',')) {
    const [a, b] = part.split('-');
    const ia = DAYS.indexOf(a as (typeof DAYS)[number]);
    const ib = b === undefined ? ia : DAYS.indexOf(b as (typeof DAYS)[number]);
    if (ia < 0 || ib < 0 || ia > ib) return null;
    for (let i = ia; i <= ib; i++) out.add(DAYS[i]);
  }
  return DAYS.filter((d) => out.has(d));
}

/** Parses a schedule string into the builder form, or null if invalid. */
export function parseSchedule(s: string): SchedForm | null {
  const base: SchedForm = { kind: 'daily', every: 1, hour: 1, minute: 0, days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'], monthDay: 1 };
  const p = s.split(' ');
  const hm = (t: string) => {
    const m = HHMM.exec(t);
    return m ? { hour: Number(m[1]), minute: Number(m[2]) } : null;
  };
  if (p[0] === 'daily' && p.length === 2) {
    const t = hm(p[1]);
    return t && { ...base, kind: 'daily', ...t };
  }
  if (p[0] === 'hourly' && p.length === 2) return MM.test(p[1]) ? { ...base, kind: 'hours', every: 1, minute: Number(p[1]) } : null;
  if (p[0] === 'every' && (p.length === 2 || (p.length === 4 && p[2] === 'at'))) {
    const n = /^(\d{1,2})h$/.exec(p[1]);
    if (!n || !EVERY.includes(Number(n[1]))) return null;
    if (p.length === 4 && !MM.test(p[3])) return null;
    return { ...base, kind: 'hours', every: Number(n[1]), minute: p.length === 4 ? Number(p[3]) : 0 };
  }
  if (p[0] === 'monthly' && p.length === 3) {
    const d = /^\d{1,2}$/.test(p[1]) ? Number(p[1]) : 0;
    const t = hm(p[2]);
    return d >= 1 && d <= 31 && t ? { ...base, kind: 'monthly', monthDay: d, ...t } : null;
  }
  if (p.length === 2) {
    const days = dayList(p[0]);
    const t = hm(p[1]);
    return days && t ? { ...base, kind: 'weekdays', days, ...t } : null;
  }
  return null;
}

/** Builder form → schedule string (as the API expects it). */
export function formatSchedule(f: SchedForm): string {
  const at = `${two(f.hour)}:${two(f.minute)}`;
  switch (f.kind) {
    case 'hours':
      return f.every === 1 ? `hourly ${two(f.minute)}` : `every ${f.every}h at ${two(f.minute)}`;
    case 'weekdays':
      return f.days.length === 7 ? `daily ${at}` : `${DAYS.filter((d) => f.days.includes(d)).join(',')} ${at}`;
    case 'monthly':
      return `monthly ${f.monthDay} ${at}`;
    default:
      return `daily ${at}`;
  }
}

/** Longest gap between two runs in seconds (the RPO the dashboard compares against). */
export function schedulePeriod(s: string): number {
  const f = parseSchedule(s);
  if (!f) return 86400;
  if (f.kind === 'hours') return f.every * 3600;
  if (f.kind === 'monthly') return 31 * 86400;
  if (f.kind === 'daily') return 86400;
  const idx = DAYS.map((d, i) => (f.days.includes(d) ? i : -1)).filter((i) => i >= 0);
  const gaps = idx.map((d, i) => (i + 1 < idx.length ? idx[i + 1] - d : idx[0] + 7 - d));
  return Math.max(1, ...gaps) * 86400;
}

export interface BlackoutWindow {
  /** start days (empty = every day) */
  days: string[];
  from: string;
  to: string;
  abort: boolean;
}

export const validWindow = (w: BlackoutWindow) => HHMM.test(w.from) && HHMM.test(w.to) && w.from !== w.to;

/** Weekday (Mon..Sun) and minutes since midnight of `t` (unix seconds) in time zone `tz`. */
function local(t: number, tz: string): { day: number; mins: number } {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(
    new Date(t * 1000),
  );
  const get = (k: string) => parts.find((p) => p.type === k)?.value ?? '';
  return { day: DAYS.indexOf(get('weekday') as (typeof DAYS)[number]), mins: Number(get('hour')) * 60 + Number(get('minute')) };
}

/** Whether one of the windows is active at `t` in `tz` (wall-clock approximation; the scheduler decides). */
export function blackoutActive(windows: BlackoutWindow[], tz: string, t: number): boolean {
  let l: { day: number; mins: number };
  try {
    l = local(t, tz);
  } catch {
    return false;
  }
  const mins = (s: string) => Number(s.slice(0, 2)) * 60 + Number(s.slice(3, 5));
  const on = (w: BlackoutWindow, d: number) => !w.days.length || w.days.includes(DAYS[(d + 7) % 7]);
  return windows.some((w) => {
    const [f, to] = [mins(w.from), mins(w.to)];
    if (to > f) return on(w, l.day) && l.mins >= f && l.mins < to;
    return (on(w, l.day) && l.mins >= f) || (on(w, l.day - 1) && l.mins < to);
  });
}

/** Time zones offered for groups (the browser's list; the API validates). */
export function timeZones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] };
  const all = intl.supportedValuesOf?.('timeZone') ?? ['Europe/Berlin', 'Europe/London', 'America/New_York'];
  return ['UTC', ...all.filter((z) => z !== 'UTC')];
}

/** `paused_until` / `maintenance_until`: active now? (-1 = indefinitely) */
export const isPaused = (until: number | null | undefined, t = Date.now() / 1000) => until === -1 || (!!until && until > t);
