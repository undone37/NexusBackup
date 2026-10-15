import type { RtCheck, RtChecks } from './types';

/** Form state of restore-test checks (text inputs). */
export interface ChecksForm {
  boot: string | number;
  agent: boolean;
  ports: string;
  command: string;
  expect: string | number;
}

export const emptyChecks = (): ChecksForm => ({ boot: '', agent: true, ports: '', command: '', expect: '0' });

export function checksForm(c: RtChecks | undefined | null): ChecksForm {
  return {
    boot: c?.boot_timeout ? String(c.boot_timeout) : '',
    agent: c?.agent !== false,
    ports: (c?.ports ?? []).join(', '),
    command: (c?.command ?? []).join(' '),
    expect: String(c?.expect_exit ?? 0),
  };
}

/** API checks; containers get the boot timeout only (they have no guest agent). */
export function toChecks(f: ChecksForm, ct: boolean): RtChecks {
  const out: RtChecks = {};
  if (String(f.boot ?? '').trim()) out.boot_timeout = Number(f.boot);
  if (ct) return out;
  if (!f.agent) out.agent = false;
  const ports = f.ports
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(Number);
  if (ports.length) out.ports = ports;
  const cmd = f.command.trim().split(/\s+/).filter(Boolean);
  if (cmd.length) {
    out.command = cmd;
    out.expect_exit = Number(f.expect || 0);
  }
  return out;
}

/** One line per check for tables: ✓/✗ name. */
export const checkSummary = (cs: RtCheck[] | null | undefined) =>
  (cs ?? []).map((c) => `${c.ok ? '✓' : '✗'} ${c.name}`).join('  ');

export const stateChip = (s: string) =>
  s === 'passed' ? 'ok' : s === 'failed' ? 'bad' : s === 'running' ? 'info' : 'plain';
