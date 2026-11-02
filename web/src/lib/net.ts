// Address checks of the network dialogs (Settings > Network), run while typing so a mistake shows next
// to its field; the API (crates/web-api, nexus-net) stays the authority. IPv4 is checked fully, IPv6
// only for its shape. Ported from NexusStor's components/vstor/net.ts.
import { t } from './i18n';

function ip4(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m || m.slice(1).some((x) => Number(x) > 255)) return null;
  return m.slice(1).reduce((a, x) => a * 256 + Number(x), 0);
}
const dotted = (n: number) => [24, 16, 8, 0].map((sh) => Math.floor(n / 2 ** sh) % 256).join('.');

/** Parsed `a.b.c.d/p` (IPv4 only). */
export function parseCidr(s: string): { ip: number; prefix: number; net: number; size: number } | null {
  const [a, p] = s.trim().split('/');
  const ip = ip4(a ?? '');
  if (ip === null || !/^\d{1,2}$/.test(p ?? '') || Number(p) > 32) return null;
  const prefix = Number(p);
  const size = 2 ** (32 - prefix);
  return { ip, prefix, net: Math.floor(ip / size) * size, size };
}
const isV6 = (s: string) => s.includes(':');
/** An IPv4 address, or something that looks like an IPv6 one (the API checks those). */
export const isIp = (s: string) => (isV6(s) ? /^[0-9a-fA-F:]+$/.test(s) : ip4(s) !== null);

/** '' when `a` is a usable `address/prefix`, otherwise what is wrong with it. */
export function checkAddress(a: string): string {
  const c = t.net.chk;
  if (!a) return '';
  if (isV6(a)) return /^[0-9a-fA-F:]+\/\d{1,3}$/.test(a.trim()) ? '' : c.address;
  const p = parseCidr(a);
  if (!p) return c.address;
  if (p.prefix < 32 && p.ip === p.net) return c.networkAddr;
  if (p.prefix < 31 && p.ip === p.net + p.size - 1) return c.broadcast;
  return '';
}

/** The subnet of `address/prefix`, '' if not parseable. */
export function subnetOf(addr: string): string {
  const c = parseCidr(addr);
  return c ? `${dotted(c.net)}/${c.prefix}` : '';
}

/** Whether the IPv4 address `ip` lies in one of the IPv4 `address/prefix` entries (true if none is IPv4). */
export function inSubnets(ip: string, addrs: string[]): boolean {
  const g = ip4(ip.trim());
  const nets = addrs.map((a) => parseCidr(a)).filter((x) => !!x);
  if (g === null || !nets.length) return true;
  return nets.some((n) => g >= n.net && g < n.net + n.size);
}
