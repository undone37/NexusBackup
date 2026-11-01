// NexusStor sources (docs/nexusstor-design.md): the pairing token NexusStor shows is pasted into the
// source form. The form only previews it; the server decodes it again and derives host, port, the
// pinned certificate fingerprint and the pairing's client certificate.

/** A pairing token as the form previews it (no import: the mock backend uses this module too). */
export interface NexusStorToken {
  host: string;
  port: number;
  fingerprint: string;
  /** Unix seconds */
  expires: number;
}

export const NEXUSSTOR_KIND = 'plugin:nexusstor';

/** The token's content, or null when it is not a well-formed `nst1.` token. */
export function decodeToken(raw: string): NexusStorToken | null {
  const m = /^nst1\.([A-Za-z0-9_-]+)={0,2}$/.exec(raw.trim());
  if (!m) return null;
  try {
    const b64 = m[1].replace(/-/g, '+').replace(/_/g, '/');
    const j = JSON.parse(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)));
    if (
      typeof j?.address !== 'string' ||
      typeof j.fingerprint !== 'string' ||
      !/^[0-9a-f]{64}$/.test(j.fingerprint) ||
      typeof j.code !== 'string' ||
      !/^[A-Z2-7]{26}$/.test(j.code) ||
      !Number.isInteger(j.expires)
    )
      return null;
    const a: string = j.address;
    let host = a;
    let port = 8443;
    const v6 = /^\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?$/.exec(a);
    if (v6) {
      host = v6[1];
      if (v6[2]) port = Number(v6[2]);
    } else if (a.split(':').length === 2) {
      const [h, p] = a.split(':');
      if (!/^\d{1,5}$/.test(p)) return null;
      host = h;
      port = Number(p);
    }
    if (!host || port < 1 || port > 65535) return null;
    return { host, port, fingerprint: j.fingerprint, expires: j.expires };
  } catch {
    return null;
  }
}

/** A SHA-256 fingerprint in groups of four hex digits (to compare with NexusStor's screen). */
export const groupHex = (h: string) => h.match(/.{1,4}/g)?.join(' ') ?? h;
