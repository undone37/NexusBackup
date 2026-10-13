// WebAuthn ceremonies for passkeys (Phase 21c, crate::passkeys): the server sends options with
// base64url fields and expects the authenticator's answer back in base64url. The mock backend marks
// its options with `mock: true`; then no browser prompt is shown (demo and screenshots).
import { post } from './api';
import { t } from './i18n';

type Json = Record<string, any>;

const b64 = (b: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(b)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const creds = (l: Json[] = []) => l.map((c) => ({ type: 'public-key' as const, id: unb64(c.id) }));
const fake = (n: number) => b64(crypto.getRandomValues(new Uint8Array(n)).buffer);

export const passkeysSupported = () => typeof window !== 'undefined' && 'PublicKeyCredential' in window;

function unsupported(): never {
  throw new Error(t.passkeys.unsupported);
}

/** navigator.credentials.create() → `{id, clientDataJSON, attestationObject}` */
export async function createPasskey(o: Json): Promise<Json> {
  if (o.mock) return { id: fake(16), clientDataJSON: fake(32), attestationObject: fake(64) };
  if (!passkeysSupported()) unsupported();
  const c = (await navigator.credentials.create({
    publicKey: {
      ...o,
      challenge: unb64(o.challenge),
      user: { ...o.user, id: unb64(o.user.id) },
      excludeCredentials: creds(o.excludeCredentials),
    } as unknown as PublicKeyCredentialCreationOptions,
  })) as PublicKeyCredential | null;
  if (!c) throw new Error(t.passkeys.cancelled);
  const r = c.response as AuthenticatorAttestationResponse;
  return { id: b64(c.rawId), clientDataJSON: b64(r.clientDataJSON), attestationObject: b64(r.attestationObject) };
}

/** navigator.credentials.get() → `{id, clientDataJSON, authenticatorData, signature}` */
export async function getPasskey(o: Json): Promise<Json> {
  if (o.mock)
    return { id: o.allowCredentials?.[0]?.id ?? fake(16), clientDataJSON: fake(32), authenticatorData: fake(37), signature: fake(64) };
  if (!passkeysSupported()) unsupported();
  const c = (await navigator.credentials.get({
    publicKey: { ...o, challenge: unb64(o.challenge), allowCredentials: creds(o.allowCredentials) } as unknown as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential | null;
  if (!c) throw new Error(t.passkeys.cancelled);
  const r = c.response as AuthenticatorAssertionResponse;
  return {
    id: b64(c.rawId),
    clientDataJSON: b64(r.clientDataJSON),
    authenticatorData: b64(r.authenticatorData),
    signature: b64(r.signature),
  };
}

/**
 * Second factor of a re-authentication (`current_totp`): the typed TOTP code, or — when the field is
 * left empty — a passkey assertion (JSON), which the server accepts in the same field.
 */
export async function secondFactor(totp: string): Promise<string> {
  if (totp.trim()) return totp.trim();
  const o = await post<Json>('/auth/passkeys/challenge', {});
  return JSON.stringify(await getPasskey(o.data as Json));
}
