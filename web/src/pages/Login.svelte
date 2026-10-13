<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, errText, API } from '../lib/api';
  import { setSession } from '../lib/session.svelte';
  import { t } from '../lib/i18n';
  import { href, route } from '../lib/router.svelte';
  import type { LoginResponse, OidcPublic } from '../lib/types';
  import { getPasskey, passkeysSupported } from '../lib/passkey';
  import Logo from '../components/Logo.svelte';
  import AuthHero from '../components/AuthHero.svelte';
  import IconKey from '@lucide/svelte/icons/key-round';
  import IconFingerprint from '@lucide/svelte/icons/fingerprint';

  let name = $state('');
  let password = $state('');
  let totp = $state('');
  let busy = $state(false);
  let error: string | null = $state(null);
  let oidc: OidcPublic | null = $state(null);
  // Phase 14d: the appliance's login banner (Settings → Security), plain text
  let banner = $state('');
  // single sign-on failures come back as /#/login?oidc_error=<code> (contract §2)
  const oidcError = $derived(route.path === '/login' ? route.query.get('oidc_error') : null);
  // after the IdP round trip, return to the page the user wanted (hash routes; same-origin path only)
  const next = $derived(route.path === '/' || route.path === '/login' ? '/' : `/#${route.path}`);

  onMount(async () => {
    [oidc, banner] = await Promise.all([
      get<OidcPublic>('/auth/oidc').catch(() => null),
      get<{ banner: string }>('/auth/banner')
        .then((b) => b.banner)
        .catch(() => ''),
    ]);
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!totp.trim()) {
      error = t.login.totpMissing;
      return;
    }
    await signIn(async () => ({ totp }));
  }

  // Phase 21c: password + passkey instead of the authenticator code
  async function withPasskey(e: MouseEvent) {
    const form = (e.currentTarget as HTMLButtonElement).form;
    if (form && !form.reportValidity()) return;
    await signIn(async () => {
      const o = await post<Record<string, any>>('/auth/login/passkey', { name });
      return { passkey: await getPasskey(o.data) };
    });
  }

  async function signIn(second: () => Promise<Record<string, unknown>>) {
    busy = true;
    error = null;
    try {
      const r = await post<LoginResponse>('/auth/login', { name, password, ...(await second()) });
      if (!r.quorum) setSession(r.data.user, r.data.csrf);
    } catch (err) {
      error = errText(err);
      totp = '';
    } finally {
      busy = false;
    }
  }
</script>

<div class="login">
  <AuthHero />
  <div class="pane">
    <form onsubmit={submit} aria-labelledby="login-title">
      <div class="brand"><Logo />{t.app}</div>
      <h1 id="login-title">{t.login.title}</h1>
      <p class="lede">{oidc?.enabled ? t.login.lede : t.login.ledeLocal}</p>
      {#if banner}<div class="banner info login-banner" role="note" aria-label={t.access.bannerLabel}>{banner}</div>{/if}
      {#if oidcError}<div class="banner error" role="alert">{t.login.oidcError(oidcError)}</div>{/if}
      {#if error}<div class="banner error" role="alert">{error}</div>{/if}
      {#if oidc?.enabled}
        <a class="button sso" href="{API}/auth/oidc/start?next={encodeURIComponent(next)}"><IconKey aria-hidden="true" />{oidc.label || t.login.title}</a>
        <div class="or">{t.login.or}</div>
      {/if}
      <div class="field">
        <label for="l-name">{t.login.name}</label>
        <input id="l-name" bind:value={name} autocomplete="username" required autocapitalize="none" spellcheck="false" />
      </div>
      <div class="field">
        <label for="l-pw">{t.login.password}</label>
        <input id="l-pw" type="password" bind:value={password} autocomplete="current-password" required />
      </div>
      <div class="field">
        <label for="l-totp">{t.login.totp}</label>
        <input
          id="l-totp"
          bind:value={totp}
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern={'[0-9]{6}'}
          maxlength="6"
          aria-describedby="l-totp-hint"
        />
        <div class="hint" id="l-totp-hint">{t.login.totpHint}</div>
      </div>
      <button class="primary" type="submit" disabled={busy}>{busy ? t.login.busy : t.login.submit}</button>
      {#if passkeysSupported()}
        <button class="passkey" type="button" disabled={busy} onclick={withPasskey}
          ><IconFingerprint aria-hidden="true" />{t.passkeys.signIn}</button
        >
      {/if}
      <p class="alt muted">{t.login.activateQ} <a href={href('/activate')}>{t.login.activateLink}</a></p>
    </form>
  </div>
</div>
