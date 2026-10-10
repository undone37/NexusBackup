<script lang="ts">
  import { post, errText } from '../lib/api';
  import { setSession } from '../lib/session.svelte';
  import { t } from '../lib/i18n';
  import { href } from '../lib/router.svelte';
  import type { LoginResponse } from '../lib/types';
  import logo from '../favicon.svg';

  let name = $state('');
  let password = $state('');
  let totp = $state('');
  let busy = $state(false);
  let error: string | null = $state(null);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      const r = await post<LoginResponse>('/auth/login', { name, password, totp });
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
  <form class="card" onsubmit={submit} aria-labelledby="login-title">
    <div class="brand"><img src={logo} alt="" />{t.app}</div>
    <h1 id="login-title">{t.login.title}</h1>
    {#if error}<div class="banner error" role="alert">{error}</div>{/if}
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
        required
        aria-describedby="l-totp-hint"
      />
      <div class="hint" id="l-totp-hint">{t.login.totpHint}</div>
    </div>
    <button class="primary" type="submit" disabled={busy}>{busy ? t.login.busy : t.login.submit}</button>
    <p class="muted">{t.login.activateQ} <a href={href('/activate')}>{t.login.activateLink}</a></p>
  </form>
</div>
