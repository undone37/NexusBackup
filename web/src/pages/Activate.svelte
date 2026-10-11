<script lang="ts">
  import { post, errText } from '../lib/api';
  import { route, href } from '../lib/router.svelte';
  import { t } from '../lib/i18n';
  import Qr from '../components/Qr.svelte';
  import Logo from '../components/Logo.svelte';
  import AuthHero from '../components/AuthHero.svelte';

  // Self-enrollment at first sign-in: name + one-time activation code → own password →
  // own authenticator (QR shown only here) → confirm with a code. The code never goes
  // into the URL; only the user name may be prefilled from `#/activate?name=…`.
  let step = $state<1 | 2 | 3 | 4>(1);
  let name = $state(route.query.get('name') ?? '');
  let code = $state('');
  let password = $state('');
  let repeat = $state('');
  let totp = $state('');
  let enroll = $state<{ totp_uri: string; totp_secret: string } | null>(null);
  let busy = $state(false);
  let error: string | null = $state(null);

  async function begin(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      const r = await post<{ name: string; totp_uri: string; totp_secret: string }>('/auth/activate/begin', {
        name: name.trim(),
        code: code.trim(),
      });
      enroll = { totp_uri: r.data.totp_uri ?? '', totp_secret: r.data.totp_secret ?? '' };
      step = 2;
    } catch (err) {
      error = errText(err);
    } finally {
      busy = false;
    }
  }

  function choosePassword(e: SubmitEvent) {
    e.preventDefault();
    error = null;
    if (password.length < 12) error = t.activate.tooShort;
    else if (password !== repeat) error = t.activate.mismatch;
    else step = 3;
  }

  async function complete(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      await post('/auth/activate/complete', { name: name.trim(), code: code.trim(), password, totp: totp.trim() });
      password = repeat = code = totp = '';
      enroll = null;
      step = 4;
    } catch (err) {
      error = errText(err);
      totp = '';
    } finally {
      busy = false;
    }
  }

  const steps = [t.activate.stepCode, t.activate.stepPassword, t.activate.stepAuth];
</script>

<div class="login">
  <AuthHero />
  <div class="pane">
  <div class="card" aria-labelledby="act-title">
    <div class="brand"><Logo />{t.app}</div>
    <h1 id="act-title">{t.activate.title}</h1>
    {#if step < 4}
      <ol class="steps">
        {#each steps as s, i (s)}
          <li aria-current={step === i + 1 ? 'step' : undefined}>{s}</li>
        {/each}
      </ol>
    {/if}
    {#if error}<div class="banner error" role="alert">{error}</div>{/if}

    {#if step === 1}
      <p class="muted">{t.activate.intro}</p>
      <form onsubmit={begin}>
        <div class="field">
          <label for="a-name">{t.activate.name}</label>
          <input id="a-name" bind:value={name} autocomplete="username" required autocapitalize="none" spellcheck="false" />
        </div>
        <div class="field">
          <label for="a-code">{t.activate.code}</label>
          <input
            id="a-code"
            bind:value={code}
            autocomplete="off"
            required
            autocapitalize="characters"
            spellcheck="false"
            aria-describedby="a-code-hint"
          />
          <div class="hint" id="a-code-hint">{t.activate.codeHint}</div>
        </div>
        <button class="primary" type="submit" disabled={busy}>{busy ? t.activate.checking : t.activate.next}</button>
      </form>
    {:else if step === 2}
      <form onsubmit={choosePassword}>
        <input type="text" class="visually-hidden" value={name} autocomplete="username" readonly tabindex="-1" aria-hidden="true" />
        <div class="field">
          <label for="a-pw">{t.activate.password}</label>
          <input
            id="a-pw"
            type="password"
            bind:value={password}
            minlength="12"
            required
            autocomplete="new-password"
            aria-describedby="a-pw-hint"
          />
          <div class="hint" id="a-pw-hint">{t.activate.passwordHint}</div>
        </div>
        <div class="field">
          <label for="a-pw2">{t.activate.passwordRepeat}</label>
          <input id="a-pw2" type="password" bind:value={repeat} minlength="12" required autocomplete="new-password" />
        </div>
        <div class="form-actions">
          <button type="submit" class="primary">{t.activate.next}</button>
        </div>
      </form>
    {:else if step === 3 && enroll}
      <form onsubmit={complete}>
        <p>{t.activate.scan}</p>
        <div class="qr-box">
          <Qr text={enroll.totp_uri} label="{t.activate.stepAuth} {name}" />
          <div class="field">
            <span class="muted">{t.activate.secret}</span>
            <code class="secret">{enroll.totp_secret}</code>
          </div>
        </div>
        <div class="field">
          <label for="a-totp">{t.activate.totp}</label>
          <input
            id="a-totp"
            bind:value={totp}
            inputmode="numeric"
            autocomplete="one-time-code"
            pattern={'[0-9]{6}'}
            maxlength="6"
            required
            aria-describedby="a-totp-hint"
          />
          <div class="hint" id="a-totp-hint">{t.activate.totpHint}</div>
        </div>
        <div class="form-actions">
          <button type="button" onclick={() => (step = 2)}>{t.activate.back}</button>
          <button class="primary" type="submit" disabled={busy}>{busy ? t.activate.finishing : t.activate.finish}</button>
        </div>
      </form>
    {:else}
      <p class="banner ok" role="status">{t.activate.done}</p>
      <p><a href={href('/')}>{t.activate.toLogin}</a></p>
    {/if}
  </div>
</div>
</div>
