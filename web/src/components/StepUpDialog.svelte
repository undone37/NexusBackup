<script lang="ts">
  // Phase 29: step-up re-authentication after a 428 (the account is marked by a risk signal).
  // Password + authenticator code, or a passkey when the code field is left empty (like the other
  // re-authentication dialogs). On success the api layer sends the refused request again.
  import Modal from './Modal.svelte';
  import { post, errText } from '../lib/api';
  import { secondFactor } from '../lib/passkey';
  import { stepUp } from '../lib/stepup.svelte';
  import { session } from '../lib/session.svelte';
  import { notify } from '../lib/notify.svelte';
  import { t } from '../lib/i18n';

  let open = $state(false);
  let password = $state('');
  let totp = $state('');
  let busy = $state(false);
  let error: string | null = $state(null);
  $effect(() => {
    const asking = stepUp.resolve !== null;
    open = asking;
    if (asking) {
      password = totp = '';
      error = null;
    }
  });
  // closed via Esc / x / Cancel: the request stays refused
  $effect(() => {
    if (!open && stepUp.resolve) stepUp.resolve(false);
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    try {
      const current_totp = await secondFactor(totp);
      await post('/auth/step-up', { current_password: password, current_totp });
      if (session.stepUp) session.stepUp = { ...session.stepUp, done: true };
      notify('ok', t.p29.stepUp.done);
      stepUp.resolve?.(true);
    } catch (x) {
      error = errText(x);
    }
    busy = false;
  }
</script>

<Modal bind:open title={t.p29.stepUp.title}>
  <form onsubmit={submit}>
    <p>{t.p29.stepUp.intro}</p>
    {#if stepUp.reason}<p class="banner warn">{stepUp.reason}</p>{/if}
    {#if error}<p class="banner error" role="alert">{error}</p>{/if}
    <div class="form-grid">
      <div class="field">
        <label for="su-pw">{t.users.currentPassword}</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input id="su-pw" type="password" autocomplete="current-password" bind:value={password} required autofocus />
      </div>
      <div class="field">
        <label for="su-totp">{t.users.currentTotp}</label>
        <input
          id="su-totp"
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern={'[0-9]{6}'}
          maxlength="6"
          bind:value={totp}
          aria-describedby="su-totp-hint"
        />
        <div class="hint" id="su-totp-hint">{t.passkeys.totpOrPasskey}</div>
      </div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={busy || !password}>{t.p29.stepUp.submit}</button>
    </div>
  </form>
</Modal>
