<script lang="ts">
  // Phase 30: just-in-time role elevation (POST /auth/elevate). The account's eligible role for a
  // chosen time, with a reason, confirmed with the password and an authenticator code (or a passkey
  // when the code field is left empty). With the approval setting the answer is a request (202).
  import Modal from './Modal.svelte';
  import { get, post, act } from '../lib/api';
  import { secondFactor } from '../lib/passkey';
  import { session, setSession } from '../lib/session.svelte';
  import { t } from '../lib/i18n';
  import type { LoginResponse } from '../lib/types';

  let { open = $bindable(false) }: { open: boolean } = $props();
  const MINUTES = [15, 30, 60, 120, 240, 480];
  let minutes = $state(60);
  let reason = $state('');
  let password = $state('');
  let totp = $state('');
  let busy = $state(false);
  const role = $derived(session.user?.eligible_role ?? null);
  $effect(() => {
    if (open) {
      reason = password = totp = '';
      minutes = 60;
    }
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!role) return;
    busy = true;
    const o = await act(
      secondFactor(totp).then((current_totp) =>
        post<{ elevated?: { role: string; until: number } }>('/auth/elevate', {
          role,
          minutes,
          reason: reason.trim(),
          current_password: password,
          current_totp,
        }),
      ),
      t.p30.elev.done(t.roles[role]),
    );
    busy = false;
    password = totp = '';
    if (!o) return;
    open = false;
    const me = await get<LoginResponse>('/auth/me').catch(() => null);
    if (me) {
      const imp = session.impersonating;
      setSession(me.user, me.csrf);
      session.impersonating = imp;
      session.elevation = me.elevation ?? null;
    }
  }
</script>

<Modal bind:open title={t.p30.elev.title}>
  <form onsubmit={submit}>
    <p>{role ? t.p30.elev.intro(t.roles[role], t.roles[session.user?.role ?? ''] ?? '') : ''}</p>
    <div class="form-grid">
      <div class="field">
        <label for="el-min">{t.p30.elev.duration}</label>
        <select id="el-min" bind:value={minutes}>
          {#each MINUTES as m (m)}<option value={m}>{t.p30.elev.minutes(m)}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="el-reason">{t.p30.elev.reason}</label>
        <input
          id="el-reason"
          bind:value={reason}
          required
          maxlength="200"
          autocomplete="off"
          aria-describedby="el-reason-hint"
        />
        <div class="hint" id="el-reason-hint">{t.p30.elev.reasonHint}</div>
      </div>
    </div>
    <div class="form-grid">
      <div class="field">
        <label for="el-pw">{t.users.currentPassword}</label>
        <input id="el-pw" type="password" autocomplete="current-password" bind:value={password} required />
      </div>
      <div class="field">
        <label for="el-totp">{t.users.currentTotp}</label>
        <input
          id="el-totp"
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern={'[0-9]{6}'}
          maxlength="6"
          bind:value={totp}
          aria-describedby="el-totp-hint"
        />
        <div class="hint" id="el-totp-hint">{t.passkeys.totpOrPasskey}</div>
      </div>
    </div>
    <p class="muted">{t.p30.elev.audited}</p>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={busy || !password || !reason.trim()}>{t.p30.elev.submit}</button>
    </div>
  </form>
</Modal>
