<script lang="ts">
  // Phase 28: the account's sign-in devices (browser family + network) and the address the
  // new-device notice is mailed to.
  import { onMount } from 'svelte';
  import { get, put, del, act, errText } from '../lib/api';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { session } from '../lib/session.svelte';
  import type { LoginDevice } from '../lib/types';
  import ErrorBanner from './ErrorBanner.svelte';

  let devices: LoginDevice[] = $state([]);
  let email = $state('');
  let loaded = $state(false);
  let error: string | null = $state(null);
  let busy = $state(false);

  async function load() {
    try {
      const r = await get<{ devices: LoginDevice[]; email: string | null }>('/auth/devices');
      devices = r.devices;
      email = r.email ?? '';
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  async function forget(d: LoginDevice) {
    if (await act(del(`/auth/devices/${d.fingerprint}`), t.devices.forgotten)) load();
  }
  async function saveEmail(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    await act(put('/auth/email', { email: email.trim() || null }), t.devices.emailSaved);
    busy = false;
  }
</script>

<section class="card" aria-labelledby="acc-dev">
  <div class="card-head"><h2 id="acc-dev">{t.devices.title}</h2></div>
  <p class="muted">{t.devices.lede}</p>
  <ErrorBanner {error} />
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if !devices.length}
    <p class="empty">{t.devices.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.devices.family}</th>
            <th scope="col">{t.devices.network}</th>
            <th scope="col">{t.devices.firstSeen}</th>
            <th scope="col">{t.devices.lastSeen}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each devices as d (d.fingerprint)}
            <tr>
              <td>{d.family}</td>
              <td class="mono">{d.prefix}</td>
              <td class="nowrap">{fmtTime(d.first_seen)}</td>
              <td class="nowrap">{fmtTime(d.last_seen)}</td>
              <td class="actions">
                <button type="button" class="small" onclick={() => forget(d)} aria-label={t.devices.forgetLabel(d.family, d.prefix)}>{t.devices.forget}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if !session.impersonating}
    <form class="email" onsubmit={saveEmail}>
      <div class="field">
        <label for="acc-email">{t.devices.email}</label>
        <input
          id="acc-email"
          type="email"
          autocomplete="email"
          bind:value={email}
          readonly={session.user?.auth === 'oidc'}
          aria-describedby="acc-email-hint"
        />
        <p class="hint" id="acc-email-hint">{t.devices.emailHint}</p>
      </div>
      {#if session.user?.auth !== 'oidc'}
        <div class="form-actions"><button type="submit" disabled={busy}>{t.save}</button></div>
      {/if}
    </form>
  {/if}
</section>

<style>
  .email {
    margin-top: 1rem;
  }
</style>
