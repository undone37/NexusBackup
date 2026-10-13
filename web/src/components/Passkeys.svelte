<script lang="ts">
  // My passkeys (Phase 21c): register (re-authenticated, then the browser prompt), rename, remove.
  // The server keeps the last passkey while the policy requires passkeys for the user's role.
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { askConfirm, askText } from '../lib/confirm.svelte';
  import { createPasskey, secondFactor } from '../lib/passkey';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Passkey } from '../lib/types';
  import Modal from './Modal.svelte';
  import ErrorBanner from './ErrorBanner.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';

  const id = $props.id();
  let items: Passkey[] = $state([]);
  let required = $state(false);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      const r = await get<{ passkeys: Passkey[]; required: boolean }>('/auth/passkeys');
      items = r.passkeys;
      required = r.required;
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  let open = $state(false);
  let busy = $state(false);
  let f = $state({ name: '', password: '', totp: '' });

  async function add(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    const name = f.name.trim();
    const r = await act(
      secondFactor(f.totp)
        .then((totp) => post<Record<string, any>>('/auth/passkeys/register/begin', { current_password: f.password, current_totp: totp }))
        .then((o) => createPasskey(o.data))
        .then((credential) => post('/auth/passkeys/register', { name, credential })),
      t.passkeys.added,
    );
    busy = false;
    f = { name: '', password: '', totp: '' };
    if (!r) return;
    open = false;
    load();
  }

  async function rename(x: Passkey) {
    const name = await askText(t.passkeys.renamePrompt, x.name);
    if (name === null || !name.trim()) return;
    if (await act(put(`/auth/passkeys/${x.id}`, { name: name.trim() }), t.passkeys.renamed)) load();
  }

  async function remove(x: Passkey) {
    if (!(await askConfirm(t.passkeys.removeConfirm(x.name)))) return;
    if (await act(del(`/auth/passkeys/${x.id}`), t.passkeys.removed)) load();
  }
</script>

<section class="card" aria-labelledby="{id}-h">
  <div class="card-head">
    <h2 id="{id}-h">{t.passkeys.title}</h2>
    <button type="button" class="small" onclick={() => ((f = { name: '', password: '', totp: '' }), (open = true))}
      ><IconPlus aria-hidden="true" />{t.passkeys.add}</button
    >
  </div>
  <p class="muted">{required ? t.passkeys.requiredLede : t.passkeys.lede}</p>
  <ErrorBanner {error} />
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if items.length === 0}
    <p class="empty">{t.passkeys.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.name}</th>
            <th scope="col">{t.passkeys.alg}</th>
            <th scope="col">{t.passkeys.host}</th>
            <th scope="col">{t.passkeys.added_at}</th>
            <th scope="col">{t.passkeys.lastUsed}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            <tr>
              <td><strong>{x.name}</strong></td>
              <td><span class="chip">{x.alg}</span></td>
              <td><code>{x.rp_id}</code></td>
              <td class="nowrap">{fmtTime(x.created)}</td>
              <td class="nowrap">{fmtAgo(x.last_used)}</td>
              <td class="actions">
                <button type="button" class="small" onclick={() => rename(x)}>{t.passkeys.rename}</button>
                <button type="button" class="small danger" onclick={() => remove(x)}>{t.passkeys.remove}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<Modal bind:open title={t.passkeys.add}>
  <form onsubmit={add}>
    <div class="field">
      <label for="{id}-name">{t.passkeys.nameLabel}</label>
      <input id="{id}-name" bind:value={f.name} maxlength="64" placeholder={t.passkeys.namePlaceholder} autocomplete="off" />
    </div>
    <fieldset>
      <legend>{t.users.reauth}</legend>
      <p class="muted">{t.passkeys.addHint}</p>
      <div class="form-grid">
        <div class="field">
          <label for="{id}-pw">{t.users.currentPassword}</label>
          <input id="{id}-pw" type="password" bind:value={f.password} required autocomplete="current-password" />
        </div>
        <div class="field">
          <label for="{id}-totp">{t.users.currentTotp}</label>
          <input id="{id}-totp" bind:value={f.totp} inputmode="numeric" pattern={'[0-9]{6}'} maxlength="6" autocomplete="one-time-code" aria-describedby="{id}-totp-hint" />
          <div class="hint" id="{id}-totp-hint">{t.passkeys.totpOrPasskey}</div>
        </div>
      </div>
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={busy}>{busy ? t.passkeys.adding : t.passkeys.add}</button>
    </div>
  </form>
</Modal>
