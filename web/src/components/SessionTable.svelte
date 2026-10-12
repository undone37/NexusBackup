<script lang="ts">
  import { del, post, act } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { SessionInfo } from '../lib/types';
  import Modal from './Modal.svelte';

  // Own sessions (My account) or, with `showUser`, every session (Settings → Security, admin).
  let {
    sessions,
    showUser = false,
    revokeAll = false,
    onchange,
  }: { sessions: SessionInfo[]; showUser?: boolean; revokeAll?: boolean; onchange: () => void } = $props();

  async function revoke(s: SessionInfo) {
    if (!(await askConfirm(t.access.revokeConfirm))) return;
    const path = showUser ? `/sessions/${s.id}` : `/auth/sessions/${s.id}`;
    if (await act(del(path), t.access.revoked)) onchange();
  }

  // appliance-wide: re-authentication of the acting admin
  let allOpen = $state(false);
  let re = $state({ password: '', totp: '' });
  async function confirmAll(e: SubmitEvent) {
    e.preventDefault();
    const r = await act(
      post<{ revoked: number }>('/sessions/revoke-all', { current_password: re.password, current_totp: re.totp.trim() }),
      (d) => t.access.revokedN(d.revoked),
    );
    re = { password: '', totp: '' };
    if (!r) return;
    allOpen = false;
    onchange();
  }
</script>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        {#if showUser}<th scope="col">{t.name}</th>{/if}
        <th scope="col">{t.access.ip}</th>
        <th scope="col">{t.access.agent}</th>
        <th scope="col">{t.access.started}</th>
        <th scope="col">{t.access.lastSeen}</th>
        <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
      </tr>
    </thead>
    <tbody>
      {#each sessions as s (s.id)}
        <tr>
          {#if showUser}<td><strong>{s.user}</strong></td>{/if}
          <td class="nowrap"><code>{s.ip || '—'}</code></td>
          <td class="ua" title={s.user_agent}>{s.user_agent || '—'}</td>
          <td class="nowrap">{fmtTime(s.created)}</td>
          <td class="nowrap">{fmtAgo(s.last_seen)}</td>
          <td class="actions">
            {#if s.current}
              <span class="chip ok">{t.access.current}</span>
            {:else}
              <button type="button" class="small" onclick={() => revoke(s)}>{t.access.revoke}</button>
            {/if}
          </td>
        </tr>
      {:else}
        <tr><td colspan={showUser ? 6 : 5} class="muted">{t.none}</td></tr>
      {/each}
    </tbody>
  </table>
</div>
{#if revokeAll}
  <p class="muted">{t.access.revokeAllHint}</p>
  <div class="form-actions">
    <button type="button" class="danger" onclick={() => ((re = { password: '', totp: '' }), (allOpen = true))}>{t.access.revokeAll}</button>
  </div>
  <Modal bind:open={allOpen} title={t.access.revokeAll}>
    <form onsubmit={confirmAll}>
      <p>{t.access.revokeAllHint}</p>
      <div class="form-grid">
        <div class="field">
          <label for="ra-pw">{t.users.currentPassword}</label>
          <input id="ra-pw" type="password" bind:value={re.password} required autocomplete="current-password" />
        </div>
        <div class="field">
          <label for="ra-totp">{t.users.currentTotp}</label>
          <input id="ra-totp" bind:value={re.totp} required inputmode="numeric" pattern={'[0-9]{6}'} maxlength="6" autocomplete="one-time-code" />
        </div>
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (allOpen = false)}>{t.cancel}</button>
        <button type="submit" class="danger">{t.access.revokeAll}</button>
      </div>
    </form>
  </Modal>
{/if}

<style>
  .ua {
    max-width: 28rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
