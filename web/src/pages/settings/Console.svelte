<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, del, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { notify } from '../../lib/notify.svelte';
  import { session } from '../../lib/session.svelte';
  import { copyText } from '../../lib/clipboard';
  import { fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { ConsoleCode, ConsoleUnlock, ConsoleUnlockStatus } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import Modal from '../../components/Modal.svelte';
  import IconCopy from '@lucide/svelte/icons/copy';
  import IconTerminal from '@lucide/svelte/icons/square-terminal';

  // Emergency console root access (Phase 14c): request -> approval -> code shown once -> tty2.
  const admin = $derived(session.user?.role === 'admin');
  let items: ConsoleUnlock[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let form = $state({ hours: 1, reason: '' });
  let busy = $state(false);

  async function load() {
    try {
      items = await get<ConsoleUnlock[]>('/console/unlock');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  const cls: Record<ConsoleUnlockStatus, string> = {
    pending: 'warn',
    approved: 'info',
    issued: 'warn',
    used: 'bad',
    rejected: '',
    expired: '',
    revoked: '',
  };

  async function request(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    try {
      // not act(): with approvals disabled the request is approved at once, nothing "runs shortly"
      const o = await post<{ quorum_id: number }>('/console/unlock', { hours: Number(form.hours), reason: form.reason.trim() });
      const id = Number(o.quorum ? o.quorumId : o.data.quorum_id);
      notify(o.quorum ? 'pending' : 'ok', o.quorum ? t.console.requested(id) : t.console.readyDirect(id));
      form = { hours: 1, reason: '' };
      load();
    } catch (err) {
      notify('error', errText(err));
    }
    busy = false;
  }

  // The code: kept only while the dialog is open.
  let code: ConsoleCode | null = $state(null);
  let codeOpen = $state(false);
  $effect(() => {
    if (!codeOpen) code = null;
  });
  async function show(u: ConsoleUnlock) {
    if (!(await askConfirm(t.console.showConfirm))) return;
    try {
      const o = await post<ConsoleCode>(`/console/unlock/${u.id}/code`);
      code = o.data as ConsoleCode;
      codeOpen = true;
    } catch (err) {
      notify('error', errText(err));
    }
    load();
  }

  async function revoke(u: ConsoleUnlock) {
    if (!(await askConfirm(t.console.revokeConfirm(u.id)))) return;
    if (await act(del(`/console/unlock/${u.id}`), t.console.revoked)) load();
  }
</script>

<div class="settings-section">
  <p class="intro muted">{t.console.intro}</p>
  <ErrorBanner {error} />

  {#if admin}
    <section class="card" aria-labelledby="con-req">
      <div class="card-head">
        <div class="row">
          <IconTerminal aria-hidden="true" />
          <h2 id="con-req">{t.console.request}</h2>
        </div>
      </div>
      <form onsubmit={request}>
        <div class="form-grid">
          <div class="field">
            <label for="con-h">{t.console.hours}</label>
            <select id="con-h" bind:value={form.hours}>
              {#each [1, 2, 3, 4, 5, 6, 7, 8] as h (h)}<option value={h}>{t.console.hoursN(h)}</option>{/each}
            </select>
          </div>
          <div class="field con-reason">
            <label for="con-r">{t.console.reason}</label>
            <input id="con-r" bind:value={form.reason} maxlength="500" required aria-describedby="con-r-hint" />
            <p id="con-r-hint" class="hint">{t.console.reasonHint}</p>
          </div>
        </div>
        <p class="hint">{t.console.quorumHint}</p>
        <div class="form-actions"><button type="submit" class="primary" disabled={busy || !form.reason.trim()}>{t.console.submit}</button></div>
      </form>
    </section>
  {:else}
    <p class="hint">{t.console.readOnly}</p>
  {/if}

  <section class="card" aria-labelledby="con-list">
    <div class="card-head"><h2 id="con-list">{t.console.list}</h2></div>
    {#if !loaded}
      <p class="muted" aria-busy="true">{t.loading}</p>
    {:else if items.length === 0}
      <p class="empty">{t.console.none}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.console.id}</th>
              <th scope="col">{t.console.by}</th>
              <th scope="col">{t.console.hours}</th>
              <th scope="col">{t.console.reason}</th>
              <th scope="col">{t.console.statusCol}</th>
              <th scope="col">{t.console.approvedBy}</th>
              <th scope="col">{t.console.codeUntil}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each items as u (u.id)}
              <tr>
                <td class="num">{u.id}</td>
                <td>{u.requested_by}<div class="muted">{fmtTime(u.created)}</div></td>
                <td>{t.console.hoursN(u.hours)}</td>
                <td class="wrap">{u.reason}</td>
                <td><span class="chip {cls[u.status] ?? ''}">{t.console.status[u.status] ?? u.status}</span></td>
                <td>{u.decided_by ?? '—'}</td>
                <td>{u.status === 'approved' || u.status === 'issued' ? fmtTime(u.code_expires) : '—'}</td>
                <td class="actions">
                  {#if admin && u.status === 'approved' && u.requested_by === session.user?.name}
                    <button type="button" class="small primary" onclick={() => show(u)}>{t.console.show}</button>
                  {/if}
                  {#if u.status === 'approved' || u.status === 'issued'}
                    <button type="button" class="small danger" onclick={() => revoke(u)}>{t.console.revoke}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
  <p class="hint">{t.console.recovery}</p>
</div>

<Modal bind:open={codeOpen} title={t.console.codeTitle(code?.id ?? 0)} wide>
  {#if code}
    <p class="banner warn" role="alert">{t.console.codeOnce}</p>
    <p>{t.console.codeSteps(code.hours)}</p>
    <div class="copyline">
      <code class="secret console-code" aria-label={t.console.code}>{code.code}</code>
      <button type="button" class="small" onclick={() => copyText(code!.code)}><IconCopy aria-hidden="true" />{t.users.copy}</button>
    </div>
    <p class="muted">{t.console.expires}: {fmtTime(code.expires)}</p>
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (codeOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<style>
  .console-code {
    font-size: 1.4rem;
    letter-spacing: 0.08em;
  }
  .con-reason {
    grid-column: span 2;
  }
  td.wrap {
    max-width: 22rem;
    white-space: normal;
  }
</style>
