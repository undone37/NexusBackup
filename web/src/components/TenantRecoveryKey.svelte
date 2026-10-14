<script lang="ts">
  import { get, post, errText } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { notify } from '../lib/notify.svelte';
  import { session } from '../lib/session.svelte';
  import { copyText } from '../lib/clipboard';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { TenantKeyInfo, TenantKeyShown, TenantKeyRequestStatus } from '../lib/types';
  import Modal from './Modal.svelte';
  import ErrorBanner from './ErrorBanner.svelte';
  import IconCopy from '@lucide/svelte/icons/copy';
  import IconKey from '@lucide/svelte/icons/key-round';

  // Tenant recovery key (Phase 17e): request -> approval -> generated and shown once to the requester.
  let { tenant = $bindable(null) }: { tenant?: string | null } = $props();

  const admin = $derived(session.user?.role === 'admin');
  let open = $state(false);
  let info = $state<TenantKeyInfo | null>(null);
  let error: string | null = $state(null);
  let busy = $state(false);
  // the key: kept only while the dialog shows it
  let shown = $state<TenantKeyShown | null>(null);

  const path = () => `/tenants/${encodeURIComponent(tenant ?? '')}/recovery-key`;

  async function load() {
    try {
      info = (await get<TenantKeyInfo>(path())) ?? null;
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }

  $effect(() => {
    if (tenant) {
      open = true;
      info = null;
      shown = null;
      load();
    }
  });
  $effect(() => {
    if (!open) {
      shown = null;
      tenant = null;
    }
  });

  const cls: Record<TenantKeyRequestStatus, string> = {
    pending: 'warn',
    approved: 'info',
    shown: 'ok',
    rejected: '',
    expired: '',
  };
  const openReq = $derived(info?.requests.some((r) => r.status === 'pending' || r.status === 'approved') ?? false);

  async function request() {
    busy = true;
    try {
      // not act(): with approvals disabled the request is approved at once, nothing "runs shortly"
      const o = await post<{ quorum_id: number }>(path());
      const id = Number(o.quorum ? o.quorumId : o.data.quorum_id);
      notify(o.quorum ? 'pending' : 'ok', o.quorum ? t.tkey.requested(id) : t.tkey.readyDirect(id));
    } catch (e) {
      notify('error', errText(e));
    }
    busy = false;
    load();
  }

  async function show(id: number) {
    if (!(await askConfirm(t.tkey.showConfirm))) return;
    try {
      const o = await post<TenantKeyShown>(`${path()}/${id}/show`);
      shown = o.data as TenantKeyShown;
    } catch (e) {
      notify('error', errText(e));
    }
    load();
  }
</script>

<Modal bind:open title={shown ? t.tkey.shownTitle(shown.tenant) : t.tkey.title(tenant ?? '')} wide>
  {#if shown}
    <p class="banner warn" role="alert">{t.tkey.once}</p>
    <div class="copyline">
      <code class="secret tkey-code" aria-label={t.tkey.button}>{shown.key}</code>
      <button type="button" class="small" onclick={() => copyText(shown!.key)}><IconCopy aria-hidden="true" />{t.users.copy}</button>
    </div>
    <p class="muted">{t.tkey.kid}: <span class="mono">{shown.kid}</span>{#if shown.replaced} · {t.tkey.replaced(shown.replaced)}{/if}</p>
    <p class="hint">{t.tkey.steps}</p>
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (open = false)}>{t.close}</button>
    </div>
  {:else}
    <p class="muted">{t.tkey.intro}</p>
    <ErrorBanner {error} />
    {#if !info}
      <p class="muted" aria-busy="true">{t.loading}</p>
    {:else}
      <div class="row tkey-state">
        <IconKey aria-hidden="true" />
        {#if info.key}
          <span class="chip ok">{t.tkey.kid} <span class="mono">{info.key.kid}</span></span>
          {#if info.key.post_quantum}
            <span class="chip accent" title={t.p30.pq.hint}>{t.p30.pq.chip}</span>
          {:else}
            <span class="chip" title={t.p30.pq.legacyHint}>{t.p30.pq.legacy}</span>
          {/if}
          <span>{t.tkey.set(fmtTime(info.key.set_at), info.key.requested_by, info.key.approved_by)}</span>
        {:else}
          <span>{t.tkey.none}</span>
        {/if}
      </div>
      {#if admin}
        <p class="hint">{t.tkey.quorumHint}{#if info.key} {t.tkey.replaceHint}{/if}</p>
        <div class="form-actions">
          <button type="button" class="primary" disabled={busy || openReq} onclick={request}>
            {info.key ? t.tkey.replace : t.tkey.generate}
          </button>
        </div>
      {:else}
        <p class="hint">{t.tkey.readOnly}</p>
      {/if}
      {#if info.requests.length}
        <h3>{t.tkey.requests}</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.tkey.id}</th>
                <th scope="col">{t.tkey.by}</th>
                <th scope="col">{t.tkey.statusCol}</th>
                <th scope="col">{t.tkey.approvedBy}</th>
                <th scope="col">{t.tkey.showUntil}</th>
                <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
              </tr>
            </thead>
            <tbody>
              {#each info.requests as r (r.id)}
                <tr>
                  <td class="num">{r.id}</td>
                  <td>{r.requested_by}<div class="muted">{fmtTime(r.created)}</div></td>
                  <td><span class="chip {cls[r.status] ?? ''}">{t.tkey.status[r.status] ?? r.status}</span></td>
                  <td>{r.decided_by ?? '—'}</td>
                  <td>{r.status === 'approved' && r.show_until ? fmtTime(r.show_until) : '—'}</td>
                  <td class="actions">
                    {#if admin && r.status === 'approved' && r.requested_by === session.user?.name}
                      <button type="button" class="small primary" onclick={() => show(r.id)}>{t.tkey.show}</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {/if}
  {/if}
</Modal>

<style>
  .tkey-code {
    font-size: 0.95rem;
    overflow-wrap: break-word;
  }
  .tkey-state {
    gap: 0.5rem;
    flex-wrap: wrap;
    margin: 0.75rem 0;
  }
</style>
