<script lang="ts">
  // Phase 33: tenant-side approvers of one tenant (GET/PUT /tenants/{name}/approvers):
  // the requirement, the tenant's approvers with the time each may decide from, switch on / request off.
  import { get, put, act, errText } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { TenantApprovers } from '../lib/types';
  import ErrorBanner from './ErrorBanner.svelte';

  let { tenant }: { tenant: string } = $props();
  const id = $props.id();
  let v: TenantApprovers | null = $state(null);
  let error: string | null = $state(null);
  let busy = $state(false);

  async function load() {
    try {
      v = await get<TenantApprovers>(`/tenants/${encodeURIComponent(tenant)}/approvers`);
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  $effect(() => {
    void tenant;
    load();
  });

  async function setEnabled(enabled: boolean) {
    if (!(await askConfirm(enabled ? t.tappr.enableConfirm(tenant) : t.tappr.disableConfirm))) return;
    busy = true;
    const r = await act(
      put(`/tenants/${encodeURIComponent(tenant)}/approvers`, { enabled }),
      enabled ? t.tappr.enabled : t.saved,
    );
    busy = false;
    if (r) load();
  }
</script>

<section class="card" aria-labelledby="{id}-h">
  <div class="card-head">
    <h2 id="{id}-h">{t.tappr.title}</h2>
    {#if v}<span class="chip {v.enabled ? 'ok' : ''}">{v.enabled ? t.tappr.on : t.tappr.off}</span>{/if}
  </div>
  <p class="muted">{t.tappr.intro}</p>
  <ErrorBanner {error} />
  {#if v}
    {#if v.enabled && v.enabled_at}<p>{t.tappr.since(v.enabled_by ?? '?', fmtTime(v.enabled_at))}</p>{/if}
    <h3>{t.tappr.approvers}</h3>
    {#if v.approvers.length === 0}
      <p class="empty">{t.tappr.none}</p>
    {:else}
      <ul class="plain">
        {#each v.approvers as a (a.name)}
          <li>
            <strong>{a.name}</strong>
            {#if a.eligible}
              <span class="chip ok">{t.tappr.eligible}</span>
            {:else}
              <span class="chip warn">{t.tappr.eligibleFrom(fmtTime(a.eligible_from))}</span>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
    {#if v.disable_request}<p class="banner info">{t.tappr.disablePending(v.disable_request)}</p>{/if}
    {#if can.tenantApprovers(session.user)}
      <div class="form-actions">
        {#if !v.enabled}
          <button
            type="button"
            class="primary"
            disabled={busy || v.approvers.length === 0}
            onclick={() => setEnabled(true)}>{t.tappr.enable}</button
          >
        {:else if !v.disable_request}
          <button type="button" disabled={busy} onclick={() => setEnabled(false)}>{t.tappr.disable}</button>
        {/if}
      </div>
    {/if}
  {:else if !error}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {/if}
</section>

<style>
  ul.plain {
    list-style: none;
    padding: 0;
    margin: 0 0 0.75rem;
    display: grid;
    gap: 0.35rem;
  }
</style>
