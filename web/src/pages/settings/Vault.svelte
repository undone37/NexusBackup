<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { VaultState } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import Check from '../../components/Check.svelte';

  // Phase 17c: vault mode (state, preconditions, enable request, the two-step switch-off).
  let v: VaultState | null = $state(null);
  let error: string | null = $state(null);
  const isAdmin = $derived(session.user?.role === 'admin');
  const CHECKS = ['secondary', 'no_local_tenants', 'no_peers', 'approvals', 'web_restricted'] as const;

  async function load() {
    try {
      v = await get<VaultState>('/vault');
      session.vault = v.enabled;
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  async function request(enabled: boolean) {
    if (!(await askConfirm(enabled ? t.vault.enableConfirm : t.vault.disableConfirm))) return;
    if (await act(put('/vault', { enabled }), t.saved)) load();
  }

  function detail(id: (typeof CHECKS)[number]): string {
    const c = v?.checks;
    if (!c) return '';
    if (id === 'no_local_tenants' && c.no_local_tenants.tenants.length)
      return t.vault.localTenants(c.no_local_tenants.tenants);
    if (id === 'no_peers' && c.no_peers.peers) return t.vault.peers(c.no_peers.peers);
    if (id === 'web_restricted' && c.web_restricted.allow.length) return c.web_restricted.allow.join(', ');
    return '';
  }
</script>

<ErrorBanner {error} />
{#if !v}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  <section class="card settings-section" aria-labelledby="v-head">
    <div class="card-head">
      <h2 id="v-head">{t.vault.title}</h2>
      <span class="chip {v.enabled ? 'ok' : 'plain'}">{v.enabled ? t.vault.on : t.vault.off}</span>
    </div>
    <p>{t.vault.intro}</p>
    {#if v.enabled && v.since}<p class="muted">{t.vault.since(v.by ?? '—', fmtTime(v.since))}</p>{/if}

    {#if !v.enabled && v.checks}
      <h3>{t.vault.checks}</h3>
      <ul class="checklist">
        {#each CHECKS as id (id)}
          {@const d = detail(id)}
          <li>
            <Check on={v.checks[id].ok} />
            {t.vault.checkNames[id]}{#if d}&nbsp;<span class="muted">— {d}</span>{/if}
          </li>
        {/each}
      </ul>
      {#if v.pending_enable}
        <p class="banner pending">
          <span>{t.vault.enablePending(v.pending_enable)} <a href={href('/quorum')}>{t.nav.quorum}</a></span>
        </p>
      {:else if isAdmin}
        {#if !v.ready}<p class="muted">{t.vault.notReady}</p>{/if}
        <div class="form-actions">
          <button type="button" class="primary" disabled={!v.ready} onclick={() => request(true)}
            >{t.vault.enable}</button
          >
        </div>
      {/if}
    {/if}

    {#if v.enabled}
      <p class="muted">{t.vault.disableHow}</p>
      {#if v.approved_disable}
        <p class="banner warn" role="status">{t.vault.disableApproved(v.approved_disable)}</p>
      {:else if v.pending_disable}
        <p class="banner pending">
          <span>{t.vault.disablePending(v.pending_disable)} <a href={href('/quorum')}>{t.nav.quorum}</a></span>
        </p>
      {:else if isAdmin}
        <div class="form-actions">
          <button type="button" class="danger" onclick={() => request(false)}>{t.vault.disable}</button>
        </div>
      {/if}
    {/if}
  </section>
{/if}

<style>
  .checklist {
    list-style: none;
    padding: 0;
    display: grid;
    gap: 0.35rem;
  }
</style>
