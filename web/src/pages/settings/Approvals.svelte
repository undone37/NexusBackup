<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { t } from '../../lib/i18n';
  import type { ApprovalsState } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';

  let settings: ApprovalsState | null = $state(null);
  let error: string | null = $state(null);
  const isAdmin = $derived(session.user?.role === 'admin');

  async function load() {
    try {
      settings = await get<ApprovalsState>('/settings/approvals');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  async function toggle() {
    if (!settings) return;
    const enable = !settings.enabled;
    if (!(await askConfirm(enable ? t.quorum.enableConfirm : t.quorum.disableConfirm))) return;
    const ok = await act(put('/settings/approvals', { enabled: enable }), t.quorum.enabledDone);
    if (ok) load();
  }
</script>

<ErrorBanner {error} />
{#if !settings}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  <section class="card settings-section" aria-labelledby="q-settings">
    <div class="card-head">
      <h2 id="q-settings">{t.quorum.settings}</h2>
      <span class="chip {settings.enabled ? 'ok' : 'warn'}">{settings.enabled ? t.quorum.on : t.quorum.off}</span>
    </div>
    <p>{settings.enabled ? t.quorum.enabledText : t.quorum.disabledText}</p>
    <p class="muted">{t.quorum.approvers(settings.possible_approvers)} {t.quorum.toggleHint}</p>
    {#if settings.few_approvers}<p class="banner warn" role="status">{t.access.fewApprovers(settings.possible_approvers)}</p>{/if}
    {#if settings.pending_disable}
      <p class="banner pending">
        <span>{t.quorum.disablePending(settings.pending_disable)} <a href={href('/quorum')}>{t.nav.quorum}</a></span>
      </p>
    {:else if isAdmin}
      <div class="form-actions">
        <button type="button" class={settings.enabled ? 'danger' : 'primary'} onclick={toggle}>
          {settings.enabled ? t.quorum.disable : t.quorum.enable}
        </button>
      </div>
    {/if}
  </section>
{/if}
