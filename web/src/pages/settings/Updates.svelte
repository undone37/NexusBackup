<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { session } from '../../lib/session.svelte';
  import { fmtAgo, fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { UpdateImage, UpdatesStatus } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconRefresh from '@lucide/svelte/icons/refresh-cw';
  import IconDownload from '@lucide/svelte/icons/download';

  const admin = $derived(session.user?.role === 'admin');
  let u = $state<UpdatesStatus | null>(null);
  let error: string | null = $state(null);

  async function load() {
    try {
      u = await get<UpdatesStatus>('/updates');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(() => {
    load();
    // follow a running check
    const iv = setInterval(() => u?.status === 'checking' && load(), 2000);
    return () => clearInterval(iv);
  });

  // "Sun 03:00 120" -> weekday, start time, minutes
  const win = $derived.by(() => {
    const [day = '', time = '', min = ''] = (u?.window ?? '').split(/\s+/);
    return min ? t.settings.upd.windowText(day, time, min) : (u?.window ?? '—');
  });
  const short = (d?: string) => (d ? d.replace(/^(sha256:)?([0-9a-f]{12})[0-9a-f]+$/, '$1$2…') : '');
  // "idle" with a newer image is shown as "update available"
  const st = $derived(u?.status === 'idle' && u.available ? 'available' : (u?.status ?? ''));
  const stCls: Record<string, string> = { idle: 'ok', available: 'info', checking: 'info', staged: 'warn', error: 'bad' };

  async function check() {
    if (await act(post('/updates/check'), t.settings.upd.checkStarted)) load();
  }
  async function apply() {
    if (!u?.available) return;
    if (!(await askConfirm(t.settings.upd.applyConfirm(u.available.version)))) return;
    if (await act(post('/updates/apply'), t.settings.upd.applied)) load();
  }
</script>

{#snippet image(x: UpdateImage | null)}
  {#if x}
    <strong>{x.version}</strong>
    {#if x.digest}<span class="muted mono" title={x.digest}>{short(x.digest)}</span>{/if}
    {#if x.since}<span class="muted">· {t.settings.upd.since(fmtTime(x.since))}</span>{/if}
  {:else}
    <span class="muted">{t.settings.upd.none}</span>
  {/if}
{/snippet}

<div class="settings-section">
  <p class="intro muted">{t.settings.upd.intro}</p>
  <ErrorBanner {error} />
  {#if !u}
    {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
  {:else}
    {#if u.error}<p class="banner error" role="alert">{u.error}</p>{/if}
    <section class="card" aria-labelledby="upd-h">
      <div class="card-head">
        <h2 id="upd-h">{t.settings.tabs.updates}</h2>
        <span class="chip {stCls[st] ?? ''}" aria-live="polite">{t.settings.upd.statuses[st] ?? st}</span>
      </div>
      <dl class="kv-list">
        <dt>{t.settings.upd.booted}</dt>
        <dd>{@render image(u.booted)}</dd>
        <dt>{t.settings.upd.staged}</dt>
        <dd>{@render image(u.staged)}</dd>
        <dt>{t.settings.upd.available}</dt>
        <dd>
          {#if u.available}{@render image(u.available)}{:else}<span class="muted">{t.settings.upd.upToDate}</span>{/if}
        </dd>
        <dt>{t.settings.upd.rollback}</dt>
        <dd>{@render image(u.rollback)}</dd>
        <dt>{t.settings.upd.channel}</dt>
        <dd>{u.channel}</dd>
        <dt>{t.settings.upd.window}</dt>
        <dd>{win}</dd>
        <dt>{t.settings.upd.lastCheck}</dt>
        <dd title={fmtTime(u.last_check)}>{fmtAgo(u.last_check)}</dd>
      </dl>
      {#if admin}
        <div class="form-actions">
          <button type="button" onclick={check} disabled={u.status === 'checking'}><IconRefresh aria-hidden="true" />{t.settings.upd.check}</button>
          {#if u.available && !u.staged}
            <button type="button" class="primary" onclick={apply}><IconDownload aria-hidden="true" />{t.settings.upd.apply}</button>
          {/if}
        </div>
      {/if}
    </section>
  {/if}
</div>
