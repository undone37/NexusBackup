<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, postRaw, put, del, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { session } from '../../lib/session.svelte';
  import { fmtAgo, fmtTime, fmtBytes } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import { manualUrl } from '../../lib/manual';
  import type { UpdateImage, UpdatesStatus } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconRefresh from '@lucide/svelte/icons/refresh-cw';
  import IconDownload from '@lucide/svelte/icons/download';
  import IconUpload from '@lucide/svelte/icons/upload';

  const admin = $derived(session.user?.role === 'admin');
  let u = $state<UpdatesStatus | null>(null);
  let error: string | null = $state(null);

  let reg = $state<{ configured: boolean; username: string | null } | null>(null);
  let regUser = $state('');
  let regToken = $state('');

  async function load() {
    try {
      reg = await get('/updates/registry');
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
  const stCls: Record<string, string> = {
    idle: 'ok',
    available: 'info',
    checking: 'info',
    staged: 'warn',
    error: 'bad',
    blocked: 'bad',
    refused: 'bad',
  };

  async function check() {
    if (await act(post('/updates/check'), t.settings.upd.checkStarted)) load();
  }
  async function saveReg(e: SubmitEvent) {
    e.preventDefault();
    if (
      await act(
        put('/updates/registry', { username: regUser.trim(), token: regToken.trim() }),
        t.settings.upd.reg.saved,
      )
    ) {
      regToken = '';
      load();
    }
  }
  async function removeReg() {
    if (!(await askConfirm(t.settings.upd.reg.removeConfirm))) return;
    if (await act(del('/updates/registry'), t.settings.upd.reg.removed)) load();
  }
  // offline update bundle (Phase 36): streamed to the appliance, verified there
  let bundle = $state<File | null>(null);
  let uploading = $state(false);
  async function uploadBundle(e: SubmitEvent) {
    e.preventDefault();
    if (!bundle) return;
    uploading = true;
    try {
      if (
        await act(
          postRaw('/updates/bundle', bundle, { 'content-type': 'application/x-tar' }),
          t.settings.upd.offline.uploaded,
        )
      ) {
        bundle = null;
        load();
      }
    } finally {
      uploading = false;
    }
  }
  const refusedImport = $derived(
    u?.last_result?.request === 'import' && /^(refused|error)/.test(u.last_result.result) ? u.last_result.result : null,
  );

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
    {#if u.status === 'blocked' && u.blocked?.length}
      <div class="banner error" role="alert">
        <p>{t.settings.upd.blocked}</p>
        <ul>
          {#each u.blocked as b (b.id)}
            <li><a href={manualUrl(b.manual)} target="_blank" rel="noopener noreferrer">{b.title}</a>: {b.detail}</li>
          {/each}
        </ul>
      </div>
    {/if}
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
          <button type="button" onclick={check} disabled={u.status === 'checking'}
            ><IconRefresh aria-hidden="true" />{t.settings.upd.check}</button
          >
          {#if u.available}
            <button type="button" class="primary" onclick={apply}
              ><IconDownload aria-hidden="true" />{t.settings.upd.apply}</button
            >
          {/if}
        </div>
      {/if}
    </section>
    {#if admin}
      <section class="card" aria-labelledby="offline-h">
        <div class="card-head"><h2 id="offline-h">{t.settings.upd.offline.title}</h2></div>
        <p class="muted">{t.settings.upd.offline.intro}</p>
        {#if refusedImport}
          <p class="banner error" role="alert">{t.settings.upd.offline.refused} {refusedImport}</p>
        {:else if u.offline}
          <p class="banner ok">
            {t.settings.upd.offline.verified(u.offline.version, u.offline.key, fmtAgo(u.offline.imported))}
            {t.settings.upd.offline.paused}
          </p>
        {/if}
        <form class="form-grid" onsubmit={uploadBundle}>
          <div class="field">
            <label for="bundle-file">{t.settings.upd.offline.file}</label>
            <input
              id="bundle-file"
              type="file"
              accept=".tar,application/x-tar"
              required
              onchange={(e) => (bundle = (e.currentTarget as HTMLInputElement).files?.[0] ?? null)}
            />
          </div>
          <div class="form-actions">
            <button type="submit" class="primary" disabled={!bundle || uploading || u.status === 'checking'}
              ><IconUpload aria-hidden="true" />{uploading
                ? t.settings.upd.offline.uploading(fmtBytes(bundle?.size ?? 0))
                : t.settings.upd.offline.upload}</button
            >
          </div>
        </form>
      </section>
    {/if}
    {#if reg}
      <section class="card" aria-labelledby="reg-h">
        <div class="card-head">
          <h2 id="reg-h">{t.settings.upd.reg.title}</h2>
          <span class="chip {reg.configured ? 'ok' : ''}"
            >{reg.configured ? t.settings.upd.reg.configured(reg.username ?? '') : t.settings.upd.reg.none}</span
          >
        </div>
        <p class="muted">{t.settings.upd.reg.intro}</p>
        {#if admin}
          <form class="form-grid" onsubmit={saveReg}>
            <div class="field">
              <label for="reg-user">{t.settings.upd.reg.user}</label>
              <input id="reg-user" bind:value={regUser} required maxlength="128" autocomplete="off" />
            </div>
            <div class="field">
              <label for="reg-token">{t.settings.upd.reg.token}</label>
              <input
                id="reg-token"
                type="password"
                bind:value={regToken}
                required
                maxlength="512"
                autocomplete="new-password"
              />
            </div>
            <div class="form-actions">
              <button type="submit" class="primary">{t.settings.upd.reg.save}</button>
              {#if reg.configured}<button type="button" onclick={removeReg}>{t.settings.upd.reg.remove}</button>{/if}
            </div>
          </form>
        {/if}
      </section>
    {/if}
  {/if}
</div>
