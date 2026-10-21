<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { fmtAgo, fmtBytes, fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { ConfigBackupStatus, ConfigBackupRun } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconPlay from '@lucide/svelte/icons/play';
  import IconDownload from '@lucide/svelte/icons/download';

  // status: administrators and security officers; Run now and the download: administrators
  // (the download also needs the download permission; the server decides)
  const admin = $derived(session.user?.role === 'admin');
  let st: ConfigBackupStatus | null = $state(null);
  let error: string | null = $state(null);

  async function load() {
    try {
      st = await get<ConfigBackupStatus>('/settings/config-backup');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  const busy = $derived.by(() => {
    const s = st as ConfigBackupStatus | null;
    return !!s && (s.running || s.runs.some((r) => r.state === 'queued' || r.state === 'running'));
  });
  onMount(() => {
    load();
    const iv = setInterval(() => busy && load(), 2000);
    return () => clearInterval(iv);
  });

  async function runNow() {
    if (await act(post('/settings/config-backup/run'), t.settings.cfgb.started)) load();
  }
  const cls: Record<string, string> = { queued: 'info', running: 'info', ok: 'ok', failed: 'bad', cancelled: 'plain' };
  const chip = (r: ConfigBackupRun | null) => r && { c: cls[r.state] ?? '', l: t.jobs.states[r.state] ?? r.state };
</script>

<div class="settings-section">
  <p class="intro muted">{t.settings.cfgb.intro}</p>
  <ErrorBanner {error} />
  {#if !st}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else}
    <section class="card" aria-labelledby="cfgb-status-h">
      <div class="card-head">
        <h2 id="cfgb-status-h">{t.settings.cfgb.status}</h2>
        {#if admin}
          <div class="row">
            <button type="button" onclick={runNow} disabled={busy}
              ><IconPlay aria-hidden="true" />{busy ? t.settings.cfgb.running : t.settings.cfgb.run}</button
            >
            {#if st.latest}
              <a class="button" href="/api/v1/settings/config-backup/download" download
                ><IconDownload aria-hidden="true" />{t.settings.cfgb.download}</a
              >
            {/if}
          </div>
        {/if}
      </div>
      <dl class="kv">
        <dt>{t.settings.cfgb.lastSuccess}</dt>
        <dd>
          {#if st.last_success}<span title={fmtTime(st.last_success)}>{fmtAgo(st.last_success)}</span>{:else}<span
              class="chip warn">{t.settings.cfgb.never}</span
            >{/if}
        </dd>
        <dt>{t.settings.cfgb.latest}</dt>
        <dd>
          {st.latest
            ? t.settings.cfgb.latestInfo(fmtBytes(st.latest.bytes), st.latest.files ?? 0, fmtAgo(st.latest.created))
            : '—'}
        </dd>
        <dt>{t.settings.cfgb.applianceId}</dt>
        <dd>
          <span class="mono">{st.appliance_id ?? '—'}</span>
          <span class="muted small">{t.settings.cfgb.applianceIdHint}</span>
        </dd>
      </dl>
      {#if admin && st.latest}<p class="muted small">{t.settings.cfgb.downloadHint}</p>{/if}
    </section>

    <section class="card" aria-labelledby="cfgb-targets-h">
      <div class="card-head"><h2 id="cfgb-targets-h">{t.settings.cfgb.targets}</h2></div>
      {#if st.targets.length === 0}
        <p class="banner warn" role="status">{t.settings.cfgb.noTargets}</p>
      {:else}
        <p class="muted small">{t.settings.cfgb.retention}</p>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.settings.cfgb.target}</th>
                <th scope="col">{t.settings.cfgb.lastUpload}</th>
                <th scope="col">{t.settings.cfgb.lastOk}</th>
              </tr>
            </thead>
            <tbody>
              {#each st.targets as x (`${x.tenant}-${x.target}`)}
                {@const c = chip(x.last)}
                <tr>
                  <td
                    >{x.tenant}{#if x.target === 2}<span class="muted"> · {t.settings.cfgb.second}</span>{/if}</td
                  >
                  <td
                    >{#if c && x.last}<span class="chip {c.c}">{c.l}</span>
                      <a href={href(`/jobs/${x.last.id}`)}>{fmtTime(x.last.finished ?? x.last.created)}</a
                      >{:else}—{/if}</td
                  >
                  <td>{x.last_ok ? fmtTime(x.last_ok) : '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section class="card" aria-labelledby="cfgb-runs-h">
      <div class="card-head"><h2 id="cfgb-runs-h">{t.settings.cfgb.runs}</h2></div>
      {#if st.runs.length === 0}
        <p class="empty">{t.settings.cfgb.never}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.state}</th>
                <th scope="col">{t.settings.cfgb.kind}</th>
                <th scope="col">{t.jobs.created}</th>
                <th scope="col">{t.settings.cfgb.by}</th>
              </tr>
            </thead>
            <tbody>
              {#each st.runs as r (r.id)}
                {@const c = chip(r)}
                <tr>
                  <td><span class="chip {c?.c}">{c?.l}</span></td>
                  <td
                    ><a href={href(`/jobs/${r.id}`)}>{t.jobs.kinds[r.kind] ?? r.kind}</a
                    >{#if r.target}{` · ${r.target}`}{/if}</td
                  >
                  <td class="nowrap">{fmtTime(r.created)}</td>
                  <td>{r.requested_by}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {/if}
</div>
