<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { fmtAgo, fmtBytes, fmtTime } from '../../lib/format';
  import { manualUrl } from '../../lib/manual';
  import { t } from '../../lib/i18n';
  import type { DiagRun } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconPlay from '@lucide/svelte/icons/play';
  import IconPackage from '@lucide/svelte/icons/package';
  import IconDownload from '@lucide/svelte/icons/download';
  import IconHelp from '@lucide/svelte/icons/circle-question-mark';

  // checks: administrators and security officers; support bundles: administrators only
  const admin = $derived(session.user?.role === 'admin');
  let runs: DiagRun[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      runs = (await get<{ items: DiagRun[] }>('/diagnostics')).items;
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  const busy = (r: DiagRun) => r.state === 'queued' || r.state === 'running';
  onMount(() => {
    load();
    // follow queued and running requests
    const iv = setInterval(() => runs.some(busy) && load(), 2000);
    return () => clearInterval(iv);
  });

  // the newest run that has checks (a bundle carries them as well), or the one in progress
  const latest = $derived(runs.find((r) => r.checks || busy(r)) ?? null);
  // Phase 21b: the security posture rows (posture.*) get their own card
  const isPosture = (c: { id: string }) => c.id.startsWith('posture.');
  const checks = $derived((latest?.checks ?? []).filter((c) => !isPosture(c)));
  const posture = $derived((latest?.checks ?? []).filter(isPosture));
  const postureTitle = (title: string) => {
    const x = title.replace(/^Security posture: /, '');
    return x.charAt(0).toUpperCase() + x.slice(1);
  };
  const count = (s: string) => checks.filter((c) => c.status === s).length;
  const blocks = $derived(checks.some((c) => c.status === 'fail' && c.severity >= 3));
  const bundles = $derived(runs.filter((r) => r.kind === 'bundle'));
  const stCls: Record<string, string> = { pass: 'ok', warn: 'warn', fail: 'bad', skip: 'plain' };
  const runCls: Record<string, string> = { queued: 'info', running: 'info', done: 'ok', error: 'bad' };

  async function runChecks() {
    if (await act(post('/diagnostics/checks'), t.settings.diag.started)) load();
  }

  // datetime-local values in the browser's time zone; default: the last 24 h
  const local = (ts: number) => {
    const d = new Date(ts * 1000);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  };
  const nowTs = Math.floor(Date.now() / 1000);
  let from = $state(local(nowTs - 86400));
  let to = $state(local(nowTs));
  const range = $derived.by(() => {
    const s = Math.floor(new Date(from).getTime() / 1000);
    const u = Math.floor(new Date(to).getTime() / 1000);
    return Number.isFinite(s) && Number.isFinite(u) && s < u && u - s <= 31 * 86400 ? { since: s, until: u } : null;
  });
  async function createBundle() {
    if (!range) return;
    if (await act(post('/diagnostics/bundle', range), t.settings.diag.created)) load();
  }
</script>

<div class="settings-section">
  <p class="intro muted">{t.settings.diag.intro}</p>
  <ErrorBanner {error} />
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else}
    <section class="card" aria-labelledby="diag-checks-h">
      <div class="card-head">
        <h2 id="diag-checks-h">{t.settings.diag.checks}</h2>
        <button type="button" onclick={runChecks} disabled={runs.some(busy)}
          ><IconPlay aria-hidden="true" />{runs.some(busy) ? t.settings.diag.running : t.settings.diag.run}</button
        >
      </div>
      {#if !latest}
        <p class="empty">{t.settings.diag.never}</p>
      {:else if !latest.checks}
        <p class="muted" aria-busy="true" aria-live="polite">{t.settings.diag.states[latest.state]}…</p>
      {:else}
        <p class="muted small" aria-live="polite">
          <span title={fmtTime(latest.finished)}>{t.settings.diag.lastRun(fmtAgo(latest.finished ?? latest.created), latest.by)}</span>
          · {t.settings.diag.summary(count('pass'), count('warn'), count('fail'))}
        </p>
        {#if blocks}<p class="banner warn" role="status">{t.settings.diag.blocksUpdates}</p>{/if}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.settings.diag.result}</th>
                <th scope="col">{t.settings.diag.check}</th>
                <th scope="col">{t.settings.diag.detail}</th>
                <th scope="col">{t.settings.diag.severity}</th>
                <th scope="col"><span class="visually-hidden">{t.settings.diag.help}</span></th>
              </tr>
            </thead>
            <tbody>
              {#each checks as c (c.id)}
                <tr>
                  <td><span class="chip {stCls[c.status] ?? ''}">{t.settings.diag.statuses[c.status] ?? c.status}</span></td>
                  <td>{c.title}<div class="muted small mono">{c.id}</div></td>
                  <td class="detail">{c.detail}</td>
                  <td class="nowrap">{c.status === 'warn' || c.status === 'fail' ? t.settings.diag.severities[c.severity] : '—'}</td>
                  <td class="actions">
                    <a class="button small" href={manualUrl(c.manual)} target="_blank" rel="noopener noreferrer" aria-label={t.settings.diag.helpLabel(c.title)}
                      ><IconHelp aria-hidden="true" />{t.settings.diag.help}</a
                    >
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section class="card" aria-labelledby="diag-posture-h">
      <div class="card-head">
        <h2 id="diag-posture-h">{t.settings.diag.posture}</h2>
        {#if posture.length}
          <span class="chip {posture.some((c) => c.status === 'warn') ? 'warn' : 'ok'}"
            >{t.settings.diag.postureSummary(posture.filter((c) => c.status === 'pass').length, posture.filter((c) => c.status === 'warn').length)}</span
          >
        {/if}
      </div>
      <p class="muted">{t.settings.diag.postureIntro}</p>
      {#if !posture.length}
        <p class="empty">{t.settings.diag.postureNone}</p>
      {:else}
        <ul class="posture">
          {#each posture as c (c.id)}
            <li>
              <span class="chip {stCls[c.status] ?? ''}">{t.settings.diag.statuses[c.status] ?? c.status}</span>
              <span><strong>{postureTitle(c.title)}</strong> <span class="muted small">— {c.detail}</span></span>
              <a class="button small" href={manualUrl(c.manual)} target="_blank" rel="noopener noreferrer" aria-label={t.settings.diag.helpLabel(c.title)}
                ><IconHelp aria-hidden="true" />{t.settings.diag.help}</a
              >
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    {#if admin}
      <section class="card" aria-labelledby="diag-bundle-h">
        <div class="card-head"><h2 id="diag-bundle-h">{t.settings.diag.bundle}</h2></div>
        <p class="muted">{t.settings.diag.bundleIntro}</p>
        <form
          onsubmit={(e) => {
            e.preventDefault();
            createBundle();
          }}
        >
          <div class="form-grid">
            <div class="field">
              <label for="diag-from">{t.settings.diag.from}</label>
              <input id="diag-from" type="datetime-local" bind:value={from} required />
            </div>
            <div class="field">
              <label for="diag-to">{t.settings.diag.to}</label>
              <input id="diag-to" type="datetime-local" bind:value={to} required />
            </div>
          </div>
          {#if !range}<p class="banner warn" role="alert">{t.settings.diag.rangeInvalid}</p>{/if}
          <div class="form-actions">
            <button type="submit" class="primary" disabled={!range || runs.some(busy)}><IconPackage aria-hidden="true" />{t.settings.diag.create}</button>
          </div>
        </form>
        <h3>{t.settings.diag.bundles}</h3>
        {#if bundles.length === 0}
          <p class="empty">{t.settings.diag.noBundles}</p>
        {:else}
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">{t.state}</th>
                  <th scope="col">{t.settings.diag.range}</th>
                  <th scope="col">{t.settings.diag.size}</th>
                  <th scope="col">{t.settings.diag.expires}</th>
                  <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
                </tr>
              </thead>
              <tbody>
                {#each bundles as b (b.id)}
                  <tr>
                    <td><span class="chip {runCls[b.state] ?? ''}">{t.settings.diag.states[b.state] ?? b.state}</span>{#if b.error}<div class="muted small">{b.error}</div>{/if}</td>
                    <td class="nowrap">{fmtTime(b.since)} – {fmtTime(b.until)}</td>
                    <td class="nowrap">{b.bundle ? fmtBytes(b.bundle.bytes) : '—'}</td>
                    <td class="nowrap">{b.bundle && b.expires ? fmtTime(b.expires) : '—'}</td>
                    <td class="actions">
                      {#if b.bundle}
                        <a class="button small" href={b.bundle.url} download><IconDownload aria-hidden="true" />{t.settings.diag.download}</a>
                      {/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </section>
    {/if}
  {/if}
</div>

<style>
  .detail {
    min-width: 16rem;
  }
  h3 {
    margin-top: 1.25rem;
  }
  .posture {
    list-style: none;
    padding: 0;
    margin: 0;
  }
  .posture li {
    display: grid;
    grid-template-columns: 6rem 1fr auto;
    gap: 0.75rem;
    align-items: center;
    padding: 0.4rem 0;
    border-top: 1px solid var(--border);
  }
  .posture li > .chip {
    justify-self: start;
  }
</style>
