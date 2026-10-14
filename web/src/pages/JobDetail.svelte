<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { askConfirm } from '../lib/confirm.svelte';
  import { API, get, post, act, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { href } from '../lib/router.svelte';
  import { terminal, downloadUrl, kindLabel, logLines, clock } from '../lib/jobs';
  import { fmtBytes, fmtDuration, fmtRate, fmtTime, fmtValue } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Job } from '../lib/types';
  import JobState from '../components/JobState.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import ProgressBar from '../components/ProgressBar.svelte';

  let { id }: { id: string } = $props();

  let job = $state<Job | null>(null);
  let error: string | null = $state(null);
  let logEl: HTMLPreElement | undefined = $state();

  async function load() {
    try {
      // Keep following the log only if the user has not scrolled up.
      const follow = !logEl || logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 8;
      job = await get<Job>(`/jobs/${encodeURIComponent(id)}`);
      error = null;
      if (follow) {
        await tick();
        if (logEl) logEl.scrollTop = logEl.scrollHeight;
      }
    } catch (e) {
      error = errText(e);
    }
  }

  const live = $derived(!!job && !terminal(job.state));
  // logs written before the time marks (and plain logs) show without a time column
  const logView = $derived(logLines(job?.log));
  const logTimed = $derived(logView.some((l) => l.time !== null));
  const prog = $derived(job?.state === 'running' ? (job.progress ?? null) : null);
  // the connector reports about every 2 s while data flows; a long gap means it waits (vzdump start, a slow source)
  const quiet = $derived(prog?.updated ? Math.max(0, Date.now() / 1000 - prog.updated) : 0);
  const pctText = (p: number | null | undefined) => (p === null || p === undefined ? '' : `${p.toFixed(p >= 10 ? 0 : 1)} %`);

  onMount(() => {
    load();
    const iv = setInterval(() => {
      if (live) load();
    }, 2000);
    return () => clearInterval(iv);
  });

  async function cancel() {
    const running = job?.state === 'running';
    if (running && !(await askConfirm(t.runctl.cancelConfirm(Number(id))))) return;
    if (await act(post(`/jobs/${encodeURIComponent(id)}/cancel`), running ? t.runctl.cancelling : t.jobs.cancelled)) load();
  }
  // Phase 29: the scan back's scanned snapshots and recommended restore point
  import ScanBackResult from '../components/ScanBackResult.svelte';
  import type { ScanBackResult as ScanBackResultData } from '../lib/types';
</script>

<div class="page-head">
  <h1>{t.jobs.detail(Number(id))}</h1>
  <div class="row">
    {#if live}<span class="live">{t.jobs.live}</span>{/if}
    {#if job?.cancel_by && job.state === 'running'}<span class="muted">{t.runctl.cancelRequested(job.cancel_by)}</span>{/if}
    {#if (job?.state === 'queued' || (job?.state === 'running' && !job.cancel_by)) && can.cancelJob(session.user)}
      <button type="button" class="danger" onclick={cancel}>{t.jobs.cancel}</button>
    {/if}
    <a class="button" href={href('/jobs')}>{t.jobs.back}</a>
  </div>
</div>

<ErrorBanner {error} />

{#if job}
  {@const torn = (job.result?.snapshots ?? []).filter((x) => x.consistent === false).map((x) => x.source)}
  {#if torn.length}<p class="banner warn">{t.jobs.notConsistent(torn.join(', '))}</p>{/if}
  {@const skipped = (job.result?.snapshots ?? []).filter((x) => (x.warnings ?? 0) > 0)}
  {#if job.result?.warnings}<p class="banner warn">
      {t.jobs.skipped(job.result.warnings, skipped.map((x) => x.source).join(', '))}
    </p>{/if}
  <div class="two-col">
    <section class="card">
      <dl class="kv">
        <dt>{t.kind}</dt>
        <dd>{kindLabel(job.kind)} <span class="muted mono">{job.kind}</span></dd>
        <dt>{t.state}</dt>
        <dd><JobState state={job.state} /></dd>
        <dt>{t.tenant}</dt>
        <dd>{job.tenant}</dd>
        <dt>{t.jobs.requestedBy}</dt>
        <dd>{job.requested_by}</dd>
        <dt>{t.jobs.created}</dt>
        <dd>{fmtTime(job.created)}</dd>
        <dt>{t.jobs.started}</dt>
        <dd>{fmtTime(job.started)}</dd>
        <dt>{t.jobs.finished}</dt>
        <dd>{fmtTime(job.finished)}</dd>
        {#if (job.attempt ?? 1) > 1 || job.retry_of}
          <dt>{t.runctl.attempt}</dt>
          <dd>
            {job.attempt}{#if job.retry_of}
              · <a href={href(`/jobs/${job.retry_of}`)}>{t.runctl.retryOf(job.retry_of)}</a>{/if}
          </dd>
        {/if}
        {#if job.not_before && job.state === 'queued'}
          <dt>{t.runctl.notBefore}</dt>
          <dd>{fmtTime(job.not_before)}</dd>
        {/if}
      </dl>
    </section>
    <section class="card" aria-labelledby="jp">
      <h2 id="jp">{t.jobs.params}</h2>
      <dl class="kv">
        {#each Object.entries(job.params ?? {}).filter(([k]) => k !== 'download_token') as [k, v] (k)}
          <dt>{k}</dt>
          <dd class="mono">{k === 'time' && typeof v === 'number' ? `${v} (${fmtTime(v)})` : fmtValue(v)}</dd>
        {:else}
          <dd class="muted">—</dd>
        {/each}
      </dl>
      {#if job.kind === 'files_get' && job.state === 'ok' && typeof job.params.download_token === 'string' && job.requested_by === session.user?.name}
        <p>
          <a class="button primary" href={downloadUrl(job.params.download_token)}>{t.files.get}</a>
        </p>
      {/if}
    </section>
  </div>
  {#if job.state === 'running'}
    <section class="card progress" aria-labelledby="jpr">
      <h2 id="jpr">{t.jobs.progress}</h2>
      {#if !prog}
        <p class="muted">{t.jobs.noProgress}</p>
      {:else}
        {#if prog.items}
          <div class="pline">
            <div class="phead">
              <span>{t.jobs.overall}</span>
              <span class="tabular">{pctText(prog.percent)}<span class="muted">{` · ${t.jobs.itemsDone(prog.items_done ?? 0, prog.items)}`}</span></span>
            </div>
            <ProgressBar value={prog.percent} label={t.jobs.overall} />
          </div>
        {/if}
        {#if prog.item || prog.part}
          <div class="pline">
            <div class="phead">
              <span>
                {#if prog.item}<span class="mono">{prog.item}</span>{#if prog.label}<span class="muted">{` ${prog.label}`}</span>{/if}{/if}
                {#if prog.part}<span class="muted">{`${prog.item ? ' · ' : ''}${t.jobs.part} `}</span><span class="mono">{prog.part}</span
                  >{#if prog.parts && prog.parts > 1}<span class="muted">{` (${t.jobs.itemOf(prog.part_index ?? 1, prog.parts)})`}</span>{/if}{/if}
              </span>
              <span class="tabular">{pctText(prog.item_percent)}</span>
            </div>
            <ProgressBar value={prog.item_percent} label={t.jobs.current} />
          </div>
        {/if}
        <dl class="kv pstats">
          {#if prog.item_index && prog.items}
            <dt>{t.jobs.item}</dt>
            <dd class="tabular">{t.jobs.itemOf(prog.item_index, prog.items)}</dd>
          {/if}
          {#if prog.total !== null && prog.total !== undefined}
            <dt>{t.jobs.part}</dt>
            <dd class="tabular">{t.jobs.bytesOf(fmtBytes(prog.done ?? 0), fmtBytes(prog.total))}</dd>
          {:else if prog.entries}
            <dt>{t.jobs.part}</dt>
            <dd class="tabular">
              {prog.entries_total ? t.jobs.entriesOf(prog.entries, prog.entries_total) : t.jobs.entries(prog.entries)}
            </dd>
          {/if}
          <dt>{t.jobs.transferred}</dt>
          <dd class="tabular">{fmtBytes(prog.bytes ?? 0)}</dd>
          <dt>{t.jobs.rate}</dt>
          <dd class="tabular">{fmtRate(prog.rate)}</dd>
          <dt>{t.jobs.eta}</dt>
          <dd class="tabular">{prog.eta === null || prog.eta === undefined ? '—' : t.jobs.etaAbout(fmtDuration(prog.eta))}</dd>
          <dt>{t.jobs.elapsed}</dt>
          <dd class="tabular">{fmtDuration(prog.elapsed)}</dd>
        </dl>
        {#if quiet > 30}<p class="muted small">{t.jobs.stale(fmtDuration(quiet))}</p>{/if}
        {#if prog.active && prog.active.length > 1}
          <h3>{t.jobs.inFlight}</h3>
          <div class="table-wrap">
            <table>
              <tbody>
                {#each prog.active as a, i (a.item ?? i)}
                  <tr>
                    <td class="mono nowrap">{a.item}{#if a.label}<span class="muted">{` ${a.label}`}</span>{/if}</td>
                    <td class="mono">{a.part ?? ''}</td>
                    <td class="wide"><ProgressBar size="s" value={a.percent} label={a.item ?? ''} /></td>
                    <td class="num">{pctText(a.percent)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {/if}
    </section>
  {/if}
  {@const res = job.result}
  {#if res && job.kind === 'scan_back' && Array.isArray((res as unknown as ScanBackResultData).scanned)}
    <section class="card" aria-labelledby="jr-sb">
      <h2 id="jr-sb">{t.jobs.result}</h2>
      <ScanBackResult result={res as unknown as ScanBackResultData} tenant={job.tenant} />
    </section>
  {/if}
  {#if res && job.kind.startsWith('plugin_') && job.kind !== 'plugin_backup'}
    <section class="card" aria-labelledby="jr">
      <h2 id="jr">{t.jobs.result}</h2>
      {#if job.kind === 'plugin_validate'}
        {#if res.valid}
          <p class="banner ok">{t.jobs.valid}</p>
        {:else}
          <p class="banner error">
            {t.jobs.invalid}{res.field ? ` (${res.field})` : ''}{res.message ? `: ${res.message}` : ''}
          </p>
        {/if}
      {:else if job.kind === 'plugin_guests' || job.kind === 'inventory'}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.jobs.guestId}</th>
                <th scope="col">{t.jobs.guestTitle}</th>
                <th scope="col">{t.inventory.tags}</th>
                <th scope="col" class="num">{t.jobs.size}</th>
              </tr>
            </thead>
            <tbody>
              {#each res.guests ?? [] as g (g.id)}
                <tr>
                  <td class="mono">{g.id}</td>
                  <td>{g.title}</td>
                  <td class="mono">{(g.tags ?? []).join(' ')}</td>
                  <td class="num">{fmtBytes(g.size)}</td>
                </tr>
              {:else}
                <tr><td colspan="4" class="empty">{t.none}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <dl class="kv">
          {#if res.restore}
            <dt>{t.jobs.restore}</dt>
            <dd class="mono">{res.restore}</dd>
          {/if}
          {#if res.info !== undefined && res.info !== null}
            <dt>{t.jobs.mountInfo}</dt>
            <dd>
              {#if typeof res.info === 'string'}<code class="secret">{res.info}</code>
              {:else}<pre class="log">{JSON.stringify(res.info, null, 2)}</pre>{/if}
            </dd>
          {/if}
          {#if res.summary}
            <dt>{t.jobs.summary}</dt>
            <dd>{res.summary}</dd>
          {/if}
        </dl>
      {/if}
    </section>
  {/if}
  <section class="card" aria-labelledby="jl">
    <h2 id="jl">{t.jobs.log}</h2>
    {#if job.kind === 'backup' && /^(\d{4}-\d\d-\d\dT\S+ )?error /m.test(job.log ?? '')}
      <!-- Phase 22b: entries a share backup could not read -->
      <p>
        <a class="button small" href={`${API}/jobs/${job.id}/skipped.csv`} download={`nexus-job-${job.id}-skipped.csv`} title={t.nas.skippedHint}
          >{t.nas.skippedCsv}</a
        >
      </p>
    {/if}
    <pre class="log" bind:this={logEl} aria-labelledby="jl">{#if job.log}{#each logView as l, i (i)}{#if logTimed}<span class="log-time">{l.time === null ? '        ' : clock(l.time)}</span> {/if}{l.text}
{/each}{:else}…{/if}</pre>
  </section>
{:else if !error}
  <p class="muted" aria-busy="true">{t.loading}</p>
{/if}

<style>
  .small {
    font-size: 0.8rem;
  }
  .progress .pline {
    display: grid;
    gap: 0.35rem;
    margin: 0 0 1rem;
    max-width: 48rem;
  }
  .progress .phead {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: baseline;
  }
  .progress .pstats {
    grid-template-columns: max-content 1fr max-content 1fr;
    max-width: 48rem;
  }
  .progress h3 {
    font-size: 0.95rem;
    margin: 1rem 0 0.5rem;
  }
  .progress td.wide {
    width: 50%;
  }
  @media (max-width: 720px) {
    .progress .pstats {
      grid-template-columns: max-content 1fr;
    }
  }
</style>
