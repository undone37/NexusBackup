<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { get, post, act, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { href } from '../lib/router.svelte';
  import { terminal, downloadUrl, kindLabel } from '../lib/jobs';
  import { fmtTime, fmtValue } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Job } from '../lib/types';
  import JobState from '../components/JobState.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

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

  onMount(() => {
    load();
    const iv = setInterval(() => {
      if (live) load();
    }, 2000);
    return () => clearInterval(iv);
  });

  async function cancel() {
    if (await act(post(`/jobs/${encodeURIComponent(id)}/cancel`), t.jobs.cancelled)) load();
  }
</script>

<div class="page-head">
  <h1>{t.jobs.detail(Number(id))}</h1>
  <div class="row">
    {#if live}<span class="live">{t.jobs.live}</span>{/if}
    {#if job?.state === 'queued' && can.cancelJob(session.user)}
      <button type="button" class="danger" onclick={cancel}>{t.jobs.cancel}</button>
    {/if}
    <a class="button" href={href('/jobs')}>{t.jobs.back}</a>
  </div>
</div>

<ErrorBanner {error} />

{#if job}
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
  <section class="card" aria-labelledby="jl">
    <h2 id="jl">{t.jobs.log}</h2>
    <pre class="log" bind:this={logEl} aria-labelledby="jl">{job.log || '…'}</pre>
  </section>
{:else if !error}
  <p class="muted" aria-busy="true">{t.loading}</p>
{/if}
