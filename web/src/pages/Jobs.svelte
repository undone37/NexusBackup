<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText, qs } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { route, navigate, href } from '../lib/router.svelte';
  import { fmtAgo, fmtRate, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { JOB_KINDS, kindLabel } from '../lib/jobs';
  import type { Job } from '../lib/types';
  import JobState from '../components/JobState.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import ProgressBar from '../components/ProgressBar.svelte';

  const STATES = ['queued', 'running', 'ok', 'failed', 'cancelled'];

  let jobs: Job[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let stateF = $state(route.query.get('state') ?? '');
  let kind = $state(route.query.get('kind') ?? '');

  async function load() {
    try {
      jobs = await get<Job[]>('/jobs' + qs({ state: route.query.get('state'), kind: route.query.get('kind') }));
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }

  onMount(() => {
    load();
    // Refresh while anything is active.
    const iv = setInterval(() => {
      if (jobs.some((j) => j.state === 'queued' || j.state === 'running')) load();
    }, 2000);
    return () => clearInterval(iv);
  });

  function filter() {
    navigate('/jobs' + qs({ state: stateF, kind }));
  }

  // queued: cancelled at once; running: the scheduler stops it (Phase 13b)
  async function cancel(j: Job) {
    if (j.state === 'running' && !(await askConfirm(t.runctl.cancelConfirm(j.id)))) return;
    if (await act(post(`/jobs/${j.id}/cancel`), j.state === 'running' ? t.runctl.cancelling : t.jobs.cancelled)) load();
  }

  function duration(j: Job) {
    if (!j.started) return '—';
    const s = (j.finished ?? Date.now() / 1000) - j.started;
    return s < 120 ? `${Math.round(s)} s` : `${Math.round(s / 60)} min`;
  }
</script>

<div class="page-head">
  <h1>{t.jobs.title}</h1>
  <button type="button" onclick={load}>{t.refresh}</button>
  <p class="lede">{t.jobs.lede}</p>
</div>

<div class="filters" role="search">
  <div class="field">
    <label for="j-state">{t.state}</label>
    <select id="j-state" bind:value={stateF} onchange={filter}>
      <option value="">{t.jobs.anyState}</option>
      {#each STATES as s (s)}<option value={s}>{t.jobs.states[s]}</option>{/each}
    </select>
  </div>
  <div class="field">
    <label for="j-kind">{t.kind}</label>
    <select id="j-kind" bind:value={kind} onchange={filter}>
      <option value="">{t.jobs.anyKind}</option>
      {#each JOB_KINDS as k (k)}<option value={k}>{kindLabel(k)}</option>{/each}
    </select>
  </div>
</div>

<ErrorBanner {error} />

<div class="card">
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if jobs.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.jobs.id}</th>
            <th scope="col">{t.kind}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.state}</th>
            <th scope="col">{t.jobs.requestedBy}</th>
            <th scope="col">{t.jobs.created}</th>
            <th scope="col">{t.jobs.progressCol}</th>
            <th scope="col" class="num">{t.jobs.duration}</th>
            {#if can.cancelJob(session.user)}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each jobs as j (j.id)}
            <tr>
              <td><a href={href(`/jobs/${j.id}`)}>#{j.id}</a></td>
              <td>{kindLabel(j.kind)}</td>
              <td>{j.tenant}</td>
              <td
                ><JobState state={j.state} />{#if j.result?.warnings}
                  <span class="chip warn" title={t.jobs.warningsTitle}>{t.jobs.warnings(j.result.warnings)}</span>{/if}{#if (j.attempt ?? 1) > 1}
                  <span class="muted">{t.runctl.attempt} {j.attempt}</span>{/if}</td
              >
              <td>{j.requested_by}</td>
              <td class="nowrap" title={fmtTime(j.created)}>{fmtAgo(j.created)}</td>
              <td class="prog">
                {#if j.state === 'running' && j.progress}
                  {@const p = j.progress}
                  <div class="pcell">
                    <ProgressBar size="s" value={p.percent ?? p.item_percent} label={t.jobs.progress} />
                    <span class="tabular small nowrap"
                      >{(p.percent ?? p.item_percent) !== null && (p.percent ?? p.item_percent) !== undefined
                        ? `${Math.round((p.percent ?? p.item_percent)!)} %`
                        : ''}{p.rate ? ` · ${fmtRate(p.rate)}` : ''}</span
                    >
                  </div>
                  {#if p.item}<div class="muted small mono nowrap">{p.item}{p.items && p.item_index ? ` (${p.item_index}/${p.items})` : ''}</div>{/if}
                {/if}
              </td>
              <td class="num">{duration(j)}</td>
              {#if can.cancelJob(session.user)}
                <td class="actions">
                  {#if (j.state === 'queued' || j.state === 'running') && !j.cancel_by}
                    <button type="button" class="small danger" onclick={() => cancel(j)}>{t.runctl.cancelRunning}</button>
                  {:else if j.cancel_by && j.state === 'running'}
                    <span class="muted">{t.runctl.cancelRequested(j.cancel_by)}</span>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .small {
    font-size: 0.8rem;
  }
  td.prog {
    min-width: 11rem;
  }
  .pcell {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
</style>
