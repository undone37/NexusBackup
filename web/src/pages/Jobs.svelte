<script lang="ts">
  import { onMount } from 'svelte';
  import { get, errText, qs } from '../lib/api';
  import { route, navigate, href } from '../lib/router.svelte';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Job } from '../lib/types';
  import JobState from '../components/JobState.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  const KINDS = ['backup', 'restore', 'restore_ct', 'instant_recover', 'files_list', 'files_get', 'offsite', 'retention', 'gc', 'verify'];
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
    }, 4000);
    return () => clearInterval(iv);
  });

  function filter() {
    navigate('/jobs' + qs({ state: stateF, kind }));
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
      {#each KINDS as k (k)}<option value={k}>{k}</option>{/each}
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
            <th scope="col" class="num">⏱</th>
          </tr>
        </thead>
        <tbody>
          {#each jobs as j (j.id)}
            <tr>
              <td><a href={href(`/jobs/${j.id}`)}>#{j.id}</a></td>
              <td>{j.kind}</td>
              <td>{j.tenant}</td>
              <td><JobState state={j.state} /></td>
              <td>{j.requested_by}</td>
              <td class="nowrap" title={fmtTime(j.created)}>{fmtAgo(j.created)}</td>
              <td class="num">{duration(j)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
