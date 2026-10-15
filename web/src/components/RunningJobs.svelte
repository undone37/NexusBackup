<script lang="ts">
  // The jobs running right now (and how many wait), refreshed every 3 s: the
  // dashboard's answer to "is anything happening?". A row opens its job.
  import { onMount } from 'svelte';
  import { get } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { rowLink } from '../lib/rowlink';
  import { fmtDuration, fmtEntryRate, fmtRate } from '../lib/format';
  import { kindLabel, jobSubject } from '../lib/jobs';
  import { t } from '../lib/i18n';
  import type { Job } from '../lib/types';
  import ProgressBar from './ProgressBar.svelte';

  let { groups = new Map<number, string>() }: { groups?: Map<number, string> } = $props();

  let running: Job[] = $state([]);
  let queued = $state(0);
  let loaded = $state(false);

  async function load() {
    try {
      const [r, q] = await Promise.all([get<Job[]>('/jobs?state=running'), get<Job[]>('/jobs?state=queued')]);
      running = r;
      queued = q.length;
      loaded = true;
    } catch {
      /* the dashboard shows its own errors */
    }
  }

  onMount(() => {
    load();
    const iv = setInterval(() => {
      if (document.visibilityState === 'visible') load();
    }, 3000);
    return () => clearInterval(iv);
  });

  const pct = (j: Job) => j.progress?.percent ?? j.progress?.item_percent ?? null;
</script>

{#if loaded}
  <section class="card running" aria-labelledby="rn">
    <div class="head">
      <h2 id="rn">{t.dash.runningNow}</h2>
      <span class="muted small">
        {#if queued}<a href={href('/jobs?state=queued')}>{t.dash.queuedN(queued)}</a> ·{/if}
        <a href={href('/jobs')}>{t.nav.jobs}</a>
      </span>
    </div>
    {#if running.length === 0}
      <p class="muted">{queued ? t.dash.nothingRunningQueued : t.dash.nothingRunning}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <tbody>
            {#each running as j (j.id)}
              {@const p = j.progress}
              <tr use:rowLink={`/jobs/${j.id}`}>
                <td class="nowrap"><a href={href(`/jobs/${j.id}`)}>#{j.id}</a></td>
                <td>
                  {kindLabel(j.kind)}
                  {#if jobSubject(j, groups)}<div class="muted small">{jobSubject(j, groups)}</div>{/if}
                </td>
                <td class="muted small mono nowrap">
                  {#if p?.item}{p.item}{p.items && p.item_index ? ` (${p.item_index}/${p.items})` : ''}{/if}
                  {#if p?.part}<div>{p.part}</div>{/if}
                </td>
                <td class="wide">
                  {#if pct(j) !== null}
                    <ProgressBar size="s" value={pct(j)} label={t.jobs.progress} />
                  {:else}
                    <!-- no figures from this kind of job: how long it runs -->
                    <span class="muted small"
                      >{t.dash.runningFor(fmtDuration(Math.max(0, Date.now() / 1000 - (j.started ?? j.created))))}</span
                    >
                  {/if}
                </td>
                <td class="num nowrap tabular">
                  {pct(j) === null ? '' : `${Math.round(pct(j)!)} %`}
                  <div class="muted small">
                    {p?.rate ? fmtRate(p.rate) : p?.entries_rate ? fmtEntryRate(p.entries_rate) : ''}
                    {#if (p?.eta ?? p?.item_eta) !== null && (p?.eta ?? p?.item_eta) !== undefined}
                      · {t.jobs.etaAbout(fmtDuration((p?.eta ?? p?.item_eta)!))}{/if}
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{/if}

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 1rem;
  }
  td.wide {
    width: 30%;
    min-width: 8rem;
  }
  .small {
    font-size: 0.8rem;
  }
</style>
