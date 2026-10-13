<script lang="ts">
  // Phase 21a: new data and changed files per protected system over its last 30 backups
  // (GET /stats/trends, from backup_stats); flagged snapshots as red dots.
  import { onMount } from 'svelte';
  import { get, errText, qs } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { SourceTrend } from '../lib/types';
  import Sparkline from './charts/Sparkline.svelte';

  let trends: SourceTrend[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  onMount(async () => {
    try {
      trends = await get<SourceTrend[]>('/stats/trends');
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  });
  const last = <T,>(xs: T[]) => xs[xs.length - 1];
</script>

<section class="card" aria-labelledby="trends-h">
  <div class="card-head"><h2 id="trends-h">{t.sources.trends}</h2></div>
  <p class="muted">{t.sources.trendsIntro}</p>
  {#if error}
    <p class="banner error">{error}</p>
  {:else if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if !trends.length}
    <p class="empty">{t.sources.trendsEmpty}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.sources.trendSource}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.sources.trendBytes}</th>
            <th scope="col">{t.sources.trendFiles}</th>
          </tr>
        </thead>
        <tbody>
          {#each trends as tr (`${tr.tenant}/${tr.source}`)}
            {@const flagged = tr.runs.map((r) => r.anomalous)}
            {@const files = tr.runs.map((r) => r.files_changed)}
            {@const lastFiles = last(files)}
            <tr>
              <td><a class="mono" href={href('/snapshots' + qs({ tenant: tr.tenant, source: tr.source }))}>{tr.source}</a></td>
              <td>{tr.tenant}</td>
              <td>
                <div class="cell">
                  <Sparkline
                    values={tr.runs.map((r) => r.new_plain)}
                    {flagged}
                    label={t.sources.trendChart(t.sources.trendBytes, tr.source, tr.runs.length)}
                    tip={(i) => `${fmtTime(tr.runs[i].time)}: ${fmtBytes(tr.runs[i].new_plain)}${flagged[i] ? ` · ${t.snap.anomalous}` : ''}`}
                  />
                  <span class="muted small">{t.sources.trendLast(fmtBytes(last(tr.runs).new_plain))}</span>
                </div>
              </td>
              <td>
                <div class="cell">
                  {#if files.some((f) => f !== null)}
                    <Sparkline
                      values={files}
                      {flagged}
                      label={t.sources.trendChart(t.sources.trendFiles, tr.source, tr.runs.length)}
                      tip={(i) => `${fmtTime(tr.runs[i].time)}: ${files[i] ?? t.sources.trendNoFiles}${flagged[i] ? ` · ${t.snap.anomalous}` : ''}`}
                    />
                    <span class="muted small">{t.sources.trendLast(lastFiles === null ? '—' : String(lastFiles))}</span>
                  {:else}
                    <span class="muted small">{t.sources.trendNoFiles}</span>
                  {/if}
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .cell {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .small {
    font-size: 0.8rem;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }
</style>
