<script lang="ts">
  // Phase 21a: new data and changed files per protected system over its last 30 backups
  // (GET /stats/trends, from backup_stats); flagged snapshots as red dots.
  // Phase 30: the backup's duration and the share of the data read that was new, and the
  // per-source anomaly sensitivity (PUT /stats/sensitivity; lowering it is an approval).
  import { onMount } from 'svelte';
  import SourceName from './SourceName.svelte';
  import { get, put, act, errText, qs } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { fmtBytes, fmtDuration, fmtPct, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { can } from '../lib/roles';
  import { session } from '../lib/session.svelte';
  import type { Sensitivity, SourceTrend } from '../lib/types';
  import Sparkline from './charts/Sparkline.svelte';

  let trends: SourceTrend[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let busy: string | null = $state(null);
  async function load() {
    try {
      trends = await get<SourceTrend[]>('/stats/trends');
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);
  const last = <T,>(xs: T[]) => xs[xs.length - 1];
  const share = (r: SourceTrend['runs'][number]) => (r.read > 0 ? Math.min(1, r.new_plain / r.read) : null);
  const editable = $derived(can.sensitivity(session.user));

  async function setLevel(tr: SourceTrend, level: Sensitivity) {
    if (level === tr.sensitivity) return;
    busy = `${tr.tenant}/${tr.source}`;
    const o = await act(
      put('/stats/sensitivity', { tenant: tr.tenant, source: tr.source, level }),
      t.sources.sensSaved(tr.source, t.sources.sensLevel[level]),
    );
    busy = null;
    if (o) await load();
  }
</script>

<section class="card" aria-labelledby="trends-h">
  <div class="card-head"><h2 id="trends-h">{t.sources.trends}</h2></div>
  <p class="muted">{t.sources.trendsIntro}</p>
  <p class="muted small-hint">{t.sources.sensHint}</p>
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
            <th scope="col">{t.sources.trendDuration}</th>
            <th scope="col">{t.sources.sensitivity}</th>
          </tr>
        </thead>
        <tbody>
          {#each trends as tr (`${tr.tenant}/${tr.source}`)}
            {@const flagged = tr.runs.map((r) => r.anomalous)}
            {@const files = tr.runs.map((r) => r.files_changed)}
            {@const lastFiles = last(files)}
            {@const secs = tr.runs.map((r) => r.secs)}
            {@const lastRun = last(tr.runs)}
            <tr>
              <td
                ><a href={href('/snapshots' + qs({ tenant: tr.tenant, source: tr.source }))}
                  ><SourceName source={tr.source} tenant={tr.tenant} /></a
                ></td
              >
              <td>{tr.tenant}</td>
              <td>
                <div class="cell">
                  <Sparkline
                    values={tr.runs.map((r) => r.new_plain)}
                    {flagged}
                    label={t.sources.trendChart(t.sources.trendBytes, tr.source, tr.runs.length)}
                    tip={(i) =>
                      `${fmtTime(tr.runs[i].time)}: ${fmtBytes(tr.runs[i].new_plain)}${flagged[i] ? ` · ${t.snap.anomalous}` : ''}`}
                  />
                  <span
                    class="muted small"
                    title={share(lastRun) === null ? undefined : t.sources.trendNew(fmtPct(share(lastRun), 0))}
                    >{t.sources.trendLast(fmtBytes(lastRun.new_plain))}</span
                  >
                </div>
              </td>
              <td>
                <div class="cell">
                  {#if files.some((f) => f !== null)}
                    <Sparkline
                      values={files}
                      {flagged}
                      label={t.sources.trendChart(t.sources.trendFiles, tr.source, tr.runs.length)}
                      tip={(i) =>
                        `${fmtTime(tr.runs[i].time)}: ${files[i] ?? t.sources.trendNoFiles}${flagged[i] ? ` · ${t.snap.anomalous}` : ''}`}
                    />
                    <span class="muted small">{t.sources.trendLast(lastFiles === null ? '—' : String(lastFiles))}</span>
                  {:else}
                    <span class="muted small">{t.sources.trendNoFiles}</span>
                  {/if}
                </div>
              </td>
              <td>
                <div class="cell">
                  {#if secs.some((s) => s !== null)}
                    <Sparkline
                      values={secs}
                      {flagged}
                      label={t.sources.trendChart(t.sources.trendDuration, tr.source, tr.runs.length)}
                      tip={(i) =>
                        `${fmtTime(tr.runs[i].time)}: ${fmtDuration(secs[i])}${flagged[i] ? ` · ${t.snap.anomalous}` : ''}`}
                    />
                    <span class="muted small">{t.sources.trendLast(fmtDuration(lastRun.secs))}</span>
                  {:else}
                    <span class="muted small">{t.sources.trendNoDuration}</span>
                  {/if}
                </div>
              </td>
              <td>
                {#if editable}
                  <select
                    aria-label={t.sources.sensitivityLabel(tr.source)}
                    value={tr.sensitivity}
                    disabled={busy === `${tr.tenant}/${tr.source}`}
                    onchange={(e) => setLevel(tr, (e.currentTarget as HTMLSelectElement).value as Sensitivity)}
                  >
                    {#each ['low', 'medium', 'high'] as l (l)}
                      <option value={l}>{t.sources.sensLevel[l]}</option>
                    {/each}
                  </select>
                {:else}
                  {t.sources.sensLevel[tr.sensitivity]}
                {/if}
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
  .small-hint {
    font-size: 0.85rem;
  }
  .small {
    font-size: 0.8rem;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }
</style>
