<script lang="ts" module>
  export interface SimInput {
    schedule: string;
    gfs: { recent?: number; daily: number; weekly: number; monthly: number; yearly: number };
    timezone?: string;
  }
</script>

<script lang="ts">
  // Restore point simulator (Phase 23a, POST /policies/simulate): kept restore points over the
  // next 400 days for a schedule + GFS, with an estimate of the stored bytes from measured
  // backups. `before` draws the current values as a dashed line (policy edits, approvals).
  import { post, errText } from '../lib/api';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Simulation } from '../lib/types';

  let {
    input,
    before = null,
    policyId = null,
    tenant = null,
    height = 170,
  }: { input: SimInput; before?: SimInput | null; policyId?: number | null; tenant?: string | null; height?: number } = $props();

  let sim = $state<Simulation | null>(null);
  let old = $state<Simulation | null>(null);
  let error: string | null = $state(null);

  async function run(i: SimInput): Promise<Simulation> {
    const body: Record<string, unknown> = { schedule: i.schedule, gfs: i.gfs, timezone: i.timezone ?? 'UTC' };
    if (policyId) body.policy_id = policyId;
    if (tenant) body.tenant = tenant;
    return (await post<Simulation>('/policies/simulate', body)).data as Simulation;
  }

  // debounced: the policy dialog changes the values on every keystroke
  $effect(() => {
    const cur = $state.snapshot(input) as SimInput;
    const prev = before ? ($state.snapshot(before) as SimInput) : null;
    if (!cur.schedule) return;
    const h = setTimeout(async () => {
      try {
        [sim, old] = await Promise.all([run(cur), prev ? run(prev) : Promise.resolve(null)]);
        error = null;
      } catch (e) {
        error = errText(e);
        sim = null;
      }
    }, 350);
    return () => clearTimeout(h);
  });

  let w = $state(520);
  const M = { l: 34, r: 10, t: 10, b: 22 };
  const iw = $derived(Math.max(10, w - M.l - M.r));
  const ih = $derived(height - M.t - M.b);
  const t0 = $derived(sim?.series[0]?.t ?? 0);
  const t1 = $derived(sim?.final.newest ?? t0 + 1);
  const ymax = $derived(Math.max(4, sim?.final.peak ?? 0, old?.final.peak ?? 0) * 1.1);
  const x = (tt: number) => M.l + ((tt - t0) / Math.max(1, t1 - t0)) * iw;
  const y = (v: number) => M.t + ih - (v / ymax) * ih;
  const path = (s: Simulation | null) =>
    (s?.series ?? []).map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.points).toFixed(1)}`).join('');
  const months = $derived(Math.round((t1 - t0) / (30 * 86400)));
  const ticks = $derived([0, 0.5, 1].map((f) => Math.round(f * ymax)));
  const classes = (s: Simulation) =>
    (['recent', 'daily', 'weekly', 'monthly', 'yearly'] as const)
      .filter((k) => s.final[k] > 0)
      .map((k) => `${s.final[k]} ${t.sp.sim.classes[k]}`)
      .join(' · ');
</script>

<section class="sim" aria-label={t.sp.sim.title}>
  <h3>{t.sp.sim.title}</h3>
  {#if error}
    <p class="hint">{error}</p>
  {:else if !sim}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else}
    <div class="chart" bind:clientWidth={w}>
      <svg class="plot" width={w} {height} viewBox="0 0 {w} {height}" role="img" aria-label={t.sp.sim.chart(sim.final.points, sim.days)}>
        <g class="grid axis">
          {#each ticks as v (v)}
            <line x1={M.l} x2={w - M.r} y1={y(v)} y2={y(v)} />
            <text x={M.l - 6} y={y(v) + 4} text-anchor="end">{v}</text>
          {/each}
        </g>
        {#if old}<path class="forecast" d={path(old)} />{/if}
        <path class="series-1" d={path(sim)} />
        <line class="baseline" x1={M.l} x2={w - M.r} y1={M.t + ih + 0.5} y2={M.t + ih + 0.5} />
        <g class="axis">
          <text x={M.l} y={height - 5}>{t.sp.sim.now}</text>
          <text x={w - M.r} y={height - 5} text-anchor="end">{t.sp.sim.inMonths(months)}</text>
        </g>
      </svg>
    </div>
    <dl class="facts">
      <dt>{t.sp.sim.points}</dt>
      <dd>
        <strong>{sim.final.points}</strong>
        {#if old && old.final.points !== sim.final.points}<span class="muted">({t.sp.sim.was(old.final.points)})</span>{/if}
        <span class="muted">{classes(sim)}</span>
      </dd>
      <dt>{t.sp.sim.oldest}</dt>
      <dd>{sim.final.oldest ? fmtTime(sim.final.oldest) : '—'}</dd>
      <dt>{t.sp.sim.stored}</dt>
      <dd>
        {#if sim.estimate}
          <strong>≈ {fmtBytes(sim.estimate.stored)}</strong>
          {#if old?.estimate && old.estimate.stored !== sim.estimate.stored}<span class="muted">({t.sp.sim.was(fmtBytes(old.estimate.stored))})</span>{/if}
          <div class="hint">{t.sp.sim.storedHow(fmtBytes(sim.estimate.full), fmtBytes(sim.estimate.delta), sim.estimate.sources)}</div>
        {:else}
          <span class="muted">{t.sp.sim.noStats}</span>
        {/if}
      </dd>
    </dl>
    {#if old}<p class="hint">{t.sp.sim.legend}</p>{/if}
    {#if sim.truncated}<p class="hint">{t.sp.sim.truncated(sim.runs)}</p>{/if}
  {/if}
</section>

<style>
  .sim {
    margin: 0.75rem 0;
  }
  h3 {
    font-size: 0.95rem;
    margin: 0 0 0.25rem;
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
    margin: 0.5rem 0 0;
  }
  .facts dt {
    color: var(--muted);
  }
  .facts dd {
    margin: 0;
  }
</style>
