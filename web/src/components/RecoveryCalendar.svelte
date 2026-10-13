<script lang="ts">
  // Phase 28: recovery calendar of one source. Every snapshot of a month as a chip
  // coloured by its scan state (scheduled / on-demand YARA scans) and anomaly flag;
  // a click hands the snapshot to the page (restore menu or file browser).
  import { t } from '../lib/i18n';
  import { fmtTime } from '../lib/format';
  import type { Snapshot } from '../lib/types';
  import IconLeft from '@lucide/svelte/icons/chevron-left';
  import IconRight from '@lucide/svelte/icons/chevron-right';

  interface Props {
    snaps: Snapshot[];
    onpick: (s: Snapshot) => void;
  }
  let { snaps, onpick }: Props = $props();

  type State = 'hit' | 'flagged' | 'clean' | 'incomplete' | 'unscanned';
  const stateOf = (s: Snapshot): State =>
    s.scan_state === 'hit' ? 'hit' : s.anomalous ? 'flagged' : (s.scan_state ?? 'unscanned');
  const chipClass: Record<State, string> = { hit: 'bad', flagged: 'bad', clean: 'ok', incomplete: 'warn', unscanned: 'plain' };

  const newest = $derived(snaps.reduce((m, s) => Math.max(m, s.time), 0));
  let offset = $state(0); // months back from the newest snapshot's month
  const month = $derived.by(() => {
    const d = new Date((newest || Date.now() / 1000) * 1000);
    return new Date(d.getFullYear(), d.getMonth() - offset, 1);
  });
  const title = $derived(month.toLocaleDateString(undefined, { year: 'numeric', month: 'long' }));
  const oldest = $derived(snaps.reduce((m, s) => Math.min(m, s.time), Infinity));
  const canBack = $derived(Number.isFinite(oldest) && oldest * 1000 < month.getTime());

  const weekdays = $derived.by(() => {
    const monday = new Date(2024, 0, 1); // a Monday
    return Array.from({ length: 7 }, (_, i) =>
      new Date(monday.getFullYear(), 0, 1 + i).toLocaleDateString(undefined, { weekday: 'short' }),
    );
  });

  const weeks = $derived.by(() => {
    const y = month.getFullYear();
    const m = month.getMonth();
    const lead = (new Date(y, m, 1).getDay() + 6) % 7; // Monday first
    const days = new Date(y, m + 1, 0).getDate();
    const byDay = new Map<number, Snapshot[]>();
    for (const s of snaps) {
      const d = new Date(s.time * 1000);
      if (d.getFullYear() !== y || d.getMonth() !== m) continue;
      const list = byDay.get(d.getDate()) ?? [];
      list.push(s);
      byDay.set(d.getDate(), list);
    }
    const cells: ({ day: number; snaps: Snapshot[] } | null)[] = [];
    for (let i = 0; i < lead; i++) cells.push(null);
    for (let d = 1; d <= days; d++) cells.push({ day: d, snaps: (byDay.get(d) ?? []).sort((a, b) => a.time - b.time) });
    while (cells.length % 7) cells.push(null);
    const out = [];
    for (let i = 0; i < cells.length; i += 7) out.push(cells.slice(i, i + 7));
    return out;
  });

  const hm = (s: Snapshot) => new Date(s.time * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
</script>

<section class="card calendar" aria-labelledby="cal-h">
  <div class="card-head">
    <h2 id="cal-h">{t.threat.calendar}</h2>
    <div class="nav">
      <button type="button" class="small" disabled={!canBack} onclick={() => offset++} aria-label={t.threat.calPrev}
        ><IconLeft aria-hidden="true" /></button
      >
      <span class="month" aria-live="polite">{title}</span>
      <button type="button" class="small" disabled={offset === 0} onclick={() => offset--} aria-label={t.threat.calNext}
        ><IconRight aria-hidden="true" /></button
      >
    </div>
  </div>
  <p class="muted">{t.threat.calendarHint}</p>
  <table class="cal">
    <thead>
      <tr>{#each weekdays as w (w)}<th scope="col">{w}</th>{/each}</tr>
    </thead>
    <tbody>
      {#each weeks as week, wi (wi)}
        <tr>
          {#each week as cell, ci (ci)}
            <td class:blank={!cell}>
              {#if cell}
                <div class="day">{cell.day}</div>
                {#each cell.snaps as s (s.time)}
                  {@const st = stateOf(s)}
                  <button
                    type="button"
                    class="chip {chipClass[st]} pick"
                    title={t.threat.calChipTitle(fmtTime(s.time), t.threat.states[st])}
                    aria-label={t.threat.calChipTitle(fmtTime(s.time), t.threat.states[st])}
                    onclick={() => onpick(s)}>{hm(s)}</button
                  >
                {/each}
              {/if}
            </td>
          {/each}
        </tr>
      {/each}
    </tbody>
  </table>
  <ul class="legend" aria-label={t.threat.legend}>
    {#each ['clean', 'hit', 'flagged', 'incomplete', 'unscanned'] as const as st (st)}
      <li><span class="chip {chipClass[st]}">{t.threat.states[st]}</span></li>
    {/each}
  </ul>
</section>

<style>
  .calendar {
    margin-bottom: 1rem;
  }
  .nav {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .month {
    min-width: 10rem;
    text-align: center;
    font-weight: 600;
  }
  table.cal {
    width: 100%;
    table-layout: fixed;
    border-collapse: collapse;
  }
  table.cal td {
    vertical-align: top;
    height: 4.5rem;
    border: 1px solid var(--border, #ddd);
    padding: 0.25rem;
  }
  table.cal td.blank {
    background: var(--surface-2, transparent);
  }
  .day {
    font-size: 0.8rem;
    color: var(--muted, #666);
    font-variant-numeric: tabular-nums;
  }
  .pick {
    cursor: pointer;
    margin: 0.1rem 0.1rem 0 0;
    font-variant-numeric: tabular-nums;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    list-style: none;
    padding: 0;
    margin: 0.75rem 0 0;
  }
</style>
