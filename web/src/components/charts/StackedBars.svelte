<script lang="ts">
  import { fmtDay, niceMax } from '../../lib/format';
  import { t } from '../../lib/i18n';

  // Jobs per day, stacked by outcome (ok / warning / failed), hand-written SVG.
  // Status colors carry the outcome; the legend + tooltip + hidden table name it in text too.
  let { data, title, height = 220 }: { data: { day: string; ok: number; warning: number; failed: number }[]; title: string; height?: number } =
    $props();

  const KEYS = [
    { k: 'ok', cls: 'seg-ok', sw: 'ok', label: t.dash.ok_ },
    { k: 'warning', cls: 'seg-warn', sw: 'warn', label: t.dash.warning_ },
    { k: 'failed', cls: 'seg-bad', sw: 'bad', label: t.dash.failed_ },
  ] as const;

  let w = $state(640);
  const M = { l: 36, r: 6, t: 10, b: 24 };
  const iw = $derived(Math.max(10, w - M.l - M.r));
  const ih = $derived(height - M.t - M.b);
  const max = $derived(niceMax(Math.max(1, ...data.map((d) => d.ok + d.warning + d.failed))));
  // whole-number ticks: 4 or 5 steps, or 2 when neither divides evenly
  const ticks = $derived.by(() => {
    const n = max <= 4 ? max : [4, 5, 2].find((k) => Number.isInteger(max / k)) ?? 1;
    return Array.from({ length: n + 1 }, (_, i) => (i * max) / n);
  });
  const band = $derived(iw / Math.max(1, data.length));
  const bw = $derived(Math.max(3, Math.min(28, band * 0.64)));
  const y = (v: number) => M.t + ih - (v / max) * ih;
  const every = $derived(Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(iw / 64)))));
  const totals = $derived(data.reduce((a, d) => ({ ok: a.ok + d.ok, warning: a.warning + d.warning, failed: a.failed + d.failed }), { ok: 0, warning: 0, failed: 0 }));

  // stacked segments with a 1.5 px gap between them (surface shows through)
  const stacks = $derived(
    data.map((d, i) => {
      let acc = 0;
      const x = M.l + i * band + (band - bw) / 2;
      const segs = [];
      for (const s of KEYS) {
        const v = d[s.k];
        if (!v) continue;
        const y0 = y(acc);
        acc += v;
        const y1 = y(acc);
        segs.push({ cls: s.cls, x, y: y1, h: Math.max(1, y0 - y1 - (acc > v ? 1.5 : 0)) });
      }
      return { x, segs, total: acc };
    }),
  );

  let hover: number | null = $state(null);
  const hd = $derived(hover === null ? null : data[hover]);
</script>

<div class="chart" bind:clientWidth={w}>
  <svg class="plot" width={w} {height} viewBox="0 0 {w} {height}" role="img" aria-label={title}>
    <g class="grid axis">
      {#each ticks as v (v)}
        <line x1={M.l} x2={w - M.r} y1={y(v)} y2={y(v)} />
        <text x={M.l - 8} y={y(v) + 4} text-anchor="end">{v}</text>
      {/each}
    </g>
    {#each stacks as s, i (data[i].day)}
      <rect class="col-hit" class:on={hover === i} x={M.l + i * band} y={M.t} width={band} height={ih} rx="3" />
      {#each s.segs as g (g.cls)}
        <rect class={g.cls} x={g.x} y={g.y} width={bw} height={g.h} rx={Math.min(2, bw / 3)} />
      {/each}
    {/each}
    <line class="baseline" x1={M.l} x2={w - M.r} y1={M.t + ih + 0.5} y2={M.t + ih + 0.5} />
    <g class="axis">
      {#each data as d, i (d.day)}
        {#if (data.length - 1 - i) % every === 0}
          <text x={M.l + i * band + band / 2} y={height - 6} text-anchor="middle">{fmtDay(d.day)}</text>
        {/if}
      {/each}
    </g>
    <!-- hit areas last: on top of the bars -->
    {#each data as d, i (d.day)}
      <rect
        class="col-hit"
        role="presentation"
        x={M.l + i * band}
        y={M.t}
        width={band}
        height={ih}
        onpointerenter={() => (hover = i)}
        onpointerleave={() => (hover = null)}
      />
    {/each}
  </svg>
  {#if hd && hover !== null}
    <div class="tooltip" style:left="{Math.min(Math.max(M.l + hover * band + band / 2, 80), w - 80)}px" style:top="{y(stacks[hover].total)}px">
      <strong>{fmtDay(hd.day, true)}</strong>
      {#each KEYS as s (s.k)}
        <div class="tt-row"><span class="swatch {s.sw}"></span>{s.label}<b>{hd[s.k]}</b></div>
      {/each}
    </div>
  {/if}
  <ul class="legend">
    {#each KEYS as s (s.k)}
      <li><span class="swatch {s.sw}"></span>{s.label} <b>{totals[s.k]}</b></li>
    {/each}
  </ul>
  <table class="visually-hidden">
    <caption>{title}</caption>
    <thead><tr><th scope="col">{t.time}</th>{#each KEYS as s (s.k)}<th scope="col">{s.label}</th>{/each}</tr></thead>
    <tbody>
      {#each data as d (d.day)}
        <tr><th scope="row">{fmtDay(d.day, true)}</th><td>{d.ok}</td><td>{d.warning}</td><td>{d.failed}</td></tr>
      {/each}
    </tbody>
  </table>
</div>
