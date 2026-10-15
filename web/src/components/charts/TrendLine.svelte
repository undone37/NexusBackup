<script lang="ts">
  import { fmtBytes, fmtDay, fmtPct, niceMax } from '../../lib/format';
  import { t } from '../../lib/i18n';

  // Capacity trend: used bytes per day, the capacity limit, and a dashed linear forecast that
  // reaches the limit after `forecastDays` (server-side regression; null = not growing / unknown).
  let {
    data,
    total,
    forecastDays,
    title,
    height = 230,
  }: {
    data: { day: string; used: number }[];
    total: number;
    forecastDays: number | null;
    title: string;
    height?: number;
  } = $props();

  const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let w = $state(640);
  const M = { l: 52, r: 10, t: 14, b: 24 };
  const iw = $derived(Math.max(10, w - M.l - M.r));
  const ih = $derived(height - M.t - M.b);
  const n = $derived(data.length);
  const last = $derived(data[n - 1]?.used ?? 0);
  // forecast slope (bytes/day) and how far to the right it is drawn (a third of the window)
  const ext = $derived(forecastDays !== null && forecastDays > 0 && n > 1 ? Math.max(3, Math.round(n / 3)) : 0);
  const slope = $derived(ext ? (total - last) / (forecastDays as number) : 0);
  const fEnd = $derived(last + slope * ext);
  const span = $derived(Math.max(1, n - 1 + ext));
  // axis in one binary unit
  const unit = $derived(
    Math.max(0, Math.min(UNITS.length - 1, Math.floor(Math.log(Math.max(total, last, 1)) / Math.log(1024)))),
  );
  const div = $derived(1024 ** unit);
  const max = $derived(niceMax((Math.max(total, last, fEnd) * 1.04) / div) * div);
  const x = (i: number) => M.l + (i / span) * iw;
  const y = (v: number) => M.t + ih - (v / max) * ih;
  const ticks = $derived([0, 0.25, 0.5, 0.75, 1].map((f) => f * max));
  const line = $derived(data.map((d, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(d.used).toFixed(1)}`).join(''));
  const area = $derived(n ? `${line}L${x(n - 1).toFixed(1)},${y(0)}L${x(0).toFixed(1)},${y(0)}Z` : '');
  const every = $derived(Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 70)))));

  let hover: number | null = $state(null);
  function move(e: PointerEvent) {
    const r = (e.currentTarget as SVGElement).getBoundingClientRect();
    const i = Math.round(((e.clientX - r.left - M.l) / iw) * span);
    hover = i >= 0 && i < n ? i : null;
  }
</script>

<div class="chart" bind:clientWidth={w}>
  <svg
    class="plot"
    width={w}
    {height}
    viewBox="0 0 {w} {height}"
    role="img"
    aria-label={title}
    onpointermove={move}
    onpointerleave={() => (hover = null)}
  >
    <g class="grid axis">
      {#each ticks as v (v)}
        <line x1={M.l} x2={w - M.r} y1={y(v)} y2={y(v)} />
        <text x={M.l - 8} y={y(v) + 4} text-anchor="end">{+(v / div).toFixed(1)} {UNITS[unit]}</text>
      {/each}
    </g>
    {#if n}
      <path class="area-1" d={area} />
      <path class="series-1" d={line} />
      {#if ext}
        <path class="forecast" d="M{x(n - 1)},{y(last)}L{x(n - 1 + ext)},{y(fEnd)}" />
      {/if}
    {/if}
    {#if total > 0}
      <line class="limit" x1={M.l} x2={w - M.r} y1={y(total)} y2={y(total)} />
      <text class="limit-label" x={w - M.r} y={y(total) - 6} text-anchor="end">{t.dash.capTotal} {fmtBytes(total)}</text
      >
    {/if}
    <line class="baseline" x1={M.l} x2={w - M.r} y1={M.t + ih + 0.5} y2={M.t + ih + 0.5} />
    <g class="axis">
      {#each data as d, i (d.day)}
        {#if (n - 1 - i) % every === 0}
          <text x={x(i)} y={height - 6} text-anchor="middle">{fmtDay(d.day)}</text>
        {/if}
      {/each}
    </g>
    {#if hover !== null}
      <line class="cursor" x1={x(hover)} x2={x(hover)} y1={M.t} y2={M.t + ih} />
      <circle class="dot" cx={x(hover)} cy={y(data[hover].used)} r="4.5" />
    {/if}
  </svg>
  {#if hover !== null}
    <div class="tooltip" style:left="{Math.min(Math.max(x(hover), 90), w - 90)}px" style:top="{y(data[hover].used)}px">
      <strong>{fmtDay(data[hover].day, true)}</strong>
      <div class="tt-row"><span class="swatch c1"></span>{t.dash.capUsed}<b>{fmtBytes(data[hover].used)}</b></div>
      {#if total > 0}<div class="tt-row">
          <span class="swatch limit"></span>{t.dash.capTotal}<b>{fmtPct(data[hover].used / total)}</b>
        </div>{/if}
    </div>
  {/if}
  <ul class="legend">
    <li><span class="swatch line"></span>{t.dash.capUsed} <b>{fmtBytes(last)}</b></li>
    {#if ext}<li><span class="swatch dash"></span>{t.dash.capForecast}</li>{/if}
    {#if total > 0}<li><span class="swatch limit"></span>{t.dash.capTotal} <b>{fmtBytes(total)}</b></li>{/if}
  </ul>
  <table class="visually-hidden">
    <caption>{title}</caption>
    <thead><tr><th scope="col">{t.time}</th><th scope="col">{t.dash.capUsed}</th></tr></thead>
    <tbody>
      {#each data as d (d.day)}<tr><th scope="row">{fmtDay(d.day, true)}</th><td>{fmtBytes(d.used)}</td></tr>{/each}
    </tbody>
  </table>
</div>
