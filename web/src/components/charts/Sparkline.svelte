<script lang="ts">
  // Phase 21a: a small single-series line (change trends on the Sources page). Values are
  // oldest first; null points leave a gap. Flagged points get a critical-colored dot; each
  // point has a hover target with its label (`tip`).
  let {
    values,
    flagged = [],
    tip,
    label,
    width = 140,
    height = 32,
  }: {
    values: (number | null)[];
    flagged?: boolean[];
    tip: (i: number) => string;
    label: string;
    width?: number;
    height?: number;
  } = $props();

  const P = 5;
  const n = $derived(values.length);
  const max = $derived(Math.max(1, ...values.map((v) => v ?? 0)));
  const x = (i: number) => (n <= 1 ? width / 2 : P + (i / (n - 1)) * (width - 2 * P));
  const y = (v: number) => height - P - (v / max) * (height - 2 * P);
  // one path, a move at the start and after every gap
  const d = $derived(
    values
      .map((v, i) => (v === null ? '' : `${i === 0 || values[i - 1] === null ? 'M' : 'L'}${x(i).toFixed(1)},${y(v).toFixed(1)}`))
      .join(''),
  );
  const step = $derived(n > 1 ? (width - 2 * P) / (n - 1) : width);
  let hover: number | null = $state(null);
</script>

<svg {width} {height} viewBox="0 0 {width} {height}" role="img" aria-label={label} class="spark">
  <line x1={P} x2={width - P} y1={height - P} y2={height - P} class="base" />
  {#if hover !== null && values[hover] !== null}
    <line x1={x(hover)} x2={x(hover)} y1={P / 2} y2={height - P} class="cross" />
  {/if}
  <path {d} class="line" />
  {#each values as v, i (i)}
    {#if v !== null && (flagged[i] || i === n - 1 || hover === i)}
      <circle cx={x(i)} cy={y(v)} r={flagged[i] ? 4 : 2.5} class:bad={flagged[i]} class="dot" />
    {/if}
  {/each}
  {#each values as _, i (i)}
    <rect
      x={x(i) - step / 2}
      y="0"
      width={step}
      {height}
      class="hit"
      role="presentation"
      onpointerenter={() => (hover = i)}
      onpointerleave={() => (hover = null)}><title>{tip(i)}</title></rect
    >
  {/each}
</svg>

<style>
  .spark {
    display: block;
    overflow: visible;
  }
  .base {
    stroke: var(--c-grid);
    stroke-width: 1;
  }
  .cross {
    stroke: var(--border-strong);
    stroke-width: 1;
  }
  .line {
    fill: none;
    stroke: var(--accent);
    stroke-width: 2;
    stroke-linejoin: round;
    stroke-linecap: round;
  }
  .dot {
    fill: var(--accent);
    stroke: var(--surface);
    stroke-width: 2;
  }
  .dot.bad {
    fill: var(--c-bad);
  }
  .hit {
    fill: transparent;
  }
</style>
