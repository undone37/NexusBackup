<script lang="ts">
  // Donut: segments as stroked circle arcs (stroke-dasharray), a 2 px gap between them, the
  // headline in the middle and a legend with the numbers next to it (identity never by color only).
  let {
    segments,
    big,
    small = '',
    title,
    size = 150,
    fmt = (v: number) => String(v),
  }: {
    segments: { value: number; cls: string; label: string }[];
    big: string;
    small?: string;
    title: string;
    size?: number;
    fmt?: (v: number) => string;
  } = $props();

  const sw = $derived(size * 0.12);
  const r = $derived(size / 2 - sw / 2 - 1);
  const c = $derived(2 * Math.PI * r);
  const sum = $derived(segments.reduce((a, s) => a + Math.max(0, s.value), 0));
  const shown = $derived(segments.filter((s) => s.value > 0));
  const arcs = $derived.by(() => {
    let off = 0;
    const gap = shown.length > 1 ? 2 : 0;
    return shown.map((s) => {
      const len = sum ? (s.value / sum) * c : 0;
      const a = { cls: s.cls, dash: `${Math.max(0.5, len - gap)} ${c}`, offset: -off };
      off += len;
      return a;
    });
  });
</script>

<div class="chart ring-wrap">
  <svg class="plot" viewBox="0 0 {size} {size}" width={size} height={size} role="img" aria-label="{title}: {big} {small}">
    <circle class="ring-track" cx={size / 2} cy={size / 2} {r} stroke-width={sw} />
    <g transform="rotate(-90 {size / 2} {size / 2})">
      {#each arcs as a, i (i)}
        <circle class="arc {a.cls}" cx={size / 2} cy={size / 2} {r} stroke-width={sw} stroke-dasharray={a.dash} stroke-dashoffset={a.offset} />
      {/each}
    </g>
    <text class="big" x={size / 2} y={size / 2 + (small ? 4 : 9)} text-anchor="middle">{big}</text>
    {#if small}<text class="small" x={size / 2} y={size / 2 + 22} text-anchor="middle">{small}</text>{/if}
  </svg>
  <ul class="legend">
    {#each segments as s (s.label)}
      <li><span class="swatch {s.cls}"></span>{s.label}<b>{fmt(s.value)}</b></li>
    {/each}
  </ul>
</div>
