<script lang="ts">
  import { niceMax } from '../../lib/format';

  // Horizontal bars, one series (e.g. failed jobs per source type), every bar labeled directly.
  let { items, title }: { items: { label: string; value: number }[]; title: string } = $props();

  let w = $state(360);
  const ROW = 30;
  const LABEL = 116;
  const VAL = 34;
  const height = $derived(items.length * ROW + 4);
  const max = $derived(niceMax(Math.max(1, ...items.map((i) => i.value))));
  const bw = $derived(Math.max(10, w - LABEL - VAL));
</script>

<div class="chart" bind:clientWidth={w}>
  <svg class="plot" width={w} {height} viewBox="0 0 {w} {height}" role="img" aria-label={title}>
    {#each items as it, i (it.label)}
      {@const y = i * ROW + 6}
      <text class="label" x="0" y={y + 13}>{it.label}</text>
      <rect class="hbar-track" x={LABEL} {y} width={bw} height="16" rx="4" />
      <rect class="hbar" x={LABEL} {y} width={Math.max(it.value ? 4 : 0, (it.value / max) * bw)} height="16" rx="4" />
      <text class="value" x={w} y={y + 13} text-anchor="end">{it.value}</text>
    {/each}
  </svg>
  <table class="visually-hidden">
    <caption>{title}</caption>
    <tbody>{#each items as it (it.label)}<tr><th scope="row">{it.label}</th><td>{it.value}</td></tr>{/each}</tbody>
  </table>
</div>
