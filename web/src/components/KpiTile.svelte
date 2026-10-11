<script lang="ts">
  import type { Component } from 'svelte';

  // One key figure: label (+ icon), value (+ unit), one line of context, optional meter
  // (0..1, colored by `tone`) and a link to the page behind the number.
  let {
    label,
    value,
    unit = '',
    sub = '',
    tone = '',
    meter = null,
    href = '',
    icon: Icon,
  }: {
    label: string;
    value: string;
    unit?: string;
    sub?: string;
    tone?: '' | 'ok' | 'warn' | 'bad';
    meter?: number | null;
    href?: string;
    icon?: Component<any>;
  } = $props();

  const fill = $derived(meter === null ? 0 : Math.max(0, Math.min(1, meter)) * 100);
</script>

{#snippet body()}
  <span class="k-label">{#if Icon}<Icon aria-hidden="true" />{/if}{label}</span>
  <span class="k-value">{value}{#if unit}<small>{unit}</small>{/if}</span>
  {#if meter !== null}
    <svg class="meter" viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true">
      <rect class="meter-track" width="100" height="6" rx="3" />
      <rect class="meter-fill {tone}" width={fill} height="6" rx="3" />
    </svg>
  {/if}
  {#if sub}<span class="k-sub" title={sub}>{sub}</span>{/if}
{/snippet}

{#if href}
  <a class="kpi {tone}" {href}>{@render body()}</a>
{:else}
  <div class="kpi {tone}">{@render body()}</div>
{/if}

<style>
  .meter-track {
    fill: var(--c-track);
  }
  .meter-fill {
    fill: var(--c-1);
  }
  .meter-fill.ok {
    fill: var(--c-ok);
  }
  .meter-fill.warn {
    fill: var(--c-warn);
  }
  .meter-fill.bad {
    fill: var(--c-bad);
  }
</style>
