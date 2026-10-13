<script lang="ts">
  // Thin determinate bar (0..100); `value` null = unknown (track only, no fill).
  let { value, label, size = 'm' }: { value: number | null | undefined; label: string; size?: 's' | 'm' } = $props();
  const pct = $derived(value === null || value === undefined ? null : Math.max(0, Math.min(100, value)));
</script>

<div
  class="pbar {size}"
  role="progressbar"
  aria-label={label}
  aria-valuemin="0"
  aria-valuemax="100"
  aria-valuenow={pct === null ? undefined : Math.round(pct)}
>
  {#if pct !== null}<span style:width="{pct}%"></span>{/if}
</div>

<style>
  .pbar {
    position: relative;
    width: 100%;
    height: 0.5rem;
    border-radius: 999px;
    background: var(--c-track);
    overflow: hidden;
  }
  .pbar.s {
    height: 0.35rem;
    min-width: 4rem;
  }
  .pbar span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: var(--accent);
    transition: width 0.6s var(--ease);
  }
  @media (prefers-reduced-motion: reduce) {
    .pbar span {
      transition: none;
    }
  }
</style>
