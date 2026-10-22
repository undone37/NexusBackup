<script lang="ts">
  // A snapshot source as people know it: the guest's or agent's name, the id muted next to it.
  import { nameOf } from '../lib/names.svelte';

  let { source, tenant = undefined }: { source: string; tenant?: string | null } = $props();
  const name = $derived(nameOf(tenant, source));
</script>

{#if name}<span class="sn">{name}</span> <span class="muted mono sid">{source}</span>{:else}<span class="mono"
    >{source}</span
  >{/if}

<style>
  .sn {
    font-weight: 500;
  }
  .sid {
    font-size: 0.8em;
  }
</style>
