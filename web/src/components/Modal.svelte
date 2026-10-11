<script lang="ts">
  import type { Snippet } from 'svelte';
  import { t } from '../lib/i18n';
  import IconX from '@lucide/svelte/icons/x';

  let {
    open = $bindable(false),
    title,
    wide = false,
    children,
  }: { open?: boolean; title: string; wide?: boolean; children: Snippet } = $props();

  const id = $props.id();
  let dlg: HTMLDialogElement | undefined = $state();

  // Native <dialog>: focus trapping, Esc to close and inert background for free.
  $effect(() => {
    if (!dlg) return;
    if (open && !dlg.open) dlg.showModal();
    else if (!open && dlg.open) dlg.close();
  });
</script>

<dialog bind:this={dlg} class:wide aria-labelledby="{id}-title" onclose={() => (open = false)}>
  {#if open}
    <header>
      <h2 id="{id}-title">{title}</h2>
      <button type="button" class="icon" aria-label={t.close} onclick={() => (open = false)}><IconX aria-hidden="true" /></button>
    </header>
    <div class="body">
      {@render children()}
    </div>
  {/if}
</dialog>
