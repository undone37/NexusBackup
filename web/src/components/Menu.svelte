<script lang="ts" module>
  import type { Component } from 'svelte';
  export interface MenuItem {
    label: string;
    hint?: string;
    icon?: Component<any>;
    title?: string;
    onselect: () => void;
  }
</script>

<script lang="ts">
  import IconChevron from '@lucide/svelte/icons/chevron-down';

  // Action menu (e.g. the restore options of a snapshot). A native popover: it lives in the top
  // layer, so table scroll containers do not clip it, and Esc / outside clicks close it. The
  // position is set through the CSSOM (style: directive), which the CSP allows.
  let {
    label,
    ariaLabel,
    items,
    small = true,
    icon: Icon,
  }: { label: string; ariaLabel?: string; items: MenuItem[]; small?: boolean; icon?: Component<any> } = $props();

  const id = $props.id();
  let btn: HTMLButtonElement | undefined = $state();
  let pop: HTMLDivElement | undefined = $state();
  let open = $state(false);
  let top = $state(0);
  let right = $state(0);

  $effect(() => {
    if (!pop) return;
    // a scrolled table or page would leave the menu floating: close it instead
    const onScroll = () => pop?.hidePopover();
    // before it is shown (no flash at the wrong place): below the button, right-aligned; above it
    // when there is no room below (height estimated from the item count)
    const onBefore = (e: Event) => {
      if ((e as ToggleEvent).newState !== 'open' || !btn) return;
      const r = btn.getBoundingClientRect();
      const h = items.length * 46 + 12;
      right = Math.max(8, window.innerWidth - r.right);
      top = r.bottom + 4 + h > window.innerHeight - 8 ? Math.max(8, r.top - 4 - h) : r.bottom + 4;
    };
    const onToggle = (e: Event) => {
      open = (e as ToggleEvent).newState === 'open';
      if (open) {
        pop?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
        document.addEventListener('scroll', onScroll, true);
      } else document.removeEventListener('scroll', onScroll, true);
    };
    pop.addEventListener('beforetoggle', onBefore);
    pop.addEventListener('toggle', onToggle);
    return () => {
      pop?.removeEventListener('beforetoggle', onBefore);
      pop?.removeEventListener('toggle', onToggle);
      document.removeEventListener('scroll', onScroll, true);
    };
  });

  function choose(it: MenuItem) {
    pop?.hidePopover();
    it.onselect();
  }

  function keys(e: KeyboardEvent) {
    const all = [...(pop?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])];
    const i = all.indexOf(document.activeElement as HTMLElement);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const n = all.length;
      all[(i + (e.key === 'ArrowDown' ? 1 : n - 1) + n) % n]?.focus();
    } else if (e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      all[e.key === 'Home' ? 0 : all.length - 1]?.focus();
    } else if (e.key === 'Escape' || e.key === 'Tab') {
      e.preventDefault();
      pop?.hidePopover();
      btn?.focus();
    }
  }
</script>

<svelte:window onresize={() => open && pop?.hidePopover()} />

<button
  bind:this={btn}
  type="button"
  class:small
  aria-haspopup="menu"
  aria-expanded={open}
  aria-label={ariaLabel}
  popovertarget="{id}-menu"
>
  {#if Icon}<Icon aria-hidden="true" />{/if}{label}<IconChevron aria-hidden="true" />
</button>
<div
  bind:this={pop}
  id="{id}-menu"
  class="menu"
  popover="auto"
  role="menu"
  tabindex="-1"
  onkeydown={keys}
  style:top="{top}px"
  style:right="{right}px"
>
  {#each items as it, i (i)}
    <button type="button" role="menuitem" tabindex="-1" title={it.title} onclick={() => choose(it)}>
      {#if it.icon}<it.icon aria-hidden="true" />{/if}
      <span
        >{it.label}{#if it.hint}<small>{it.hint}</small>{/if}</span
      >
    </button>
  {/each}
</div>
