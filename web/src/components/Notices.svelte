<script lang="ts">
  import { notices, dismiss } from '../lib/notify.svelte';
  import { t } from '../lib/i18n';
  import { href } from '../lib/router.svelte';
  import IconOk from '@lucide/svelte/icons/circle-check';
  import IconError from '@lucide/svelte/icons/circle-alert';
  import IconPending from '@lucide/svelte/icons/clock-alert';
  import IconInfo from '@lucide/svelte/icons/info';
  import IconX from '@lucide/svelte/icons/x';
</script>

<!-- Polite live region: screen readers announce results of actions (incl. "pending approval"). -->
<div class="notices" role="status" aria-live="polite">
  {#each notices as n (n.id)}
    <div class="notice {n.kind}">
      {#if n.kind === 'ok'}<IconOk aria-hidden="true" />{:else if n.kind === 'error'}<IconError aria-hidden="true" />{:else if n.kind === 'pending'}<IconPending
          aria-hidden="true"
        />{:else}<IconInfo aria-hidden="true" />{/if}
      <p>
        {n.text}{#if n.link}
          <a href={href(n.link.path)} onclick={() => dismiss(n.id)}>{n.link.label}</a>{/if}
      </p>
      <button type="button" class="icon" aria-label={t.close} onclick={() => dismiss(n.id)}><IconX aria-hidden="true" /></button>
    </div>
  {/each}
</div>
