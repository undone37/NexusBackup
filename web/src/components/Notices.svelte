<script lang="ts">
  import { notices, dismiss } from '../lib/notify.svelte';
  import { t } from '../lib/i18n';
</script>

<!-- Polite live region: screen readers announce results of actions (incl. "pending approval"). -->
<div class="notices" role="status" aria-live="polite">
  {#each notices as n (n.id)}
    <div class="notice {n.kind}">
      <p>{n.text}</p>
      <button type="button" class="icon" aria-label={t.close} onclick={() => dismiss(n.id)}>×</button>
    </div>
  {/each}
</div>
