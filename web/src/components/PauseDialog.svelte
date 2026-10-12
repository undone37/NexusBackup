<script lang="ts">
  // Pause a group / put a source into maintenance (Phase 13b): for N days or until resumed.
  import { t } from '../lib/i18n';
  import Modal from './Modal.svelte';

  let {
    open = $bindable(false),
    title,
    hint,
    submit,
    onsubmit,
  }: { open?: boolean; title: string; hint: string; submit: string; onsubmit: (until: number | null) => void } = $props();

  const CHOICES = [1, 3, 7, 14, 30];
  let days: number | 0 = $state(1);
  $effect(() => {
    if (open) days = 1;
  });

  function go(e: SubmitEvent) {
    e.preventDefault();
    onsubmit(days ? Math.floor(Date.now() / 1000) + days * 86400 : null);
  }
</script>

<Modal bind:open {title}>
  <form onsubmit={go}>
    <p class="muted">{hint}</p>
    <div class="field">
      <label for="pause-for">{t.runctl.pauseFor}</label>
      <select id="pause-for" bind:value={days}>
        {#each CHOICES as n (n)}<option value={n}>{t.runctl.pauseDays(n)}</option>{/each}
        <option value={0}>{t.runctl.pauseIndefinitely}</option>
      </select>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{submit}</button>
    </div>
  </form>
</Modal>
