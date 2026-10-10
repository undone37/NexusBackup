<script lang="ts">
  import Modal from './Modal.svelte';
  import { pending, answer } from '../lib/confirm.svelte';
  import { t } from '../lib/i18n';

  const id = $props.id();
  let open = $state(false);
  $effect(() => {
    open = pending.resolve !== null;
  });
  // closed via Esc / ×: counts as "no"
  $effect(() => {
    if (!open && pending.resolve) answer(false);
  });
</script>

<Modal bind:open title={pending.input === null ? t.confirmTitle : t.inputTitle}>
  <form
    onsubmit={(e) => {
      e.preventDefault();
      answer(true);
    }}
  >
    {#if pending.input === null}
      <p>{pending.text}</p>
    {:else}
      <div class="field">
        <label for="{id}-in">{pending.text}</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input id="{id}-in" class="mono" bind:value={pending.input} autocomplete="off" spellcheck="false" autofocus />
      </div>
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => answer(false)}>{t.cancel}</button>
      <button type="submit" class="primary">{pending.input === null ? t.confirmOk : t.ok}</button>
    </div>
  </form>
</Modal>
