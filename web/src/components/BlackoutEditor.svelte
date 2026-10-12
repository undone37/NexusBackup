<script lang="ts">
  // Blackout windows of a policy (Phase 13b): start days, from/to (group time zone), abort.
  import { t } from '../lib/i18n';
  import { DAYS, type BlackoutWindow } from '../lib/schedule';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconX from '@lucide/svelte/icons/x';

  let { windows = $bindable([]) }: { windows?: BlackoutWindow[] } = $props();
  const add = () => (windows = [...windows, { days: [], from: '08:00', to: '18:00', abort: false }]);
  const remove = (i: number) => (windows = windows.filter((_, j) => j !== i));
</script>

<fieldset class="field">
  <legend>{t.runctl.blackout}</legend>
  <p class="hint">{t.runctl.blackoutHint}</p>
  {#each windows as w, i (i)}
    <div class="window">
      <div class="days" role="group" aria-label="{t.runctl.days} {i + 1}">
        {#each DAYS as d (d)}
          <label class="inline-check"><input type="checkbox" value={d} bind:group={w.days} />{d}</label>
        {/each}
        {#if !w.days.length}<span class="hint">{t.runctl.everyDay}</span>{/if}
      </div>
      <div class="form-grid">
        <div class="field">
          <label for="bw-from-{i}">{t.runctl.from}</label>
          <input id="bw-from-{i}" type="time" bind:value={w.from} required />
        </div>
        <div class="field">
          <label for="bw-to-{i}">{t.runctl.to}</label>
          <input id="bw-to-{i}" type="time" bind:value={w.to} required />
        </div>
      </div>
      <div class="row">
        <label class="inline-check"><input type="checkbox" bind:checked={w.abort} />{t.runctl.abort}</label>
        <button type="button" class="small icon-text" onclick={() => remove(i)}><IconX aria-hidden="true" />{t.runctl.removeWindow}</button>
      </div>
    </div>
  {/each}
  <button type="button" class="small" onclick={add}><IconPlus aria-hidden="true" />{t.runctl.addWindow}</button>
</fieldset>

<style>
  .window {
    border: 1px solid var(--border);
    border-radius: var(--radius-s);
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.5rem;
  }
  .days {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem 1rem;
    margin-bottom: 0.25rem;
  }
  .row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }
</style>
