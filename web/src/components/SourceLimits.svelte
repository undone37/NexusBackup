<script lang="ts">
  // Phase 22b: concurrency caps (PVE only) and the appliance-side read limit of a source.
  import { t } from '../lib/i18n';
  import { timeZones } from '../lib/schedule';
  import type { LimitsForm } from '../lib/limits';
  import BlackoutEditor from './BlackoutEditor.svelte';

  let { form = $bindable(), pve = false }: { form: LimitsForm; pve?: boolean } = $props();
  const zones = timeZones();
</script>

<fieldset class="field limits">
  <legend>{t.limits.title}</legend>
  <p class="hint">{pve ? t.limits.hintPve : t.limits.hint}</p>
  <div class="form-grid">
    {#if pve}
      <div class="field">
        <label for="lim-par">{t.limits.maxParallel}</label>
        <input
          id="lim-par"
          type="number"
          min="1"
          max="8"
          placeholder={t.limits.noCap}
          bind:value={form.max_parallel}
          aria-describedby="lim-par-hint"
        />
        <div class="hint" id="lim-par-hint">{t.limits.maxParallelHint}</div>
      </div>
      <div class="field">
        <label for="lim-caps">{t.limits.storageCaps}</label>
        <textarea
          id="lim-caps"
          class="mono"
          rows="2"
          spellcheck="false"
          placeholder={'ceph-ssd=2'}
          bind:value={form.caps}
          aria-describedby="lim-caps-hint"></textarea>
        <div class="hint" id="lim-caps-hint">{t.limits.storageCapsHint}</div>
      </div>
    {/if}
    <div class="field">
      <label for="lim-rate">{t.limits.rate}</label>
      <input
        id="lim-rate"
        type="number"
        min="0.01"
        step="any"
        placeholder={t.limits.unlimited}
        bind:value={form.rate}
        aria-describedby="lim-rate-hint"
      />
      <div class="hint" id="lim-rate-hint">{t.limits.rateHint}</div>
    </div>
    {#if form.windows.length}
      <div class="field">
        <label for="lim-tz">{t.windows.timezone}</label>
        <select id="lim-tz" bind:value={form.tz}>
          {#each zones as z (z)}<option value={z}>{z}</option>{/each}
        </select>
      </div>
    {/if}
  </div>
  <BlackoutEditor
    bind:windows={form.windows}
    mode="limit"
    idp="lim-w"
    legend={t.limits.windows}
    hint={t.limits.windowsHint}
  />
</fieldset>

<style>
  .limits {
    grid-column: 1 / -1;
  }
</style>
