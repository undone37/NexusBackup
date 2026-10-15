<script lang="ts">
  // Daily windows: start days, from/to (a time zone given by the caller).
  // mode blackout: policy blackout windows (13b, with "abort");
  // mode rate: bandwidth windows (17a, pause or limit with a rate);
  // mode span: replication sync window (17a, days and times only);
  // mode limit: read-limit windows of a source (22b, limit with a rate only, no pause).
  import { t } from '../lib/i18n';
  import { DAYS, type BlackoutWindow, type RateWindow, type Span } from '../lib/schedule';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconX from '@lucide/svelte/icons/x';

  type Mode = 'blackout' | 'rate' | 'span' | 'limit';
  type W = Span & Partial<BlackoutWindow> & Partial<RateWindow>;
  let {
    windows = $bindable([]),
    mode = 'blackout',
    legend,
    hint,
    idp = 'bw',
  }: { windows?: W[]; mode?: Mode; legend?: string; hint?: string; idp?: string } = $props();
  const fresh = (): W =>
    mode === 'rate'
      ? { days: [], from: '08:00', to: '18:00', action: 'pause' }
      : mode === 'limit'
        ? { days: [], from: '08:00', to: '18:00', action: 'limit', rate_bytes: 50e6 }
        : mode === 'span'
          ? { days: [], from: '22:00', to: '06:00' }
          : { days: [], from: '08:00', to: '18:00', abort: false };
  const add = () => (windows = [...windows, fresh()]);
  const remove = (i: number) => (windows = windows.filter((_, j) => j !== i));
  // rates are edited in MB/s, stored in bytes per second
  const mbps = (w: W) => (w.rate_bytes ? w.rate_bytes / 1e6 : '');
  function setRate(w: W, v: string) {
    w.rate_bytes = v ? Math.round(Number(v) * 1e6) || undefined : undefined;
  }
  function setAction(w: W, a: string) {
    w.action = a as RateWindow['action'];
    if (a === 'pause') delete w.rate_bytes;
  }
</script>

<fieldset class="field">
  <legend>{legend ?? t.runctl.blackout}</legend>
  <p class="hint">{hint ?? t.runctl.blackoutHint}</p>
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
          <label for="{idp}-from-{i}">{t.runctl.from}</label>
          <input id="{idp}-from-{i}" type="time" bind:value={w.from} required />
        </div>
        <div class="field">
          <label for="{idp}-to-{i}">{t.runctl.to}</label>
          <input id="{idp}-to-{i}" type="time" bind:value={w.to} required />
        </div>
        {#if mode === 'limit'}
          <div class="field">
            <label for="{idp}-rate-{i}">{t.windows.rate}</label>
            <input
              id="{idp}-rate-{i}"
              type="number"
              min="0.01"
              step="any"
              required
              value={mbps(w)}
              oninput={(e) => setRate(w, e.currentTarget.value)}
            />
          </div>
        {:else if mode === 'rate'}
          <div class="field">
            <label for="{idp}-act-{i}">{t.windows.action}</label>
            <select id="{idp}-act-{i}" value={w.action} onchange={(e) => setAction(w, e.currentTarget.value)}>
              <option value="pause">{t.windows.pause}</option>
              <option value="limit">{t.windows.limit}</option>
            </select>
          </div>
          {#if w.action === 'limit'}
            <div class="field">
              <label for="{idp}-rate-{i}">{t.windows.rate}</label>
              <input
                id="{idp}-rate-{i}"
                type="number"
                min="0.01"
                step="any"
                required
                value={mbps(w)}
                oninput={(e) => setRate(w, e.currentTarget.value)}
              />
            </div>
          {/if}
        {/if}
      </div>
      <div class="row">
        {#if mode === 'blackout'}
          <label class="inline-check"><input type="checkbox" bind:checked={w.abort} />{t.runctl.abort}</label>
        {:else}
          <span></span>
        {/if}
        <button type="button" class="small icon-text" onclick={() => remove(i)}
          ><IconX aria-hidden="true" />{t.runctl.removeWindow}</button
        >
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
