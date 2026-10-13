<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, act, errText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { fmtBytes } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { AnomalySettings } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';

  // Setting `anomaly` (Phase 13e, docs/storage-accounting.md); weakening goes through approval.
  const GIB = 2 ** 30;
  let cur: AnomalySettings | null = $state(null);
  let form = $state({ enabled: true, factor: 3, history: 14, floorGib: 1, notes: '' });
  let error: string | null = $state(null);
  const isAdmin = $derived(session.user?.role === 'admin');

  async function load() {
    try {
      cur = await get<AnomalySettings>('/settings/anomaly');
      form = {
        enabled: cur.enabled,
        factor: cur.factor,
        history: cur.history,
        floorGib: +(cur.floor_bytes / GIB).toFixed(2),
        notes: (cur.ransom_notes ?? []).join('\n'),
      };
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const body: AnomalySettings = {
      enabled: form.enabled,
      factor: Number(form.factor),
      history: Number(form.history),
      floor_bytes: Math.round(Number(form.floorGib) * GIB),
      ransom_notes: form.notes
        .split('\n')
        .map((x) => x.trim())
        .filter(Boolean),
    };
    if (await act(put('/settings/anomaly', body), t.saved)) load();
  }
</script>

<ErrorBanner {error} />
{#if !cur}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  <section class="card settings-section" aria-labelledby="an-h">
    <div class="card-head">
      <h2 id="an-h">{t.settings.tabs.anomaly}</h2>
      <span class="chip {cur.enabled ? 'ok' : 'warn'}">{cur.enabled ? t.quorum.on : t.quorum.off}</span>
    </div>
    <p>{t.storage.anomaly.intro}</p>
    <p class="muted">{t.storage.anomaly.rule(cur.factor, cur.history, fmtBytes(cur.floor_bytes))}</p>
    <p class="muted">{t.storage.anomaly.fileSignals}</p>
    <form onsubmit={save}>
      <fieldset disabled={!isAdmin}>
        <div class="field">
          <label class="inline-check"><input type="checkbox" bind:checked={form.enabled} />{t.storage.anomaly.enabled}</label>
        </div>
        <div class="form-grid">
          <div class="field">
            <label for="an-f">{t.storage.anomaly.factor}</label>
            <input id="an-f" type="number" min="1.5" max="100" step="0.5" bind:value={form.factor} required />
          </div>
          <div class="field">
            <label for="an-n">{t.storage.anomaly.history}</label>
            <input id="an-n" type="number" min="5" max="100" step="1" bind:value={form.history} required />
          </div>
          <div class="field">
            <label for="an-g">{t.storage.anomaly.floor}</label>
            <input id="an-g" type="number" min="0.001" step="any" bind:value={form.floorGib} required />
          </div>
        </div>
        <div class="field">
          <label for="an-notes">{t.storage.anomaly.notes}</label>
          <textarea id="an-notes" class="mono" rows="4" bind:value={form.notes} aria-describedby="an-notes-hint"></textarea>
          <div class="hint" id="an-notes-hint">{t.storage.anomaly.notesHint}</div>
        </div>
      </fieldset>
      {#if isAdmin}
        <p class="hint">{t.storage.anomaly.quorumHint}</p>
        <div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>
      {:else}
        <p class="hint">{t.settings.readOnly}</p>
      {/if}
    </form>
  </section>
{/if}
