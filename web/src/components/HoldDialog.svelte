<script lang="ts">
  // Legal hold (Phase 15c): one snapshot (Snapshots page, alerts) or every snapshot of a
  // tenant / guest in a time range (incident response). Security officers only; immediate.
  import { post, act } from '../lib/api';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { SnapshotRef } from '../lib/types';
  import Modal from './Modal.svelte';
  import type { Snippet } from 'svelte';

  let {
    open = $bindable(false),
    target = null,
    reason: initial = '',
    tenants = [],
    tenant: preset = '',
    sources = [],
    ondone,
    children,
  }: {
    open?: boolean;
    /** one snapshot; null = time range */
    target?: SnapshotRef | null;
    reason?: string;
    tenants?: string[];
    /** preselected tenant in range mode (e.g. the page filter) */
    tenant?: string;
    /** guest names offered in range mode */
    sources?: string[];
    ondone?: () => void;
    /** shown above the form (Phase 21a: the flagged-snapshot notice) */
    children?: Snippet;
  } = $props();

  const local = (ts: number) => {
    const d = new Date(ts * 1000);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  };
  let reason = $state('');
  let tenant = $state('');
  let source = $state('');
  let from = $state('');
  let to = $state('');
  let busy = $state(false);
  $effect(() => {
    if (!open) return;
    reason = initial;
    tenant = preset && tenants.includes(preset) ? preset : (tenants[0] ?? '');
    source = '';
    const now = Math.floor(Date.now() / 1000);
    from = local(now - 7 * 86400);
    to = local(now);
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    const r = reason.trim();
    const ok = target
      ? await act(
          post(
            `/snapshots/${encodeURIComponent(target.tenant)}/${encodeURIComponent(target.source)}/${target.time}/hold`,
            { reason: r },
          ),
          t.snap.holdSet,
        )
      : await act(
          post<{ held: number }>('/holds', {
            tenant,
            source: source.trim() || null,
            from: Math.floor(new Date(from).getTime() / 1000),
            to: Math.floor(new Date(to).getTime() / 1000) + 59,
            reason: r,
          }),
          (d) => t.snap.holdRangeSet(d.held),
        );
    busy = false;
    if (ok) {
      open = false;
      ondone?.();
    }
  }
</script>

<Modal bind:open title={target ? t.snap.holdTitle : t.snap.holdRangeTitle}>
  <form onsubmit={submit}>
    <p class="muted">{target ? t.snap.holdIntro : t.snap.holdRangeIntro}</p>
    {#if target}
      <p><span class="mono">{target.source}</span> · {target.tenant} · {fmtTime(target.time)}</p>
      {@render children?.()}
    {:else}
      <div class="form-grid two">
        <div class="field">
          <label for="hold-tenant">{t.tenant}</label>
          <select id="hold-tenant" bind:value={tenant} required>
            {#each tenants as tn (tn)}<option value={tn}>{tn}</option>{/each}
          </select>
        </div>
        <div class="field">
          <label for="hold-source">{t.snap.source}</label>
          <input
            id="hold-source"
            bind:value={source}
            list="hold-sources"
            placeholder={t.snap.allSources}
            autocomplete="off"
          />
          <datalist id="hold-sources"
            >{#each sources as s (s)}<option value={s}></option>{/each}</datalist
          >
        </div>
        <div class="field">
          <label for="hold-from">{t.snap.from}</label>
          <input id="hold-from" type="datetime-local" bind:value={from} required />
        </div>
        <div class="field">
          <label for="hold-to">{t.snap.to}</label>
          <input id="hold-to" type="datetime-local" bind:value={to} required />
        </div>
      </div>
    {/if}
    <div class="field">
      <label for="hold-reason">{t.snap.reason}</label>
      <input id="hold-reason" bind:value={reason} required maxlength="500" aria-describedby="hold-reason-hint" />
      <div class="hint" id="hold-reason-hint">{t.snap.reasonHint}</div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={busy || !reason.trim()}>{t.snap.holdSubmit}</button>
    </div>
  </form>
</Modal>

<style>
  .two {
    grid-template-columns: 1fr 1fr;
  }
  .two input {
    min-width: 0;
    width: 100%;
  }
</style>
