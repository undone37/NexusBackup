<script lang="ts">
  // Phase 29: "scan back to the last clean snapshot" (POST /snapshots/{tenant}/{source}/{time}/scan-back):
  // YARA scans of the source's snapshots from `time` backwards until one is complete and clean; the
  // dialog follows the job and shows the scanned snapshots and the recommended restore point.
  import { onDestroy } from 'svelte';
  import { labelOf } from '../lib/names.svelte';
  import { get, post, errText } from '../lib/api';
  import { terminal } from '../lib/jobs';
  import { href } from '../lib/router.svelte';
  import { notify } from '../lib/notify.svelte';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Job, ScanBackResult as Result } from '../lib/types';
  import Modal from './Modal.svelte';
  import ScanBackResult from './ScanBackResult.svelte';

  let {
    open = $bindable(false),
    tenant,
    source,
    time,
    ondone,
  }: { open?: boolean; tenant: string; source: string; time: number; ondone?: () => void } = $props();

  let budget = $state('');
  let max = $state('');
  let busy = $state(false);
  let error: string | null = $state(null);
  let job: Job | null = $state(null);
  let stop = false;
  onDestroy(() => (stop = true));

  let wasOpen = false;
  $effect(() => {
    if (open && !wasOpen) {
      budget = max = '';
      error = null;
      job = null;
      busy = false;
    }
    wasOpen = open;
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      const body: Record<string, number> = {};
      if (String(budget ?? '').trim()) body.budget_min = Number(budget);
      if (String(max ?? '').trim()) body.max = Number(max);
      const path = `/snapshots/${encodeURIComponent(tenant)}/${encodeURIComponent(source)}/${time}/scan-back`;
      const o = await post<{ id: number }>(path, body);
      const id = o.data.id;
      if (id === undefined) return;
      notify('ok', t.p29.scanBack.started(id));
      for (;;) {
        job = await get<Job>(`/jobs/${id}`);
        if (terminal(job.state) || stop || !open) break;
        await new Promise((r) => setTimeout(r, 800));
      }
      if (job.state !== 'ok') error = t.p29.scanBack.failed;
      ondone?.();
    } catch (x) {
      error = errText(x);
    } finally {
      busy = false;
    }
  }
  const result = $derived.by(() => {
    const j = job as Job | null;
    return (j?.state === 'ok' ? j.result : null) as Result | null;
  });
</script>

<Modal bind:open title={t.p29.scanBack.title(labelOf(tenant, source))} wide>
  <p class="muted">{tenant} · {t.p29.scanBack.from(fmtTime(time))}</p>
  {#if error}<p class="banner error" role="alert">{error}</p>{/if}
  {#if result?.scanned}
    <ScanBackResult {result} {tenant} />
    {#if job}<p><a href={href(`/jobs/${job.id}`)}>{t.p29.scanBack.openJob(job.id)}</a></p>{/if}
    <div class="form-actions"><button type="button" onclick={() => (open = false)}>{t.close}</button></div>
  {:else}
    <form onsubmit={submit}>
      <p>{t.p29.scanBack.intro}</p>
      <div class="form-grid">
        <div class="field">
          <label for="sb-budget">{t.p29.scanBack.budget}</label>
          <input
            id="sb-budget"
            type="number"
            min="1"
            max="1440"
            bind:value={budget}
            aria-describedby="sb-budget-hint"
          />
          <div class="hint" id="sb-budget-hint">{t.p29.scanBack.budgetHint}</div>
        </div>
        <div class="field">
          <label for="sb-max">{t.p29.scanBack.max}</label>
          <input id="sb-max" type="number" min="1" max="100" bind:value={max} aria-describedby="sb-max-hint" />
          <div class="hint" id="sb-max-hint">{t.p29.scanBack.maxHint}</div>
        </div>
      </div>
      {#if job && busy}<p class="muted" aria-busy="true">
          {t.p29.scanBack.running} <a href={href(`/jobs/${job.id}`)}>{t.p29.scanBack.openJob(job.id)}</a>
        </p>{/if}
      <div class="form-actions">
        <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}>{t.p29.scanBack.start}</button>
      </div>
    </form>
  {/if}
</Modal>
