<script lang="ts">
  import { get, errText, qs } from '../lib/api';
  import { fmtTime, fmtDuration } from '../lib/format';
  import { href } from '../lib/router.svelte';
  import { t } from '../lib/i18n';
  import type { Snapshot, SnapshotScan } from '../lib/types';
  import Modal from './Modal.svelte';
  import ErrorBanner from './ErrorBanner.svelte';

  // YARA scans of one snapshot (Phase 21e, GET /scans), newest first, with the matches.
  let { open = $bindable(false), snap }: { open?: boolean; snap: Snapshot | null } = $props();
  let scans: SnapshotScan[] = $state([]);
  let error: string | null = $state(null);
  let loading = $state(false);

  $effect(() => {
    if (!open || !snap) return;
    const s = snap;
    loading = true;
    get<SnapshotScan[]>('/scans' + qs({ tenant: s.tenant, source: s.source, time: s.time }))
      .then((x) => ((scans = x), (error = null)))
      .catch((e) => (error = errText(e)))
      .finally(() => (loading = false));
  });
</script>

<Modal bind:open title={snap ? t.scan.resultsTitle(snap.source, fmtTime(snap.time)) : ''} wide>
  <ErrorBanner {error} />
  {#if loading}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if !scans.length}
    <p class="empty">{t.scan.none}</p>
  {:else}
    {#each scans as s (s.job)}
      <section class="scan" aria-label={t.scan.scanOf(fmtTime(s.finished))}>
        <p>
          <span class="chip {s.matches_total ? 'bad' : s.complete ? 'ok' : 'warn'}"
            >{s.matches_total ? t.scan.hits(s.matches_total) : s.complete ? t.scan.clean : t.scan.incomplete}</span
          >
          <span class="muted">{t.scan.summary(fmtTime(s.finished), s.files, s.skipped, s.errors)}</span>
          <a href={href(`/jobs/${s.job}`)}>{t.scan.job(s.job)}</a>
        </p>
        <p class="muted small mono">{t.scan.rulesUsed(s.rules)}</p>
        {#if s.matches.length}
          <div class="table-wrap">
            <table>
              <thead><tr><th scope="col">{t.scan.rule}</th><th scope="col">{t.scan.path}</th></tr></thead>
              <tbody>
                {#each s.matches as m, i (i)}
                  <tr><td class="mono">{m.rule}</td><td class="mono">{m.path}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if s.matches_total > s.matches.length}<p class="hint">
              {t.scan.moreMatches(s.matches_total - s.matches.length)}
            </p>{/if}
        {/if}
      </section>
    {/each}
  {/if}
  <p class="hint">{t.scan.resultsHint(fmtDuration(4 * 3600))}</p>
</Modal>

<style>
  .scan + .scan {
    border-top: 1px solid var(--border);
    padding-top: 0.75rem;
  }
</style>
