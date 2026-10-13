<script lang="ts">
  // Phase 29: a production restore of a flagged snapshot (anomaly or malware scan hit, not cleared)
  // needs approval `restore.infected` (approvals off: administrators only). The notice says so and
  // offers the isolated variants the dialog supports (network disconnected / another path).
  import { t } from '../lib/i18n';
  import type { Snapshot } from '../lib/types';

  let {
    snap,
    production,
    onisolateNet,
    onisolatePath,
  }: {
    snap: Pick<Snapshot, 'flagged' | 'anomalous' | 'scan_state'> | null;
    /** the dialog's current options make it a production restore */
    production: boolean;
    onisolateNet?: () => void;
    onisolatePath?: () => void;
  } = $props();

  const flagged = $derived(!!snap && (snap.flagged ?? (!!snap.anomalous || snap.scan_state === 'hit')));
</script>

{#if flagged && production}
  <div class="banner warn infected" role="status">
    <p><strong>{t.p29.infected.notice}</strong></p>
    <p class="small">{t.p29.infected.what}</p>
    {#if onisolateNet || onisolatePath}
      <p>
        {t.p29.infected.isolated}
        {#if onisolateNet}<button type="button" class="small" onclick={onisolateNet}>{t.p29.infected.isolateNet}</button>{/if}
        {#if onisolatePath}<button type="button" class="small" onclick={onisolatePath}>{t.p29.infected.isolatePath}</button>{/if}
      </p>
    {/if}
  </div>
{:else if flagged}
  <p class="hint">{t.p29.infected.ok}</p>
{/if}

<style>
  .infected {
    flex-direction: column;
    align-items: stretch;
    gap: 0.35rem;
  }
  .infected p {
    margin: 0;
  }
  .infected button {
    margin-left: 0.4rem;
  }
  .small {
    font-size: 0.85rem;
  }
</style>
