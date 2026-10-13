<script lang="ts">
  // Phase 21a: restore / hold dialogs opened on a flagged snapshot default to the latest clean
  // snapshot before it; this notice says so and switches between the two.
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Snapshot } from '../lib/types';

  let {
    flagged,
    clean,
    using,
    onswitch,
  }: {
    /** the snapshot the dialog was opened on (anomalous) */
    flagged: Snapshot;
    /** latest clean snapshot before it, null = none kept */
    clean: Snapshot | null;
    /** the one the dialog acts on */
    using: Snapshot;
    onswitch: (s: Snapshot) => void;
  } = $props();
  const reason = $derived(flagged.anomaly?.reason ?? '');
</script>

<div class="banner warn" role="status">
  {#if !clean}
    {t.snap.flaggedNoClean(fmtTime(flagged.time), reason)}
  {:else if using.time === clean.time}
    {t.snap.flaggedUsingClean(fmtTime(flagged.time), reason, fmtTime(clean.time))}
    <button type="button" class="small" onclick={() => onswitch(flagged)}>{t.snap.useFlagged}</button>
  {:else}
    {t.snap.flaggedUsingFlagged(fmtTime(flagged.time), reason)}
    <button type="button" class="small" onclick={() => onswitch(clean)}>{t.snap.useClean}</button>
  {/if}
</div>
