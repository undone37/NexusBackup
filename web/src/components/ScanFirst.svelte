<script lang="ts">
  import { t } from '../lib/i18n';
  import type { ScanFirst } from '../lib/types';

  // Restore option "scan first" (Phase 21e): a YARA scan of the snapshot in the restore
  // micro-VM before the restore runs; on a hit the restore is refused or (guest restores)
  // runs with every network card of the new guest disconnected.
  let { value = $bindable(''), linkDown = false }: { value?: ScanFirst | ''; linkDown?: boolean } = $props();
  const id = $props.id();
</script>

<div class="field">
  <label for="{id}-scan">{t.scan.first}</label>
  <select id="{id}-scan" bind:value aria-describedby="{id}-scan-hint">
    <option value="">{t.scan.firstOff}</option>
    <option value="refuse">{t.scan.firstRefuse}</option>
    {#if linkDown}<option value="link_down">{t.scan.firstLinkDown}</option>{/if}
  </select>
  <div class="hint" id="{id}-scan-hint">{t.scan.firstHint}</div>
</div>
