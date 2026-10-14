<script lang="ts">
  // Phase 29: the result of a `scan_back` job: the scanned snapshots (newest first, one
  // `snapshot_scan` job each) and the recommended restore point (the first complete, clean one).
  import { fmtTime } from '../lib/format';
  import { href } from '../lib/router.svelte';
  import { qs } from '../lib/api';
  import { t } from '../lib/i18n';
  import type { ScanBackResult } from '../lib/types';

  let { result, tenant }: { result: ScanBackResult; tenant: string } = $props();
  const verdict = (x: ScanBackResult['scanned'][number]) =>
    x.matches_total
      ? { cls: 'bad', text: x.stopped ? t.p29.scanBack.stopped(1) : t.p29.scanBack.stopped(x.matches_total) }
      : x.complete
        ? { cls: 'ok', text: t.p29.scanBack.clean }
        : { cls: 'warn', text: t.p29.scanBack.incomplete };
</script>

{#if result.recommended !== null}
  <p class="banner ok" role="status">
    <span
      ><strong>{t.p29.scanBack.recommended(fmtTime(result.recommended))}</strong>
      <a href={href('/snapshots' + qs({ tenant, source: result.source }))}>{t.p29.scanBack.showList}</a></span
    >
  </p>
{:else}
  <p class="banner error" role="status">{t.p29.scanBack.noneClean}</p>
{/if}
{#if result.truncated}<p class="banner warn">{t.p29.scanBack.truncated}</p>{/if}
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th scope="col">{t.p29.scanBack.snapshot}</th>
        <th scope="col">{t.p29.scanBack.verdict}</th>
        <th scope="col">{t.p29.scanBack.scanJob}</th>
      </tr>
    </thead>
    <tbody>
      {#each result.scanned as x (x.time)}
        {@const v = verdict(x)}
        <tr>
          <td class="nowrap">
            {fmtTime(x.time)}
            {#if x.time === result.recommended}<span class="chip ok plain">{t.p29.scanBack.badge}</span>{/if}
          </td>
          <td><span class="chip {v.cls}">{v.text}</span></td>
          <td><a href={href(`/jobs/${x.job}`)}>{t.p29.scanBack.openJob(x.job)}</a></td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
