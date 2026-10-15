<script lang="ts">
  // Monthly usage per tenant for billing (Phase 23a, GET /usage): objects, logical / measured
  // stored / offsite bytes as daily average and peak; CSV download of the same table.
  import { API, get, errText, qs } from '../lib/api';
  import { fmtBytes } from '../lib/format';
  import { session } from '../lib/session.svelte';
  import { t } from '../lib/i18n';
  import type { Usage } from '../lib/types';
  import IconDownload from '@lucide/svelte/icons/download';

  const id = $props.id();
  let month = $state(new Date().toISOString().slice(0, 7));
  let data: Usage | null = $state(null);
  let error: string | null = $state(null);
  const multi = $derived(!session.user?.tenant);

  $effect(() => {
    const m = month;
    if (!/^\d{4}-\d{2}$/.test(m)) return;
    get<Usage>(`/usage${qs({ month: m })}`)
      .then((u) => {
        data = u;
        error = null;
      })
      .catch((e) => {
        data = null;
        error = errText(e);
      });
  });
  const csv = $derived(`${API}/usage${qs({ month, format: 'csv' })}`);
  const pair = (avg: number | null, peak: number | null) =>
    avg === null ? '—' : `${fmtBytes(avg)} / ${fmtBytes(peak)}`;
</script>

<section class="card" aria-labelledby="usage-h">
  <div class="card-head">
    <div>
      <h2 id="usage-h">{t.sp.usage.title}</h2>
      <div class="sub">{t.sp.usage.sub}</div>
    </div>
    <div class="usage-tools">
      <label for="{id}-m" class="visually-hidden">{t.sp.usage.month}</label>
      <input id="{id}-m" type="month" bind:value={month} max={new Date().toISOString().slice(0, 7)} />
      <a class="button small" href={csv} download><IconDownload aria-hidden="true" />{t.reports.download}</a>
    </div>
  </div>
  {#if error}
    <p class="banner error">{error}</p>
  {:else if !data}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else}
    {#if !data.complete}<p class="hint">{t.sp.usage.running}</p>{/if}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            {#if multi}<th scope="col">{t.tenant}</th>{/if}
            <th scope="col" class="num" title={t.sp.usage.objectsHint}>{t.sp.usage.objects}</th>
            <th scope="col" class="num">{t.sp.usage.backups}</th>
            <th scope="col" class="num" title={t.storage.logicalHint}>{t.sp.usage.logical}</th>
            <th scope="col" class="num" title={t.storage.usedHint}>{t.sp.usage.stored}</th>
            <th scope="col" class="num" title={t.sp.usage.offsiteHint}>{t.sp.usage.offsite}</th>
            <th scope="col" class="num">{t.sp.usage.days}</th>
          </tr>
        </thead>
        <tbody>
          {#each data.tenants as u (u.tenant)}
            <tr>
              {#if multi}<th scope="row">{u.tenant}</th>{/if}
              <td class="num">{u.objects}</td>
              <td class="num">{u.backups}</td>
              <td class="num nowrap">{pair(u.logical_avg, u.logical_peak)}</td>
              <td class="num nowrap">{pair(u.stored_avg, u.stored_peak)}</td>
              <td class="num nowrap">{pair(u.offsite_avg, u.offsite_peak)}</td>
              <td class="num">{u.days_sampled}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="hint">{t.sp.usage.hint}</p>
  {/if}
</section>

<style>
  .usage-tools {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }
</style>
