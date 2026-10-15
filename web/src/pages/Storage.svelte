<script lang="ts">
  import { onMount } from 'svelte';
  import { rowLink } from '../lib/rowlink';
  import { href } from '../lib/router.svelte';
  import { get, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { fmtAgo, fmtBytes, fmtPct, fmtRatio, fmtTime } from '../lib/format';
  import { can } from '../lib/roles';
  import { t } from '../lib/i18n';
  import type { IndexStatus, Storage, StorageGrowth } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import KpiTile from '../components/KpiTile.svelte';
  import TrendLine from '../components/charts/TrendLine.svelte';
  import HBars from '../components/charts/HBars.svelte';
  import UsageSection from '../components/UsageSection.svelte';
  import IconLayers from '@lucide/svelte/icons/layers';
  import IconIn from '@lucide/svelte/icons/arrow-down-to-line';
  import IconDisk from '@lucide/svelte/icons/hard-drive';
  import IconSaved from '@lucide/svelte/icons/piggy-bank';

  // GET /storage (docs/storage-accounting.md): Logical / Data in / Stored / Saved per tenant and group.
  let data = $state<Storage | null>(null);
  let error: string | null = $state(null);
  // Phase 31b: the file search index (GET /files/index-status), for the roles that may search
  let index = $state<IndexStatus | null>(null);
  onMount(async () => {
    if (can.search(session.user))
      get<IndexStatus>('/files/index-status')
        .then((x) => (index = x))
        .catch(() => {
          /* no index section */
        });
    try {
      data = await get<Storage>('/storage');
    } catch (e) {
      error = `${t.storage.loadFailed} (${errText(e)})`;
    }
  });
  const tot = $derived(data?.totals);
  const multi = $derived(!session.user?.tenant);
  const growth = (g: StorageGrowth, k: keyof StorageGrowth) =>
    g[k] === null ? '—' : `${(g[k] as number) >= 0 ? '+' : '−'}${fmtBytes(Math.abs(g[k] as number))}`;
  const groupName = (g: Storage['groups'][number]) => g.group ?? t.storage.ungrouped;
  const byStored = $derived(
    (data?.groups ?? [])
      .filter((g) => g.stored > 0)
      .sort((a, b) => b.stored - a.stored)
      .slice(0, 8)
      .map((g) => ({ label: multi ? `${g.tenant}: ${groupName(g)}` : groupName(g), value: g.stored })),
  );
</script>

<div class="page-head">
  <h1>{t.storage.title}</h1>
  {#if data}<span class="stamp">{t.dash.updated(fmtTime(data.generated))}</span>{/if}
  <p class="lede">{t.storage.lede}</p>
</div>
<ErrorBanner {error} />

{#if data && tot}
  <section class="kpis" aria-label={t.storage.title}>
    <KpiTile icon={IconLayers} label={t.storage.logical} value={fmtBytes(tot.logical)} sub={t.storage.logicalHint} />
    <KpiTile
      icon={IconIn}
      label={t.storage.dataIn}
      value={fmtBytes(tot.data_in)}
      sub={`${t.storage.dedup} ${fmtRatio(tot.dedup)}`}
    />
    <KpiTile
      icon={IconDisk}
      label={t.storage.stored}
      value={fmtBytes(tot.stored)}
      sub={`${t.storage.compression} ${fmtRatio(tot.compression)}`}
    />
    <KpiTile
      icon={IconSaved}
      label={t.storage.saved}
      value={fmtBytes(tot.saved)}
      sub={`${t.storage.reduction} ${fmtRatio(tot.reduction)}`}
    />
  </section>

  <div class="dash-grid">
    <section class="card span-8" aria-labelledby="s-trend">
      <div class="card-head">
        <div>
          <h2 id="s-trend">{t.storage.trend}</h2>
          <div class="sub">{t.storage.trendSub}</div>
        </div>
        <span
          class="chip plain"
          title={`${t.storage.growthN(7)} ${growth(tot.growth, 'd7')} · ${t.storage.growthN(90)} ${growth(tot.growth, 'd90')}`}
          >{t.storage.growthChip(growth(tot.growth, 'd30'))}</span
        >
      </div>
      <TrendLine data={data.per_day} total={0} forecastDays={null} title={t.storage.trend} />
    </section>
    <section class="card span-4" aria-labelledby="s-groups">
      <div class="card-head">
        <div>
          <h2 id="s-groups">{t.storage.perGroup}</h2>
          <div class="sub">{t.storage.stored}</div>
        </div>
      </div>
      {#if byStored.length}
        <HBars title={t.storage.perGroup} items={byStored} fmt={fmtBytes} tone="neutral" />
      {:else}
        <p class="empty">{t.storage.empty}</p>
      {/if}
    </section>
  </div>

  <section class="card" aria-labelledby="s-tenants">
    <h2 id="s-tenants">{t.storage.perTenant}</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.tenant}</th>
            <th scope="col" class="num" title={t.storage.usedHint}>{t.storage.used}</th>
            <th scope="col">{t.storage.quota}</th>
            <th scope="col" class="num" title={t.storage.logicalHint}>{t.storage.logical}</th>
            <th scope="col" class="num" title={t.storage.dataInHint}>{t.storage.dataIn}</th>
            <th scope="col" class="num" title={t.storage.storedHint}>{t.storage.stored}</th>
            <th scope="col" class="num">{t.storage.dedup}</th>
            <th scope="col" class="num">{t.storage.compression}</th>
            <th scope="col" class="num">{t.storage.growth} 7 / 30 / 90</th>
          </tr>
        </thead>
        <tbody>
          {#each data.tenants as x (x.tenant)}
            <tr use:rowLink={`/snapshots?tenant=${encodeURIComponent(x.tenant)}`}>
              <th scope="row"
                ><a href={href(`/snapshots?tenant=${encodeURIComponent(x.tenant)}`)} title={t.storage.tenantSnapshots}
                  >{x.tenant}</a
                ></th
              >
              <td class="num">{fmtBytes(x.used)}</td>
              <td class="nowrap">
                {#if x.quota_bytes}
                  <span class="chip {(x.quota_used ?? 0) >= 1 ? 'bad' : (x.quota_used ?? 0) >= 0.8 ? 'warn' : 'plain'}"
                    >{fmtPct(x.quota_used, 0)}</span
                  >
                  <span class="muted">{t.storage.quotaOf(fmtBytes(x.used), fmtBytes(x.quota_bytes))}</span>
                {:else}<span class="muted">{t.storage.noQuota}</span>{/if}
              </td>
              <td class="num">{fmtBytes(x.logical)}</td>
              <td class="num">{fmtBytes(x.data_in)}</td>
              <td class="num">{fmtBytes(x.stored)}</td>
              <td class="num">{fmtRatio(x.dedup)}</td>
              <td class="num">{fmtRatio(x.compression)}</td>
              <td class="num nowrap"
                >{growth(x.growth, 'd7')} / {growth(x.growth, 'd30')} / {growth(x.growth, 'd90')}</td
              >
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  <section class="card" aria-labelledby="s-group-table">
    <h2 id="s-group-table">{t.storage.perGroup}</h2>
    {#if data.groups.length === 0}
      <p class="empty">{t.storage.empty}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              {#if multi}<th scope="col">{t.tenant}</th>{/if}
              <th scope="col">{t.storage.group}</th>
              <th scope="col" class="num">{t.storage.sources}</th>
              <th scope="col" class="num">{t.storage.snapshots}</th>
              <th scope="col" class="num">{t.storage.logical}</th>
              <th scope="col" class="num">{t.storage.dataIn}</th>
              <th scope="col" class="num">{t.storage.stored}</th>
              <th scope="col" class="num">{t.storage.dedup}</th>
              <th scope="col" class="num">{t.storage.compression}</th>
            </tr>
          </thead>
          <tbody>
            {#each data.groups as g (`${g.tenant}/${g.group_id}`)}
              <tr>
                {#if multi}<td>{g.tenant}</td>{/if}
                <th scope="row" class:muted={g.group_id === null}>{groupName(g)}</th>
                <td class="num">{g.sources}</td>
                <td class="num">{g.snapshots}</td>
                <td class="num">{fmtBytes(g.logical)}</td>
                <td class="num">{fmtBytes(g.data_in)}</td>
                <td class="num">{fmtBytes(g.stored)}</td>
                <td class="num">{fmtRatio(g.dedup)}</td>
                <td class="num">{fmtRatio(g.compression)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <p class="hint">{t.storage.coverage(tot.snapshots, tot.snapshots_all)} {t.storage.approx}</p>
  </section>

  {#if index}
    <section class="card" aria-labelledby="s-index">
      <div class="card-head">
        <div>
          <h2 id="s-index">{t.storage.index}</h2>
          <div class="sub">{t.storage.indexSub}</div>
        </div>
      </div>
      {#if !index.available}
        <p class="banner warn">{t.storage.indexDown}</p>
      {:else}
        {#if index.paused}
          <p class="banner warn">{t.storage.indexPaused(fmtBytes(index.free_bytes), fmtBytes(index.floor_bytes))}</p>
        {/if}
        <div class="table-wrap">
          <table id="s-index-table">
            <thead>
              <tr>
                <th scope="col">{t.tenant}</th>
                <th scope="col" class="num">{t.storage.indexSize}</th>
                <th scope="col" class="num">{t.storage.indexDocs}</th>
                <th scope="col" class="num">{t.storage.indexSources}</th>
                <th scope="col" class="num">{t.storage.indexIndexed}</th>
                <th scope="col" class="num">{t.storage.indexPending}</th>
                <th scope="col" class="num">{t.storage.indexUnindexed}</th>
                <th scope="col">{t.storage.indexLastSync}</th>
              </tr>
            </thead>
            <tbody>
              {#each index.tenants ?? [] as x (x.tenant)}
                <tr>
                  <th scope="row">{x.tenant}</th>
                  <td class="num">{fmtBytes(x.bytes)}</td>
                  <td class="num">{x.docs.toLocaleString('en-US')}</td>
                  <td class="num">{x.sources}</td>
                  <td class="num">{x.snapshots_indexed}</td>
                  <td class="num"
                    >{#if x.snapshots_pending}<span class="chip warn plain">{x.snapshots_pending}</span>
                      {#if x.oldest_pending}<div class="muted small">
                          {t.storage.indexOldest(fmtAgo(x.oldest_pending))}
                        </div>{/if}{:else}0{/if}</td
                  >
                  <td class="num">{x.snapshots_unindexed}</td>
                  <td class="nowrap"
                    >{fmtAgo(x.last_sync)}{#if x.error}<div>
                        <span class="chip bad" title={x.error}>{x.error}</span>
                      </div>{/if}</td
                  >
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <p class="hint">
          {t.storage.indexFree(
            fmtBytes(index.free_bytes),
            fmtBytes(index.floor_bytes),
            fmtBytes(index.cache_bytes),
            fmtBytes(index.cache_limit),
          )}
          {t.storage.indexHint}
        </p>
      {/if}
    </section>
  {/if}

  <UsageSection />
{:else if !error}
  <p class="muted" aria-busy="true">{t.loading}</p>
{/if}
