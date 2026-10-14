<script lang="ts">
  // Phase 29: Dashboard card "Change tracking": scheduled full reads that check whether the change
  // tracking (dirty bitmap, metadata cache, USN journal, zfs diff) reported every change.
  // Summary from GET /dashboard (`full_reads`), the sources from GET /full-reads.
  import { onMount } from 'svelte';
  import { get } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { href } from '../lib/router.svelte';
  import { fmtAgo, fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Dashboard, FullRead } from '../lib/types';

  let { summary }: { summary: NonNullable<Dashboard['full_reads']> } = $props();
  const SHOWN = 8;
  let rows: FullRead[] = $state([]);
  onMount(async () => {
    rows = await get<FullRead[]>('/full-reads').catch(() => []);
  });
  // drift first, then never checked, then the oldest verification
  const rank = (r: FullRead) => (r.result === 'drift' ? 0 : r.result === null || r.result === 'no_baseline' ? 1 : 2);
  const sorted = $derived([...rows].sort((a, b) => rank(a) - rank(b) || (a.last_at ?? 0) - (b.last_at ?? 0)));
  const cls: Record<string, string> = { clean: 'ok', drift: 'bad', no_baseline: 'warn', never: 'plain' };
  const tracker = (r: FullRead) => {
    const k = String(r.details?.tracker ?? '');
    return k ? (t.p29.fullRead.trackers[k] ?? k) : '—';
  };
</script>

<section class="card span-12" aria-labelledby="c-ct">
  <div class="card-head">
    <div><h2 id="c-ct">{t.p29.fullRead.dashTitle}</h2><div class="sub">{t.p29.fullRead.dashSub}</div></div>
    <div class="chips">
      <span class="chip ok">{t.p29.fullRead.verified}: {summary.verified}</span>
      <span class="chip {summary.drift ? 'bad' : 'plain'}">{t.p29.fullRead.drift}: {summary.drift}</span>
      <span class="chip {summary.never ? 'warn' : 'plain'}">{t.p29.fullRead.never}: {summary.never}</span>
      {#if summary.oldest_verified}<span class="muted small">{t.p29.fullRead.oldest(fmtAgo(summary.oldest_verified))}</span>{/if}
    </div>
  </div>
  {#if !sorted.length}
    <p class="empty">{t.p29.fullRead.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.p29.fullRead.source}</th>
            {#if !session.user?.tenant}<th scope="col">{t.tenant}</th>{/if}
            <th scope="col">{t.p29.fullRead.last}</th>
            <th scope="col">{t.p29.fullRead.result}</th>
            <th scope="col">{t.p29.fullRead.tracker}</th>
            <th scope="col" class="num">{t.p29.fullRead.unreported}</th>
            <th scope="col">{t.p29.fullRead.next}</th>
          </tr>
        </thead>
        <tbody>
          {#each sorted.slice(0, SHOWN) as r (`${r.tenant}/${r.source}`)}
            {@const res = r.result ?? 'never'}
            <tr>
              <td>
                <a class="mono" href={href(`/snapshots?tenant=${encodeURIComponent(r.tenant)}&source=${encodeURIComponent(r.source)}`)}>{r.source}</a>
                {#if r.result === 'drift' && r.details?.examples?.length}
                  <div class="muted small mono" title={r.details.examples.join('\n')}>{r.details.examples.slice(0, 2).join(', ')}</div>
                {/if}
              </td>
              {#if !session.user?.tenant}<td>{r.tenant}</td>{/if}
              <td class="nowrap" title={r.last_at ? fmtTime(r.last_at) : ''}>{r.last_at ? fmtAgo(r.last_at) : t.ago.never}</td>
              <td>
                <span class="chip {cls[res]}">{t.p29.fullRead.results[res]}</span>
                {#if r.result === 'drift' && r.last_clean_at}<div class="muted small">{t.p29.fullRead.lastClean(fmtAgo(r.last_clean_at))}</div>{/if}
              </td>
              <td>{tracker(r)}</td>
              <td class="num">{r.unreported ? t.p29.fullRead.unreportedOf(r.unreported, fmtBytes(r.unreported_bytes ?? 0)) : r.result ? '0' : '—'}</td>
              <td class="nowrap">{r.next_due ? fmtTime(r.next_due) : '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if sorted.length > SHOWN}<p class="muted">{t.p29.fullRead.more(sorted.length - SHOWN)}</p>{/if}
  {/if}
</section>

<style>
  .chips {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.4rem;
  }
  .small {
    font-size: 0.8rem;
  }
</style>
