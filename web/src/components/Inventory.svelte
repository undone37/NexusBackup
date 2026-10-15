<script lang="ts">
  // Guest inventory of one source (GET /sources/{id}/inventory, Phase 13c) with a
  // refresh (`inventory` job) for operators and admins.
  import { onDestroy } from 'svelte';
  import { get, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { href } from '../lib/router.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { runJob } from '../lib/jobs';
  import type { Inventory, Source } from '../lib/types';
  import ErrorBanner from './ErrorBanner.svelte';

  let { source }: { source: Source } = $props();

  let inv = $state<Inventory | null>(null);
  let error: string | null = $state(null);
  let busy = $state(false);
  let failedJob: number | null = $state(null);
  const ctl = new AbortController();
  onDestroy(() => ctl.abort());

  async function load() {
    try {
      inv = await get<Inventory>(`/sources/${source.id}/inventory`);
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  $effect(() => {
    void source.id;
    load();
  });

  async function refresh() {
    busy = true;
    failedJob = null;
    try {
      const r = await runJob('inventory', source.tenant, { source_id: source.id }, ctl.signal);
      if (r && r.job.state !== 'ok') {
        failedJob = r.job.id;
        notify('error', t.groups.refreshFailed);
      }
      await load();
    } catch (e) {
      notify('error', errText(e));
    } finally {
      busy = false;
    }
  }
</script>

<p class="lede">{t.inventory.lede}</p>
<ErrorBanner {error} />
{#if !inv && !error}
  <p class="muted" aria-busy="true">{t.loading}</p>
{:else if inv}
  <div class="row">
    <span class="muted">{inv.refreshed ? t.groups.refreshed(fmtAgo(inv.refreshed)) : t.inventory.never}</span>
    {#if can.backup(session.user)}
      <button type="button" class="small" disabled={busy} onclick={refresh}
        >{busy ? t.groups.refreshing : t.groups.refresh}</button
      >
    {/if}
    {#if failedJob}<a href={href(`/jobs/${failedJob}`)}>{t.jobs.detail(failedJob)}</a>{/if}
  </div>
  {#if inv.guests.length === 0}
    <p class="empty">{inv.refreshed ? t.inventory.empty : t.groups.noInventory}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.inventory.guest}</th>
            <th scope="col">{t.inventory.name}</th>
            <th scope="col">{t.inventory.type}</th>
            <th scope="col">{t.inventory.tags}</th>
            <th scope="col">{t.inventory.groups}</th>
          </tr>
        </thead>
        <tbody>
          {#each inv.guests as g (g.guest)}
            <tr class:muted={g.gone !== null}>
              <td class="mono">{g.guest}</td>
              <td>{g.name}</td>
              <td>{g.kind || '—'}</td>
              <td
                >{#each g.tags as x (x)}<span class="chip plain mono">{x}</span>
                {/each}</td
              >
              <td>
                {#if g.gone !== null}
                  <span title={fmtTime(g.gone)}>{t.inventory.gone(fmtAgo(g.gone))}</span>
                {:else if g.groups.length}
                  {g.groups.join(', ')}
                {:else}
                  <span class="chip warn">{t.inventory.unprotected}</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}
