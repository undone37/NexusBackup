<script lang="ts">
  // Phase 22b: the restore-priority switch (Dashboard, admins and operators). While it is on,
  // scheduled backups, GC, verify, offsite uploads and replication wait; it expires on its own.
  import { onMount } from 'svelte';
  import { get, put, del, act } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { fmtTime, fmtAgo } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { RestorePriority } from '../lib/types';
  import IconLifeBuoy from '@lucide/svelte/icons/life-buoy';

  let hours = $state(8);
  let reason = $state('');
  let busy = $state(false);
  const p = $derived(session.priority);
  onMount(async () => {
    session.priority = await get<RestorePriority>('/restore-priority').catch(() => session.priority);
  });

  async function turnOn(e: SubmitEvent) {
    e.preventDefault();
    if (!p?.active && !(await askConfirm(t.priority.confirm(hours)))) return;
    busy = true;
    const r = await act(
      put<RestorePriority>('/restore-priority', { hours: Number(hours), reason: reason.trim() }),
      p?.active ? t.priority.renewed : t.priority.on,
    );
    busy = false;
    if (r && !r.quorum) session.priority = r.data;
  }
  async function turnOff() {
    busy = true;
    const r = await act(del<RestorePriority>('/restore-priority'), t.priority.off);
    busy = false;
    if (r && !r.quorum) session.priority = r.data;
  }
</script>

<section class="card priority-card" class:on={p?.active} aria-labelledby="dash-priority">
  <div class="card-head">
    <h2 id="dash-priority"><IconLifeBuoy aria-hidden="true" />{t.priority.title}</h2>
    {#if p?.active}<span class="chip warn">{t.priority.active}</span>{:else}<span class="chip"
        >{t.priority.inactive}</span
      >{/if}
  </div>
  {#if p?.active}
    <p>
      <strong>{t.priority.until(fmtTime(p.until ?? 0))}</strong>
      {t.priority.since(p.by ?? '?', fmtAgo(p.since ?? 0))}{p.reason ? ` · ${p.reason}` : ''}
    </p>
  {:else}
    <p class="muted">{t.priority.intro}</p>
  {/if}
  <form class="row" onsubmit={turnOn}>
    <div class="field">
      <label for="prio-h">{p?.active ? t.priority.renewFor : t.priority.hours}</label>
      <select id="prio-h" bind:value={hours}>
        {#each [1, 2, 4, 8, 12, 24] as h (h)}<option value={h}>{t.priority.hoursN(h)}</option>{/each}
      </select>
    </div>
    <div class="field grow">
      <label for="prio-r">{t.priority.reason}</label>
      <input id="prio-r" bind:value={reason} maxlength="200" placeholder={t.priority.reasonHint} />
    </div>
    <button type="submit" class="primary" disabled={busy}>{p?.active ? t.priority.renew : t.priority.turnOn}</button>
    {#if p?.active}<button type="button" disabled={busy} onclick={turnOff}>{t.priority.turnOff}</button>{/if}
  </form>
</section>

<style>
  .priority-card {
    margin-bottom: 1rem;
  }
  .priority-card.on {
    border-color: var(--warn);
  }
  h2 {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: 0.5rem 1rem;
  }
  .row .field {
    margin: 0;
  }
  .grow {
    flex: 1 1 16rem;
  }
</style>
