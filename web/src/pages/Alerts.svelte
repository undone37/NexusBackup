<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Alert } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let alerts: Alert[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let showAcked = $state(false);

  async function load() {
    try {
      alerts = await get<Alert[]>('/alerts');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(() => {
    load();
    const iv = setInterval(load, 30000);
    return () => clearInterval(iv);
  });

  const shown = $derived(alerts.filter((a) => showAcked || !a.acked_by));
  const sev = (s: string) => (s === 'critical' ? 'bad' : s === 'warning' ? 'warn' : 'info');

  async function ack(a: Alert) {
    if (await act(post(`/alerts/${a.id}/ack`), t.alerts.done)) load();
  }
</script>

<div class="page-head">
  <h1>{t.alerts.title}</h1>
  <label class="inline-check"><input type="checkbox" bind:checked={showAcked} />{t.alerts.showAcked}</label>
</div>

<ErrorBanner {error} />

<div class="card">
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if shown.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.alerts.severity}</th>
            <th scope="col">{t.time}</th>
            <th scope="col">{t.kind}</th>
            <th scope="col">{t.alerts.message}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each shown as a (a.id)}
            <tr>
              <td><span class="chip {sev(a.severity)}">{a.severity}</span></td>
              <td class="nowrap" title={fmtTime(a.ts)}>{fmtAgo(a.ts)}</td>
              <td class="mono">{a.kind}</td>
              <td>{a.message}</td>
              <td class="actions">
                {#if a.acked_by}
                  <span class="muted">{t.alerts.acked} {t.alerts.ackedBy(a.acked_by)}</span>
                {:else if can.ackAlert(session.user)}
                  <button type="button" class="small" onclick={() => ack(a)}>{t.alerts.ack}</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
