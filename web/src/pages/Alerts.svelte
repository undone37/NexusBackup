<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { route } from '../lib/router.svelte';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Alert } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import Modal from '../components/Modal.svelte';

  // ?id=<n> (the alert_url of notifications) shows that alert whatever its state
  const focus = Number(route.query.get('id') ?? 0) || null;
  let alerts: Alert[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let filter: 'open' | 'resolved' | 'all' = $state(focus ? 'all' : 'open');

  async function load() {
    try {
      alerts = await get<Alert[]>(`/alerts?state=${filter}`);
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
  function setFilter(f: typeof filter) {
    filter = f;
    load();
  }

  const shown = $derived(focus ? alerts.filter((a) => a.id === focus) : alerts);
  const sev = (s: string) => (s === 'critical' ? 'bad' : s === 'warning' ? 'warn' : 'info');
  const hint = (a: Alert) => t.alerts.hints[a.kind] ?? a.hint;

  // acknowledge / resolve with an optional note
  let dlg: { a: Alert; action: 'ack' | 'resolve' } | null = $state(null);
  let open = $state(false);
  let note = $state('');
  let busy = $state(false);
  function ask(a: Alert, action: 'ack' | 'resolve') {
    dlg = { a, action };
    note = '';
    open = true;
  }
  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!dlg) return;
    busy = true;
    const body = note.trim() ? { note: note.trim() } : {};
    const ok = await act(post(`/alerts/${dlg.a.id}/${dlg.action}`, body), dlg.action === 'ack' ? t.alerts.done : t.alerts.resolvedDone);
    busy = false;
    if (ok) {
      open = false;
      load();
    }
  }
</script>

<div class="page-head">
  <h1>{t.alerts.title}</h1>
  <div class="seg" role="group" aria-label={t.alerts.filter}>
    {#each ['open', 'resolved', 'all'] as const as f (f)}
      <button type="button" aria-pressed={filter === f} onclick={() => setFilter(f)}>{t.alerts.filters[f]}</button>
    {/each}
  </div>
  <p class="lede">{t.alerts.lede}</p>
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
            <th scope="col">{t.alerts.seen}</th>
            <th scope="col">{t.kind}</th>
            <th scope="col">{t.alerts.message}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each shown as a (a.id)}
            <tr class:resolved={a.resolved_at}>
              <td><span class="chip {a.resolved_at ? 'muted-chip' : sev(a.severity)}">{a.severity}</span></td>
              <td class="nowrap" title={t.alerts.firstLast(fmtTime(a.first_ts), fmtTime(a.last_ts))}>
                {fmtAgo(a.last_ts)}
                <div class="muted small">{t.alerts.count(a.count)}{a.count > 1 ? ` · ${fmtAgo(a.first_ts)}` : ''}</div>
              </td>
              <td>
                <span class="mono">{a.kind}</span>
                {#if a.tenant}<div class="muted small">{t.alerts.tenant}: {a.tenant}</div>{/if}
              </td>
              <td>
                {a.message}
                <details class="alert-hint">
                  <summary>{t.alerts.whatToDo}</summary>
                  <p>{hint(a)}</p>
                </details>
                {#if a.note}<div class="muted small">{t.alerts.noteLabel}: {a.note}</div>{/if}
              </td>
              <td class="actions">
                {#if a.resolved_at}
                  <span class="muted small" title={fmtTime(a.resolved_at)}>
                    {t.alerts.resolvedBy(a.resolved_by ?? '?', fmtAgo(a.resolved_at))}
                  </span>
                  {#if a.auto}<span class="chip ok" title={t.alerts.autoTitle}>{t.alerts.auto}</span>{/if}
                {:else if can.ackAlert(session.user)}
                  {#if a.acked_by}
                    <span class="muted small">{t.alerts.acked} {t.alerts.ackedBy(a.acked_by)}</span>
                  {:else}
                    <button type="button" class="small" onclick={() => ask(a, 'ack')}>{t.alerts.ack}</button>
                  {/if}
                  <button type="button" class="small" onclick={() => ask(a, 'resolve')}>{t.alerts.resolve}</button>
                {:else if a.acked_by}
                  <span class="muted small">{t.alerts.acked} {t.alerts.ackedBy(a.acked_by)}</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal bind:open title={dlg?.action === 'resolve' ? t.alerts.resolveTitle : t.alerts.ackTitle}>
  {#if dlg}
    <form onsubmit={submit}>
      <p class="muted">{dlg.action === 'resolve' ? t.alerts.resolveIntro : t.alerts.ackIntro}</p>
      <p><span class="chip {sev(dlg.a.severity)}">{dlg.a.severity}</span> {dlg.a.message}</p>
      <div class="field">
        <label for="al-note">{t.alerts.note}</label>
        <textarea id="al-note" bind:value={note} rows="3" maxlength="1000"></textarea>
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}>{dlg.action === 'resolve' ? t.alerts.resolve : t.alerts.ack}</button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  tr.resolved td {
    color: var(--muted);
  }
  .small {
    font-size: 0.8rem;
  }
  .alert-hint summary {
    font-size: 0.8rem;
    color: var(--muted);
    cursor: pointer;
  }
  .alert-hint p {
    margin: 0.25rem 0 0;
    font-size: 0.85rem;
  }
  .muted-chip {
    opacity: 0.7;
  }
  td.actions {
    white-space: nowrap;
  }
</style>
