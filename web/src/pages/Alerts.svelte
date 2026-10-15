<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText, qs } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { href, route } from '../lib/router.svelte';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Alert, Snapshot } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import Modal from '../components/Modal.svelte';
  import HoldDialog from '../components/HoldDialog.svelte';
  import IconGavel from '@lucide/svelte/icons/gavel';
  import IconHistory from '@lucide/svelte/icons/history';
  import ScanBack from '../components/ScanBack.svelte';
  import { notify } from '../lib/notify.svelte';
  import type { SnapshotRef } from '../lib/types';

  // ?id=<n> (the alert_url of notifications) shows that alert whatever its state
  const focus = Number(route.query.get('id') ?? 0) || null;
  let alerts: Alert[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let filter: 'open' | 'resolved' | 'all' = $state(focus ? 'all' : 'open');
  let category = $state('');
  const CATEGORIES = ['security', 'backup', 'replication', 'hardware', 'system'];

  async function load() {
    try {
      alerts = await get<Alert[]>(`/alerts?state=${filter}${category ? `&category=${category}` : ''}`);
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
  // 15c: "Hold last good snapshot" (anomaly) / "Apply hold" (advisory from the primary)
  let holdOpen = $state(false);
  let holdTarget: SnapshotRef | null = $state(null);
  let holdReason = $state('');
  function hold(a: Alert) {
    if (!a.snapshot) return;
    holdTarget = a.snapshot;
    const origin = /^primary (\S+) holds/.exec(a.message)?.[1] ?? '?';
    holdReason =
      a.kind === 'anomaly'
        ? t.alerts.holdReasonAnomaly(`${a.snapshot.tenant}/${a.snapshot.source}`)
        : t.alerts.holdReasonAdvisory(origin);
    holdOpen = true;
  }
  const ref = (s: SnapshotRef) => `${s.source} @ ${fmtTime(s.time)}`;

  // Phase 29: "Scan back to last clean" from a malware / scan / hash hunt alert. The source comes
  // from the alert key `kind:tenant/source`; the start is the newest flagged snapshot of it.
  const SCAN_BACK_KINDS = ['scan_hit', 'malware', 'hash_hunt_hit'];
  const keySource = (a: Alert) => {
    const m = /^[a-z_]+:([^/]+)\/(.+)$/.exec(a.key ?? '');
    return SCAN_BACK_KINDS.includes(a.kind) && m ? { tenant: m[1], source: m[2] } : null;
  };
  let sb: { tenant: string; source: string; time: number } | null = $state(null);
  let sbOpen = $state(false);
  async function scanBack(a: Alert) {
    const k = keySource(a);
    if (!k) return;
    try {
      const xs = await get<Snapshot[]>('/snapshots' + qs(k));
      const flagged = xs
        .filter((x) => x.local && (x.flagged ?? (!!x.anomalous || x.scan_state === 'hit')))
        .sort((x, y) => y.time - x.time);
      const from = flagged[0];
      if (!from) return void notify('info', t.p29.scanBack.noFlagged);
      sb = { ...k, time: from.time };
      sbOpen = true;
    } catch (e) {
      notify('error', errText(e));
    }
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!dlg) return;
    busy = true;
    const body = note.trim() ? { note: note.trim() } : {};
    const ok = await act(
      post(`/alerts/${dlg.a.id}/${dlg.action}`, body),
      dlg.action === 'ack' ? t.alerts.done : t.alerts.resolvedDone,
    );
    busy = false;
    if (ok) {
      open = false;
      load();
    }
  }
  /** A readable title of an alert kind (`user_risk` -> "Unusual account activity" or "User risk"). */
  const kindTitle = (k: string) =>
    t.alerts.kindTitles[k] ?? k.charAt(0).toUpperCase() + k.slice(1).replaceAll('_', ' ');
  /** The message split around "job N" mentions (links to the job). */
  function linkParts(m: string): { text: string; job?: number }[] {
    const out: { text: string; job?: number }[] = [];
    let last = 0;
    for (const x of m.matchAll(/\bjob #?(\d+)\b/g)) {
      out.push({ text: m.slice(last, x.index) });
      out.push({ text: x[0], job: Number(x[1]) });
      last = x.index! + x[0].length;
    }
    out.push({ text: m.slice(last) });
    return out;
  }
</script>

<div class="page-head">
  <h1>{t.alerts.title}</h1>
  <div class="seg" role="group" aria-label={t.alerts.filter}>
    {#each ['open', 'resolved', 'all'] as const as f (f)}
      <button type="button" aria-pressed={filter === f} onclick={() => setFilter(f)}>{t.alerts.filters[f]}</button>
    {/each}
  </div>
  <select class="cat-filter" bind:value={category} onchange={load} aria-label={t.alerts.category}>
    <option value="">{t.alerts.allCategories}</option>
    {#each CATEGORIES as c (c)}
      <option value={c}>{t.alerts.categories[c]}</option>
    {/each}
  </select>
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
                <strong>{kindTitle(a.kind)}</strong>
                <div class="muted small mono">{a.kind}</div>
                <div class="muted small">{t.alerts.categories[a.category] ?? a.category}</div>
                {#if a.tenant}<div class="muted small">{t.alerts.tenant}: {a.tenant}</div>{/if}
              </td>
              <td>
                <!-- "job 220" in a message opens that job -->
                {#each linkParts(a.message) as part, i (i)}{#if part.job}<a href={href(`/jobs/${part.job}`)}
                      >{part.text}</a
                    >{:else}{part.text}{/if}{/each}
                <details class="alert-hint">
                  <summary>{t.alerts.whatToDo}</summary>
                  <p>{hint(a)}</p>
                </details>
                {#if a.note}<div class="muted small">{t.alerts.noteLabel}: {a.note}</div>{/if}
                {#if a.tickets?.length}
                  <div class="muted small">
                    {#each a.tickets as tk (tk.rule + tk.ticket)}
                      <span class="ticket"
                        >{t.alerts.ticket(
                          t.settings.al.psaVendors[tk.vendor] ?? tk.vendor,
                          tk.ticket,
                          !!tk.closed,
                        )}</span
                      >
                    {/each}
                  </div>
                {/if}
              </td>
              <td class="actions">
                {#if a.resolved_at}
                  <span class="muted small" title={fmtTime(a.resolved_at)}>
                    {t.alerts.resolvedBy(a.resolved_by ?? '?', fmtAgo(a.resolved_at))}
                  </span>
                  {#if a.auto}<span class="chip ok" title={t.alerts.autoTitle}>{t.alerts.auto}</span>{/if}
                {:else if can.ackAlert(session.user)}
                  {#if a.snapshot && can.hold(session.user)}
                    <button
                      type="button"
                      class="small"
                      onclick={() => hold(a)}
                      aria-label={a.kind === 'anomaly'
                        ? t.alerts.holdLastGoodLabel(ref(a.snapshot))
                        : t.alerts.applyHoldLabel(ref(a.snapshot))}
                      ><IconGavel aria-hidden="true" />{a.kind === 'anomaly'
                        ? t.alerts.holdLastGood
                        : t.alerts.applyHold}</button
                    >
                  {/if}
                  {#if keySource(a) && can.scan(session.user)}
                    <button type="button" class="small" onclick={() => scanBack(a)}
                      ><IconHistory aria-hidden="true" />{t.p29.scanBack.alertAction}</button
                    >
                  {/if}
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
        <button type="submit" class="primary" disabled={busy}
          >{dlg.action === 'resolve' ? t.alerts.resolve : t.alerts.ack}</button
        >
      </div>
    </form>
  {/if}
</Modal>

<HoldDialog bind:open={holdOpen} target={holdTarget} reason={holdReason} ondone={load} />

{#if sb}<ScanBack bind:open={sbOpen} tenant={sb.tenant} source={sb.source} time={sb.time} />{/if}

<style>
  .ticket + .ticket::before {
    content: ' · ';
  }
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
  .cat-filter {
    width: auto;
  }
</style>
