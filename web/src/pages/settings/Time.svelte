<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, act, errText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { TimeServer, TimeState } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import Modal from '../../components/Modal.svelte';

  // Settings > Time (docs/control-plane.md "Time servers"): the chrony sources. The server validates
  // and gates (`time.servers`); nexus-time applies the change and reports the sources every 2 minutes.
  let cur: TimeState | null = $state(null);
  let error: string | null = $state(null);
  const isAdmin = $derived(session.user?.role === 'admin');

  async function load() {
    try {
      cur = await get<TimeState>('/settings/time');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(() => {
    load();
    const iv = setInterval(load, 30_000);
    return () => clearInterval(iv);
  });

  // ---- edit dialog
  let open = $state(false);
  let rows = $state<TimeServer[]>([]);
  let allowNtp = $state(false);

  function edit() {
    if (!cur) return;
    rows = cur.servers.map((s) => ({ ...s }));
    if (rows.length === 0) rows = [{ host: '', nts: true }];
    allowNtp = cur.allow_ntp;
    open = true;
  }

  const label = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
  // client-side hints only, the same rules as the server (crates/web-api/src/timesync.rs)
  function hostOk(h: string): boolean {
    if (!h || h.length > 253) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h.split('.').every((o) => Number(o) <= 255);
    if (h.includes(':')) return /^[0-9a-fA-F:.]+$/.test(h);
    const parts = h.replace(/\.$/, '').split('.');
    return parts.every((p) => label.test(p)) && !/^\d+$/.test(parts[parts.length - 1]);
  }
  const hosts = $derived(rows.map((r) => r.host.trim()).filter(Boolean));
  const problems = $derived.by(() => {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const h of hosts) {
      if (!hostOk(h)) out.push(t.timeSync.invalid(h));
      else if (seen.has(h.toLowerCase())) out.push(t.timeSync.duplicate(h));
      seen.add(h.toLowerCase());
    }
    if (hosts.length === 0) out.push(t.timeSync.none);
    if (cur && hosts.length > cur.max_servers) out.push(t.timeSync.tooMany(cur.max_servers));
    if (!allowNtp && rows.some((r) => r.host.trim() && !r.nts)) out.push(t.timeSync.needsOptIn);
    return out;
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const servers = rows
      .filter((r) => r.host.trim())
      .map((r) => ({ host: r.host.trim(), nts: allowNtp ? r.nts : true }));
    if (await act(put('/settings/time', { servers, allow_ntp: allowNtp }), t.timeSync.saved)) {
      open = false;
      load();
    }
  }

  const plain = $derived(((cur as TimeState | null)?.servers ?? []).filter((s) => !s.nts).map((s) => s.host));
  function ms(v: number | null): string {
    if (v === null) return '—';
    const m = v * 1000;
    return Math.abs(m) >= 1000 ? `${(m / 1000).toFixed(2)} s` : `${m >= 0 ? '+' : ''}${m.toFixed(2)} ms`;
  }
  const bits = (n: number) =>
    n
      .toString(2)
      .split('')
      .filter((b) => b === '1').length;
  const tone: Record<string, string> = { selected: 'ok', combined: 'info', unreachable: 'warn', falseticker: 'error' };
</script>

<div class="settings-section">
  <p class="intro muted">{t.timeSync.intro}</p>
  <ErrorBanner {error} />

  {#if !cur}
    {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
  {:else}
    {#if !cur.available}
      <p class="banner warn">{t.timeSync.noStatus}</p>
    {:else if cur.stale}
      <p class="banner warn">{t.timeSync.stale}</p>
    {/if}

    <section class="card" aria-labelledby="time-status">
      <div class="card-head"><h2 id="time-status">{t.timeSync.status}</h2></div>
      {#if cur.chrony_error}
        <p class="banner error">{t.timeSync.chronyDown(cur.chrony_error)}</p>
      {:else if cur.tracking}
        <p>
          <span class="chip {cur.tracking.synced ? 'ok' : 'error'}"
            >{cur.tracking.synced ? t.timeSync.synced : t.timeSync.notSynced}</span
          >
          <span class="muted"
            >{t.timeSync.syncedDetail(cur.tracking.reference, cur.tracking.stratum, ms(cur.tracking.offset))}</span
          >
        </p>
      {/if}
      {#if plain.length}<p class="banner warn">{t.timeSync.ntpWarning(plain.join(', '))}</p>{/if}
      {#if cur.last}
        {@const by = cur.last.by ?? '?'}
        {@const when = fmtTime(cur.last.time)}
        <p class="hint" class:error-text={cur.last.result === 'refused'}>
          {cur.last.result === 'applied'
            ? t.timeSync.last.applied(by, when)
            : cur.last.result === 'unchanged'
              ? t.timeSync.last.unchanged(by, when)
              : t.timeSync.last.refused(by, when, cur.last.error ?? '')}
        </p>
      {/if}
      {#if cur.scanned}<p class="hint">{t.timeSync.asOf(fmtTime(cur.scanned))}</p>{/if}
    </section>

    <section class="card" aria-labelledby="time-servers">
      <div class="card-head">
        <h2 id="time-servers">{t.timeSync.servers}</h2>
        {#if isAdmin}
          <button type="button" class="small" onclick={edit} disabled={cur.request_pending !== null}
            >{t.timeSync.edit}</button
          >
        {/if}
      </div>
      {#if cur.request_pending !== null}
        <p>
          <a class="chip warn" href={href(`/quorum?id=${cur.request_pending}`)}
            >{t.timeSync.pending(cur.request_pending)}</a
          >
        </p>
      {/if}
      {#if cur.queued}<p class="chip info">{t.timeSync.queued}</p>{/if}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.timeSync.host}</th>
              <th scope="col">{t.timeSync.kind}</th>
            </tr>
          </thead>
          <tbody>
            {#each cur.servers as s (s.host)}
              <tr>
                <td><code>{s.host}</code></td>
                <td>
                  {#if s.nts}<span class="chip ok">{t.timeSync.nts}</span>{:else}<span class="chip warn"
                      >{t.timeSync.ntp}</span
                    >{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="hint">{t.timeSync.firewallHint}</p>
    </section>

    <section class="card" aria-labelledby="time-sources">
      <div class="card-head"><h2 id="time-sources">{t.timeSync.sources}</h2></div>
      <p class="hint">{t.timeSync.sourcesHint}</p>
      {#if cur.sources.length === 0}
        <p class="empty">{t.timeSync.noSources}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.timeSync.name}</th>
                <th scope="col">{t.timeSync.state}</th>
                <th scope="col">{t.timeSync.kind}</th>
                <th scope="col" class="num">{t.timeSync.stratum}</th>
                <th scope="col">{t.timeSync.reach}</th>
                <th scope="col">{t.timeSync.lastRx}</th>
                <th scope="col" class="num">{t.timeSync.offset}</th>
              </tr>
            </thead>
            <tbody>
              {#each cur.sources as s (s.name)}
                <tr>
                  <td><code>{s.name}</code></td>
                  <td><span class="chip {tone[s.state] ?? ''}">{t.timeSync.states[s.state] ?? s.state}</span></td>
                  <td>{s.nts === null ? '—' : s.nts ? t.timeSync.nts : t.timeSync.ntp}</td>
                  <td class="num">{s.stratum ?? '—'}</td>
                  <td>{t.timeSync.reachOf(bits(s.reach))}</td>
                  <td>{s.last_rx === null ? '—' : t.timeSync.ago(s.last_rx)}</td>
                  <td class="num">{s.reach === 0 ? '—' : ms(s.offset)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {/if}
</div>

<Modal bind:open title={t.timeSync.editTitle} wide>
  {#if cur}
    <form onsubmit={save}>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.timeSync.hostField}</th>
              {#if allowNtp}<th scope="col">{t.timeSync.ntsField}</th>{/if}
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each rows as r, i (i)}
              <tr>
                <td>
                  <input
                    aria-label={t.timeSync.hostField}
                    bind:value={r.host}
                    spellcheck="false"
                    autocapitalize="none"
                    autocomplete="off"
                  />
                </td>
                {#if allowNtp}
                  <td><input type="checkbox" aria-label={t.timeSync.ntsField} bind:checked={r.nts} /></td>
                {/if}
                <td class="actions">
                  <button type="button" class="small" onclick={() => rows.splice(i, 1)} disabled={rows.length === 1}
                    >{t.timeSync.remove}</button
                  >
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <button
        type="button"
        class="small"
        onclick={() => rows.push({ host: '', nts: true })}
        disabled={rows.length >= cur.max_servers}>{t.timeSync.add}</button
      >
      <p class="hint">{t.timeSync.minHint}</p>
      <label class="inline-check"><input type="checkbox" bind:checked={allowNtp} />{t.timeSync.allowNtp}</label>
      <p class="hint">{t.timeSync.allowNtpHint}</p>
      {#each problems as p (p)}<p class="banner error" role="alert">{p}</p>{/each}
      <p class="hint">{t.timeSync.approvalHint}</p>
      <div class="form-actions">
        <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={problems.length > 0}>{t.save}</button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  .error-text {
    color: var(--bad);
  }
</style>
