<script lang="ts">
  import { askConfirm, askText } from '../lib/confirm.svelte';
  // Appliance replication (docs/replication.md): peers on the primary, sources on the secondary.
  import { onMount } from 'svelte';
  import Menu, { type MenuItem } from '../components/Menu.svelte';
  import { jobLink } from '../lib/jobs';
  import { href } from '../lib/router.svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Job, ReplicationPeer, ReplicationSource, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import BlackoutEditor from '../components/BlackoutEditor.svelte';
  import {
    bandwidthWeaker,
    isPaused,
    syncOpen,
    syncWidened,
    timeZones,
    validRateWindow,
    validWindow,
    type RateWindow,
    type Span,
  } from '../lib/schedule';

  let peers: ReplicationPeer[] = $state([]);
  let sources: ReplicationSource[] = $state([]);
  let tenants: Tenant[] = $state([]);
  // queued / running replica_sync jobs by replication source (shown in the source row)
  let syncing: Record<number, Job[]> = $state({});
  let error: string | null = $state(null);
  let loaded = $state(false);
  let now = $state(Date.now() / 1000);
  const admin = $derived(can.configure(session.user));

  async function load() {
    try {
      [peers, sources, tenants] = await Promise.all([
        get<ReplicationPeer[]>('/replication/peers'),
        get<ReplicationSource[]>('/replication/sources'),
        get<Tenant[]>('/tenants'),
      ]);
      const busy = (await Promise.all([get<Job[]>('/jobs?state=running'), get<Job[]>('/jobs?state=queued')])).flat();
      const by: Record<number, Job[]> = {};
      for (const j of busy) {
        const id = j.params?.replication_source_id;
        if (j.kind === 'replica_sync' && typeof id === 'number') (by[id] ??= []).push(j);
      }
      syncing = by;
      error = null;
    } catch (e) {
      error = errText(e);
    }
    now = Date.now() / 1000;
    loaded = true;
  }
  onMount(() => {
    load();
    // sync state and last sync stay current (nothing reloads while a dialog is open)
    const iv = setInterval(() => {
      if (document.visibilityState === 'visible' && !peerOpen && !srcOpen && !winOpen && !codeOpen) load();
    }, 15000);
    return () => clearInterval(iv);
  });

  const stateCls: Record<string, string> = {
    pending: 'info',
    approved: 'info',
    enrolled: 'ok',
    revoked: 'bad',
    enrolling: 'info',
    failed: 'bad',
  };
  const shortFp = (fp: string | null) => (fp ? `${fp.slice(0, 12)}…` : '—');

  // ---- peers (primary)
  let peerOpen = $state(false);
  let pf = $state({ name: '', tenants: [] as string[] });
  function newPeer() {
    pf = { name: '', tenants: [] };
    peerOpen = true;
  }
  let code: { name: string; code: string; fingerprint: string | null } | null = $state(null);
  let codeOpen = $state(false);
  $effect(() => {
    if (!codeOpen) code = null;
  });
  async function savePeer(e: SubmitEvent) {
    e.preventDefault();
    const r = await act(
      post<{ peer: ReplicationPeer; code: string; primary_cert_sha256?: string | null }>('/replication/peers', { name: pf.name.trim(), tenants: pf.tenants }),
      t.created,
    );
    if (!r) return;
    peerOpen = false;
    if (r.data.code) {
      code = { name: pf.name.trim(), code: r.data.code, fingerprint: r.data.primary_cert_sha256 ?? null };
      codeOpen = true;
    }
    load();
  }
  async function exportKeys(p: ReplicationPeer) {
    if (!(await askConfirm(t.repl.exportConfirm(p.name)))) return;
    if (await act(post(`/replication/peers/${encodeURIComponent(p.id)}/export-keys`, {}), t.saved)) load();
  }
  async function revoke(p: ReplicationPeer) {
    if (!(await askConfirm(t.confirmDelete(t.repl.revokeWhat(p.name))))) return;
    if (await act(del(`/replication/peers/${encodeURIComponent(p.id)}`), t.deleted)) load();
  }

  // ---- sources (secondary)
  let srcOpen = $state(false);
  let sf = $state({
    name: '',
    url: '',
    code: '',
    fingerprint: '',
    tenants: '',
    schedule: 'daily 02:00',
    daily: 14,
    weekly: 4,
    monthly: 6,
    yearly: 2,
    mbps: '',
  });
  function newSource() {
    sf = { name: '', url: '', code: '', fingerprint: '', tenants: '', schedule: 'daily 02:00', daily: 14, weekly: 4, monthly: 6, yearly: 2, mbps: '' };
    srcOpen = true;
  }
  async function saveSource(e: SubmitEvent) {
    e.preventDefault();
    const body = {
      name: sf.name.trim(),
      url: sf.url.trim(),
      code: sf.code.trim(),
      fingerprint: sf.fingerprint.trim(),
      tenants: sf.tenants
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean),
      schedule: sf.schedule.trim(),
      gfs: { daily: Number(sf.daily), weekly: Number(sf.weekly), monthly: Number(sf.monthly), yearly: Number(sf.yearly) },
      bwlimit: sf.mbps ? Math.round(Number(sf.mbps) * 1e6) : null,
    };
    if (await act(post('/replication/sources', body), t.created)) {
      srcOpen = false;
      load();
    }
  }
  async function syncNow(s: ReplicationSource) {
    const r = await act(
      post<{ jobs: number[] }>(`/replication/sources/${s.id}/sync`, {}),
      (d) => t.repl.syncStarted(d.jobs.length),
      (d) => (d.jobs.length ? jobLink({ id: d.jobs[0] }) : null),
    );
    if (r) load();
  }
  async function newCode(s: ReplicationSource) {
    const c = await askText(t.repl.newCodePrompt);
    if (!c) return;
    if (await act(post(`/replication/sources/${s.id}/enroll`, { code: c.trim() }), t.saved)) load();
  }
  async function removeSource(s: ReplicationSource) {
    if (!(await askConfirm(t.confirmDelete(t.repl.deleteSourceWhat(s.name))))) return;
    if (await act(del(`/replication/sources/${s.id}`), t.deleted)) load();
  }
  async function setSchedule(s: ReplicationSource) {
    const v = await askText(t.repl.schedule, s.schedule);
    if (!v || v === s.schedule) return;
    if (await act(put(`/replication/sources/${s.id}`, { schedule: v.trim() }), t.saved)) load();
  }

  // ---- windows (17a) and close vault (17b)
  const zones = timeZones();
  const span = (w: Span) => `${w.days.length ? w.days.join(',') + ' ' : ''}${w.from}–${w.to}`;
  let winOpen = $state(false);
  let wf = $state({ id: 0, name: '', windows: [] as RateWindow[], sync: [] as Span[], tz: 'UTC', mbps: '' });
  let winOld: ReplicationSource | null = $state(null);
  function editWindows(s: ReplicationSource) {
    winOld = s;
    wf = {
      id: s.id,
      name: s.name,
      windows: $state.snapshot(s.windows ?? []),
      sync: $state.snapshot(s.sync_window ?? []),
      tz: s.timezone ?? 'UTC',
      mbps: s.bwlimit ? String(s.bwlimit / 1e6) : '',
    };
    winOpen = true;
  }
  const wfBase = $derived(wf.mbps ? Math.round(Number(wf.mbps) * 1e6) : null);
  const winWeaker = $derived.by(() => {
    const o = winOld as ReplicationSource | null;
    if (!o || !winOpen) return false;
    const tz = o.timezone ?? 'UTC';
    return (
      bandwidthWeaker({ windows: o.windows ?? [], base: o.bwlimit, tz }, { windows: wf.windows, base: wfBase, tz: wf.tz }) ||
      syncWidened(o.sync_window ?? [], tz, wf.sync, wf.tz)
    );
  });
  async function saveWindows(e: SubmitEvent) {
    e.preventDefault();
    if (!wf.windows.every(validRateWindow) || !wf.sync.every(validWindow)) return;
    const body = { windows: $state.snapshot(wf.windows), sync_window: $state.snapshot(wf.sync), timezone: wf.tz, bwlimit: wfBase };
    if (await act(put(`/replication/sources/${wf.id}`, body), t.saved)) {
      winOpen = false;
      load();
    }
  }
  const closed = (s: ReplicationSource) => isPaused(s.closed_until, now);
  async function closeVault(s: ReplicationSource) {
    if (!(await askConfirm(t.repl.closeConfirm(s.name)))) return;
    if (await act(post(`/replication/sources/${s.id}/close`, {}), t.repl.closedDone)) load();
  }
  async function reopen(s: ReplicationSource) {
    if (!(await askConfirm(t.repl.reopenConfirm(s.name)))) return;
    if (await act(post(`/replication/sources/${s.id}/reopen`, {}), t.repl.reopenDone)) load();
  }

  function sourceActions(s: ReplicationSource): MenuItem[] {
    const out: MenuItem[] = [];
    if (can.closeVault(session.user))
      out.push(closed(s) ? { label: t.repl.reopen, onselect: () => reopen(s) } : { label: t.repl.closeVault, onselect: () => closeVault(s) });
    if (admin) {
      out.push({ label: t.repl.schedule, onselect: () => setSchedule(s) }, { label: t.repl.windows, onselect: () => editWindows(s) });
      if (s.state !== 'enrolled') out.push({ label: t.repl.newCode, onselect: () => newCode(s) });
      out.push({ label: t.delete, onselect: () => removeSource(s) });
    }
    return out;
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      notify('ok', t.users.copied);
    } catch {
      /* clipboard unavailable: the code is selectable */
    }
  }
</script>

<div class="page-head">
  <h1>{t.repl.title}</h1>
  <p class="lede">{t.repl.intro}</p>
</div>
<ErrorBanner {error} />

<section class="card">
  <div class="page-head">
    <h2>{t.repl.peers}</h2>
    {#if admin}<button type="button" class="primary" onclick={newPeer}>{t.repl.newPeer}</button>{/if}
  </div>
  <p class="muted">{t.repl.peersIntro}</p>
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if peers.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.name}</th>
            <th scope="col">{t.repl.tenants}</th>
            <th scope="col">{t.repl.state}</th>
            <th scope="col">{t.repl.keys}</th>
            <th scope="col">{t.repl.keydFp}</th>
            <th scope="col">{t.repl.cert}</th>
            <th scope="col">{t.repl.lastSeen}</th>
            {#if admin}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each peers as p (p.id)}
            <tr>
              <td><strong>{p.name}</strong> <div class="muted mono">{p.id}</div></td>
              <td>{p.tenants.join(', ')}</td>
              <td>
                <span class="chip {stateCls[p.state] ?? ''}">{t.repl.states[p.state] ?? p.state}</span>
                {#if p.state === 'approved' && p.token_expires}<div class="muted">{fmtTime(p.token_expires)}</div>{/if}
              </td>
              <td>
                {#if Object.keys(p.keys).length}
                  {#each Object.entries(p.keys) as [tn, k] (tn)}<div>{tn}: v{k.versions.join(', v')}</div>{/each}
                {:else}<span class="muted">{t.repl.noKeys}</span>{/if}
              </td>
              <td class="mono">
                {p.keyd_fingerprint ?? '—'}
                {#if p.state === 'enrolled'}
                  {#if p.post_quantum}<span class="chip accent" title={t.p30.pq.hint}>{t.p30.pq.chip}</span>{:else}<span class="chip" title={t.p30.pq.peerLegacyHint}>{t.p30.pq.legacy}</span>{/if}
                {/if}
              </td>
              <td class="mono" title={p.cert_sha256 ?? ''}>{shortFp(p.cert_sha256)}</td>
              <td class="nowrap" title={fmtTime(p.last_seen)}>{fmtAgo(p.last_seen, now)}</td>
              {#if admin}
                <td class="actions">
                  {#if p.state === 'enrolled'}
                    <button type="button" class="small" onclick={() => exportKeys(p)}>{t.repl.exportKeys}</button>
                  {/if}
                  {#if p.state !== 'revoked'}
                    <button type="button" class="small danger" onclick={() => revoke(p)}>{t.delete}</button>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<section class="card">
  <div class="page-head">
    <h2>{t.repl.sources}</h2>
    {#if admin}<button type="button" class="primary" onclick={newSource}>{t.repl.newSource}</button>{/if}
  </div>
  <p class="muted">{t.repl.sourcesIntro}</p>
  {#if loaded && sources.length === 0}
    <p class="empty">{t.none}</p>
  {:else if loaded}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.name}</th>
            <th scope="col">{t.repl.primaryShort}</th>
            <th scope="col">{t.repl.state}</th>
            <th scope="col">{t.repl.schedule}</th>
            <th scope="col">{t.repl.lastSync}</th>
            <th scope="col">{t.repl.keydFp}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each sources as s (s.id)}
            <tr>
              <td><strong>{s.name}</strong></td>
              <td class="mono">{s.url}<div class="muted" title={s.cert_pin}>{shortFp(s.cert_pin)}</div></td>
              <td>
                <span class="chip {stateCls[s.state] ?? ''}">{t.repl.states[s.state] ?? s.state}</span>
                {#if closed(s)}
                  <div><span class="chip bad">{t.repl.closed}</span></div>
                  <div class="muted">
                    {t.repl.closedSince(fmtTime(s.closed_at), s.closed_by ?? '?')},
                    {s.closed_until === -1 ? t.repl.closedForever : t.repl.closedUntil(fmtTime(s.closed_until))}
                  </div>
                {:else if !syncOpen(s.sync_window ?? [], s.timezone ?? 'UTC', now)}
                  <div><span class="chip info">{t.repl.outsideWindow}</span></div>
                {/if}
              </td>
              <td>
                <span class="mono nowrap">{s.schedule}</span>
                {#if s.sync_window?.length || s.windows?.length}
                  <div class="muted">
                    {#if s.sync_window?.length}{t.repl.syncWindowShort}: {s.sync_window.map(span).join(', ')}<br />{/if}
                    {#if s.windows?.length}{t.windows.bandwidth}: {t.windows.short(s.windows.length)}<br />{/if}
                    {s.timezone}
                  </div>
                {/if}
              </td>
              <td>
                {#each syncing[s.id] ?? [] as j (j.id)}
                  <div><a class="chip info" href={href(`/jobs/${j.id}`)}>{j.state === 'running' ? t.repl.syncRunning(j.tenant, j.id) : t.repl.syncQueued(j.tenant, j.id)}</a></div>
                {/each}
                {#each s.tenants as tn (tn)}
                  {@const st = s.status?.[tn]}
                  <div>
                    <strong>{tn}</strong>:
                    {#if st?.last_ok}<span title={fmtTime(st.last_ok)}>{fmtAgo(st.last_ok, now)}</span>{:else}<span class="muted">{t.repl.never}</span>{/if}
                    {#if st?.last_error && (st.last_error_at ?? 0) > (st.last_ok ?? 0)}
                      <div class="chip bad" title={st.last_error}>{t.repl.error}: {st.last_error.slice(0, 80)}</div>
                    {/if}
                  </div>
                {/each}
              </td>
              <td class="mono">{s.keyd_fingerprint ?? '—'}</td>
              <td class="actions">
                {#if s.state === 'enrolled' && !closed(s) && syncOpen(s.sync_window ?? [], s.timezone ?? 'UTC', now) && can.syncReplication(session.user)}
                  <button type="button" class="small" disabled={!!syncing[s.id]?.length} onclick={() => syncNow(s)}>{t.repl.syncNow}</button>
                {/if}
                {#if sourceActions(s).length}<Menu label={t.agents.more} ariaLabel={t.repl.moreLabel(s.name)} items={sourceActions(s)} />{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<Modal bind:open={peerOpen} title={t.repl.newPeer}>
  <form onsubmit={savePeer}>
    <div class="form-grid">
      <div class="field">
        <label for="p-name">{t.name}</label>
        <input id="p-name" bind:value={pf.name} required maxlength="64" autocomplete="off" spellcheck="false" />
      </div>
      <fieldset class="field">
        <legend>{t.repl.tenants}</legend>
        {#each tenants as tn (tn.name)}
          <label class="inline-check"><input type="checkbox" value={tn.name} bind:group={pf.tenants} />{tn.name}</label>
        {/each}
      </fieldset>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (peerOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={!pf.tenants.length}>{t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={codeOpen} title={t.repl.codeTitle(code?.name ?? '')} wide>
  {#if code}
    <p class="banner warn" role="alert">{t.repl.codeOnce}</p>
    <p>{t.repl.codeSteps}</p>
    <div class="field">
      <span class="muted">{t.repl.code}</span>
      <code class="secret">{code.code}</code>
      <button type="button" class="small" onclick={() => copy(code!.code)}>{t.users.copy}</button>
    </div>
    <div class="field">
      <span class="muted">{t.repl.primaryFingerprint}</span>
      {#if code.fingerprint}
        <code class="secret">{code.fingerprint}</code>
        <button type="button" class="small" onclick={() => copy(code!.fingerprint!)}>{t.users.copy}</button>
      {:else}
        <span class="muted">{t.repl.primaryFingerprintUnknown}</span>
      {/if}
    </div>
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (codeOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<Modal bind:open={srcOpen} title={t.repl.newSource} wide>
  <form onsubmit={saveSource}>
    <div class="form-grid">
      <div class="field">
        <label for="s-name">{t.name}</label>
        <input id="s-name" bind:value={sf.name} required maxlength="64" autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label for="s-url">{t.repl.primary}</label>
        <input id="s-url" class="mono" bind:value={sf.url} required autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label for="s-code">{t.repl.code}</label>
        <input id="s-code" class="mono" bind:value={sf.code} required autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label for="s-fp">{t.repl.fingerprint}</label>
        <input id="s-fp" class="mono" bind:value={sf.fingerprint} required autocomplete="off" spellcheck="false" />
        <small class="muted">{t.repl.fingerprintHint}</small>
      </div>
      <div class="field">
        <label for="s-tenants">{t.repl.tenants}</label>
        <input id="s-tenants" bind:value={sf.tenants} required autocomplete="off" spellcheck="false" />
        <small class="muted">{t.repl.tenantsHint}</small>
      </div>
      <div class="field">
        <label for="s-sched">{t.repl.schedule}</label>
        <input id="s-sched" class="mono" bind:value={sf.schedule} required />
        <small class="muted">{t.policies.scheduleHint}</small>
      </div>
      <fieldset class="field">
        <legend>{t.policies.gfs}</legend>
        <label>{t.policies.daily} <input type="number" min="0" max="1000" bind:value={sf.daily} /></label>
        <label>{t.policies.weekly} <input type="number" min="0" max="1000" bind:value={sf.weekly} /></label>
        <label>{t.policies.monthly} <input type="number" min="0" max="1000" bind:value={sf.monthly} /></label>
        <label>{t.policies.yearly} <input type="number" min="0" max="1000" bind:value={sf.yearly} /></label>
        <small class="muted">{t.repl.gfsHint}</small>
      </fieldset>
      <div class="field">
        <label for="s-bw">{t.repl.bwlimit}</label>
        <input id="s-bw" type="number" min="0" step="0.1" bind:value={sf.mbps} />
      </div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (srcOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={winOpen} title={t.repl.windowsTitle(wf.name)} wide>
  <form onsubmit={saveWindows}>
    <p class="hint">{t.windows.gatedHint}</p>
    <BlackoutEditor bind:windows={wf.sync} mode="span" idp="w-sync" legend={t.windows.syncWindow} hint={t.windows.syncWindowHint} />
    <BlackoutEditor bind:windows={wf.windows} mode="rate" idp="w-bw" legend={t.windows.bandwidth} hint={t.windows.bandwidthHint} />
    <div class="form-grid">
      <div class="field">
        <label for="w-tz">{t.windows.timezone}</label>
        <select id="w-tz" bind:value={wf.tz}>
          {#each zones as z (z)}<option value={z}>{z}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="w-bw">{t.repl.bwlimit}</label>
        <input id="w-bw" type="number" min="0" step="0.1" bind:value={wf.mbps} />
      </div>
    </div>
    {#if winWeaker}<p class="banner warn" role="status">{t.windows.weaker}</p>{/if}
    <div class="form-actions">
      <button type="button" onclick={() => (winOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.save}</button>
    </div>
  </form>
</Modal>
