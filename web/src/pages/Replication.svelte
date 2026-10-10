<script lang="ts">
  import { askConfirm, askText } from '../lib/confirm.svelte';
  // Appliance replication (docs/replication.md): peers on the primary, sources on the secondary.
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { ReplicationPeer, ReplicationSource, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let peers: ReplicationPeer[] = $state([]);
  let sources: ReplicationSource[] = $state([]);
  let tenants: Tenant[] = $state([]);
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
      error = null;
    } catch (e) {
      error = errText(e);
    }
    now = Date.now() / 1000;
    loaded = true;
  }
  onMount(load);

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
    const r = await act(post<{ jobs: number[] }>(`/replication/sources/${s.id}/sync`, {}), (d) =>
      t.repl.syncStarted(d.jobs.length),
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

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      notify('ok', t.users.copied);
    } catch {
      /* clipboard unavailable: the code is selectable */
    }
  }
</script>

<h1>{t.repl.title}</h1>
<p class="muted">{t.repl.intro}</p>
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
              <td class="mono">{p.keyd_fingerprint ?? '—'}</td>
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
              <td><span class="chip {stateCls[s.state] ?? ''}">{t.repl.states[s.state] ?? s.state}</span></td>
              <td class="mono">{s.schedule}</td>
              <td>
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
                {#if s.state === 'enrolled' && can.syncReplication(session.user)}
                  <button type="button" class="small" onclick={() => syncNow(s)}>{t.repl.syncNow}</button>
                {/if}
                {#if admin}
                  <button type="button" class="small" onclick={() => setSchedule(s)}>{t.repl.schedule}</button>
                  {#if s.state !== 'enrolled'}
                    <button type="button" class="small" onclick={() => newCode(s)}>{t.repl.newCode}</button>
                  {/if}
                  <button type="button" class="small danger" onclick={() => removeSource(s)}>{t.delete}</button>
                {/if}
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
