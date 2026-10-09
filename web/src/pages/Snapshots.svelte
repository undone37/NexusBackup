<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText, qs } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { route, navigate, href } from '../lib/router.svelte';
  import { fmtBytes, fmtTime, fmtAgo } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Snapshot, Source, Tenant } from '../lib/types';
  import Check from '../components/Check.svelte';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let snaps: Snapshot[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let sources: Source[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  let tenant = $state(route.query.get('tenant') ?? '');
  let source = $state(route.query.get('source') ?? '');

  async function load() {
    try {
      snaps = await get<Snapshot[]>('/snapshots' + qs({ tenant: route.query.get('tenant'), source: route.query.get('source') }));
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }

  onMount(async () => {
    load();
    try {
      [tenants, sources] = await Promise.all([get<Tenant[]>('/tenants'), get<Source[]>('/sources')]);
    } catch {
      /* filters still work as free text */
    }
  });

  function applyFilter(e: SubmitEvent) {
    e.preventDefault();
    navigate('/snapshots' + qs({ tenant, source: source.trim() }));
  }

  const guestNames = $derived([...new Set(snaps.map((s) => s.source))].sort());
  const now = Date.now() / 1000;

  // Restore / instant-recover dialog
  let dlgOpen = $state(false);
  let mode: 'restore' | 'instant' = $state('restore');
  let sel: Snapshot | null = $state(null);
  let node = $state('');
  let target = $state('');
  let storage = $state('');
  let busy = $state(false);

  const tenantSources = $derived(sources.filter((s) => sel && s.tenant === sel.tenant));
  const nodeNames = $derived([...new Set(tenantSources.flatMap((s) => Object.keys(s.config?.nodes ?? {})))]);

  function openRestore(s: Snapshot, m: 'restore' | 'instant') {
    sel = s;
    mode = m;
    target = '';
    node = '';
    storage = sources.find((x) => x.tenant === s.tenant)?.config?.storage ?? '';
    node = nodeNames[0] ?? '';
    dlgOpen = true;
  }
  $effect(() => {
    if (dlgOpen && !node && nodeNames.length) node = nodeNames[0];
  });

  async function startRestore(e: SubmitEvent) {
    e.preventDefault();
    if (!sel) return;
    busy = true;
    const kind = mode === 'instant' ? 'instant_recover' : sel.source.startsWith('ct-') ? 'restore_ct' : 'restore';
    const params = { source: sel.source, time: sel.time, node, target: Number(target), storage };
    const r = await act(post<{ id: number }>('/jobs', { kind, tenant: sel.tenant, params }), (d) => t.snap.jobStarted(d.id));
    busy = false;
    if (r) dlgOpen = false;
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }

  function browse(s: Snapshot) {
    navigate('/files' + qs({ tenant: s.tenant, source: s.source, time: s.time, path: '/' }));
  }
</script>

<div class="page-head">
  <h1>{t.snap.title}</h1>
</div>

<form class="filters" onsubmit={applyFilter} role="search">
  {#if !session.user?.tenant}
    <div class="field">
      <label for="f-tenant">{t.snap.filterTenant}</label>
      <select id="f-tenant" bind:value={tenant}>
        <option value="">{t.all}</option>
        {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
      </select>
    </div>
  {/if}
  <div class="field">
    <label for="f-source">{t.snap.filterSource}</label>
    <input id="f-source" bind:value={source} list="guest-names" autocomplete="off" />
    <datalist id="guest-names">
      {#each guestNames as g (g)}<option value={g}></option>{/each}
    </datalist>
  </div>
  <button type="submit">{t.snap.apply}</button>
</form>

<ErrorBanner {error} />

<div class="card">
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if snaps.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.snap.source}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.time}</th>
            <th scope="col" class="num">{t.snap.size}</th>
            <th scope="col">{t.dash.local}</th>
            <th scope="col">{t.dash.offsite}</th>
            <th scope="col">{t.dash.verified}</th>
            <th scope="col">{t.snap.lock}</th>
            {#if can.restore(session.user)}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each snaps as s (`${s.tenant}/${s.source}/${s.time}`)}
            <tr>
              <td class="mono">{s.source}</td>
              <td>{s.tenant}</td>
              <td class="nowrap">{fmtTime(s.time)}</td>
              <td class="num">{fmtBytes(s.size)}</td>
              <td><Check on={s.local} /></td>
              <td><Check on={s.offsite} /></td>
              <td><Check on={s.verified} title={s.verified ? fmtAgo(s.verified) : ''} /></td>
              <td class="nowrap">{s.lock_until > now ? fmtTime(s.lock_until) : '—'}</td>
              {#if can.restore(session.user)}
                <td class="actions">
                  <button type="button" class="small" onclick={() => openRestore(s, 'restore')}>{t.snap.restore}</button>
                  {#if s.source.startsWith('vm-')}
                    <button type="button" class="small" onclick={() => openRestore(s, 'instant')}>{t.snap.instant}</button>
                  {/if}
                  <button type="button" class="small" onclick={() => browse(s)}>{t.snap.browse}</button>
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal
  bind:open={dlgOpen}
  title={sel ? (mode === 'instant' ? t.snap.instantTitle(sel.source) : t.snap.restoreTitle(sel.source)) : ''}
>
  {#if sel}
    <form onsubmit={startRestore}>
      <p class="muted">{sel.tenant} · {fmtTime(sel.time)}</p>
      {#if mode === 'instant'}<p class="banner info">{t.snap.instantHint}</p>{/if}
      <div class="field">
        <label for="r-node">{t.snap.node}</label>
        <input id="r-node" bind:value={node} list="r-nodes" required autocomplete="off" />
        <datalist id="r-nodes">{#each nodeNames as n (n)}<option value={n}></option>{/each}</datalist>
      </div>
      <div class="form-grid">
        <div class="field">
          <label for="r-target">{t.snap.target}</label>
          <input id="r-target" type="number" min="100" max="999999999" bind:value={target} required />
        </div>
        <div class="field">
          <label for="r-storage">{t.snap.storage}</label>
          <input id="r-storage" bind:value={storage} required />
        </div>
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (dlgOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}>{t.snap.start}</button>
      </div>
    </form>
  {/if}
</Modal>

<p class="muted"><a href={href('/jobs')}>{t.nav.jobs} →</a></p>
