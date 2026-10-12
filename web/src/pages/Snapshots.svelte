<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, del, act, errText, qs } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { route, navigate } from '../lib/router.svelte';
  import { fmtBytes, fmtTime, fmtAgo } from '../lib/format';
  import { t } from '../lib/i18n';
  import { notify } from '../lib/notify.svelte';
  import { hostAgentId } from '../lib/jobs';
  import { parsePluginSnapshot, pluginKinds, restoreApplies, snapshotKind } from '../lib/plugins';
  import { buildValue, initValues, type FormValues } from '../lib/schema';
  import type { Agent, Plugin, PluginRestore, PveSource, Snapshot, Source, Tenant } from '../lib/types';
  import Check from '../components/Check.svelte';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import RestoreFiles from '../components/RestoreFiles.svelte';
  import SchemaForm from '../components/SchemaForm.svelte';
  import Menu, { type MenuItem } from '../components/Menu.svelte';
  import IconFolder from '@lucide/svelte/icons/folder-open';
  import IconRestore from '@lucide/svelte/icons/archive-restore';
  import IconZap from '@lucide/svelte/icons/zap';
  import IconHost from '@lucide/svelte/icons/hard-drive';
  import IconPlugin from '@lucide/svelte/icons/puzzle';
  import IconTrash from '@lucide/svelte/icons/trash-2';

  let snaps: Snapshot[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let sources: Source[] = $state([]);
  let agents: Agent[] = $state([]);
  let plugins: Plugin[] = $state([]);
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
    try {
      agents = await get<Agent[]>('/agents');
    } catch {
      /* host snapshots then show only the agent id */
    }
    try {
      plugins = await get<Plugin[]>('/plugins');
    } catch {
      /* plugin snapshots then offer only the file browser */
    }
  });
  const kinds = $derived(pluginKinds(plugins));

  // Plugin snapshots (`plugin-<plugin id>-<source id>[-<guest>]`): restores of the source's kind.
  const pluginOf = (s: Snapshot) => {
    const p = parsePluginSnapshot(s.source);
    if (!p) return null;
    return {
      ...p,
      sourceName: sources.find((x) => x.id === p.sourceId)?.name ?? null,
      kind: snapshotKind(s.source, sources, kinds)?.kind ?? null,
    };
  };

  let prOpen = $state(false);
  let prSnap: Snapshot | null = $state(null);
  let prRestore: PluginRestore | null = $state(null);
  let prValues: FormValues = $state({});
  let prErrors: Record<string, string> = $state({});
  let prMinutes = $state(60);
  const isMount = (r: PluginRestore | null) => r?.id === 'mount';

  function openPluginRestore(s: Snapshot, r: PluginRestore) {
    prSnap = s;
    prRestore = r;
    prValues = initValues(r.params_schema);
    prErrors = {};
    prMinutes = 60;
    prOpen = true;
  }

  async function startPluginRestore(e: SubmitEvent) {
    e.preventDefault();
    if (!prSnap || !prRestore) return;
    const { value, errors } = buildValue(prRestore.params_schema, prValues);
    prErrors = errors;
    const minutes = Number(prMinutes);
    if (Object.keys(errors).length || (isMount(prRestore) && !(Number.isInteger(minutes) && minutes >= 1 && minutes <= 1440))) {
      notify('error', t.schema.invalid);
      return;
    }
    busy = true;
    const base = { source: prSnap.source, time: prSnap.time };
    const job = isMount(prRestore)
      ? { kind: 'plugin_mount', tenant: prSnap.tenant, params: { ...base, params: value, minutes } }
      : { kind: 'plugin_restore', tenant: prSnap.tenant, params: { ...base, restore: prRestore.id, params: value } };
    const r = await act(post<{ id: number }>('/jobs', job), (d) => t.snap.jobStarted(d.id));
    busy = false;
    if (r) prOpen = false;
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }
  const agentOf = (s: Snapshot) => {
    const id = hostAgentId(s.source);
    return id ? (agents.find((a) => a.id === id) ?? null) : null;
  };

  // NFS/SMB share snapshots (`share-<source id>`): show the source's name.
  const shareName = (s: Snapshot) => {
    const m = /^share-(\d+)$/.exec(s.source);
    return m ? (sources.find((x) => x.id === Number(m[1]))?.name ?? null) : null;
  };

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

  const pveSources = $derived(sources.filter((s): s is PveSource => s.kind === 'pve'));
  const tenantSources = $derived(pveSources.filter((s) => sel && s.tenant === sel.tenant));
  const nodeNames = $derived([...new Set(tenantSources.flatMap((s) => Object.keys(s.config?.nodes ?? {})))]);

  function openRestore(s: Snapshot, m: 'restore' | 'instant') {
    sel = s;
    mode = m;
    target = '';
    node = '';
    // the source's `storage` is the NexusBackup storage itself, not a place for restored disks
    storage = '';
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

  // Restore files of a host snapshot to a path (agents)
  let rfOpen = $state(false);
  let rfSnap: Snapshot | null = $state(null);
  function openRestoreFiles(s: Snapshot) {
    rfSnap = s;
    rfOpen = true;
  }

  // Restore options of a snapshot, offered in one menu (long plugin restore titles fit there).
  function restoreItems(s: Snapshot): MenuItem[] {
    if (hostAgentId(s.source))
      return [{ label: t.snap.restorePath, hint: t.snap.restorePathHint, icon: IconHost, onselect: () => openRestoreFiles(s) }];
    const pl = pluginOf(s);
    if (pl)
      return (pl.kind?.restores ?? [])
        .filter((r) => r.id !== 'download' && restoreApplies(r, pl.guest))
        .map((r) => ({ label: r.title, hint: r.app_specific ? t.snap.appSpecific : undefined, icon: IconPlugin, onselect: () => openPluginRestore(s, r) }));
    // TrueNAS datasets and NFS/SMB shares: file download only (docs/truenas-connector.md, docs/nas-connector.md)
    if (s.source.startsWith('nas-') || s.source.startsWith('share-')) return [];
    const items: MenuItem[] = [{ label: t.snap.fullRestore, hint: t.snap.fullRestoreHint, icon: IconRestore, onselect: () => openRestore(s, 'restore') }];
    if (s.source.startsWith('vm-'))
      items.push({ label: t.snap.instant, hint: t.snap.instantHintShort, icon: IconZap, onselect: () => openRestore(s, 'instant') });
    return items;
  }

  // Manual delete (approval `snapshot.delete`): local, unlocked, not replicated snapshots only.
  const deletable = (s: Snapshot) => can.configure(session.user) && s.local && !s.origin && s.lock_until <= now;
  async function remove(s: Snapshot) {
    if (!(await askConfirm(t.snap.deleteConfirm(s.source, fmtTime(s.time))))) return;
    const path = `/snapshots/${encodeURIComponent(s.tenant)}/${encodeURIComponent(s.source)}/${s.time}`;
    await act(del(path), t.snap.deleteQueued);
  }

  function browse(s: Snapshot) {
    navigate('/files' + qs({ tenant: s.tenant, source: s.source, time: s.time, path: '/' }));
  }
</script>

<div class="page-head">
  <h1>{t.snap.title}</h1>
  <p class="lede">{t.snap.lede}</p>
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
            {@const ag = agentOf(s)}
            {@const sh = shareName(s)}
            {@const pl = pluginOf(s)}
            {@const download = pl?.kind?.restores.find((r) => r.id === 'download')}
            {@const items = restoreItems(s)}
            <tr>
              <td>
                <span class="mono">{s.source}</span>
                {#if ag}<div class="muted">{t.snap.agent(ag.name)}</div>{/if}
                {#if sh}<div class="muted">{t.snap.share(sh)}</div>{/if}
                {#if pl}
                  <div class="muted">
                    {t.snap.plugin(pl.sourceName ?? `#${pl.sourceId}`)}{pl.kind ? ` · ${pl.kind.title}` : ''}{pl.guest
                      ? ` · ${t.snap.pluginGuest(pl.guest)}`
                      : ''}
                  </div>
                {/if}
                {#if s.origin}<div><span class="chip info">{t.snap.replicatedFrom(s.origin)}</span></div>{/if}
              </td>
              <td>{s.tenant}</td>
              <td class="nowrap">{fmtTime(s.time)}</td>
              <td class="num">{fmtBytes(s.size)}</td>
              <td><Check on={s.local} /></td>
              <td><Check on={s.offsite} /></td>
              <td><Check on={s.verified} title={s.verified ? fmtAgo(s.verified) : ''} /></td>
              <td class="nowrap">{s.lock_until > now ? fmtTime(s.lock_until) : '—'}</td>
              {#if can.restore(session.user)}
                <td class="actions">
                  <button
                    type="button"
                    class="small"
                    onclick={() => browse(s)}
                    title={pl && !pl.kind ? t.snap.pluginUnknown : undefined}><IconFolder aria-hidden="true" />{download?.title ?? t.snap.browse}</button
                  >
                  {#if items.length}
                    <Menu label={t.snap.restoreMenu} ariaLabel={t.snap.restoreMenuLabel(s.source)} {items} />
                  {/if}
                  {#if deletable(s)}
                    <button type="button" class="small danger" onclick={() => remove(s)} aria-label={t.snap.deleteLabel(s.source, fmtTime(s.time))}
                      ><IconTrash aria-hidden="true" />{t.delete}</button
                    >
                  {/if}
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
          <input id="r-storage" bind:value={storage} required placeholder="local-lvm" />
        </div>
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (dlgOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}>{t.snap.start}</button>
      </div>
    </form>
  {/if}
</Modal>

<Modal
  bind:open={prOpen}
  title={prSnap && prRestore ? t.snap.pluginRestoreTitle(prRestore.title, prSnap.source) : ''}
  wide
>
  {#if prSnap && prRestore}
    <form onsubmit={startPluginRestore}>
      <p class="muted">
        {prSnap.tenant} · {fmtTime(prSnap.time)}
        {#if prRestore.app_specific}<span class="chip info">{t.snap.appSpecific}</span>{/if}
      </p>
      {#if prRestore.params_schema && Object.keys(prRestore.params_schema.properties ?? {}).length}
        <SchemaForm schema={prRestore.params_schema} bind:values={prValues} errors={prErrors} />
      {:else if !isMount(prRestore)}
        <p class="muted">{t.snap.noParams}</p>
      {/if}
      {#if isMount(prRestore)}
        <div class="field">
          <label for="pr-min">{t.snap.mountMinutes}</label>
          <input id="pr-min" type="number" min="1" max="1440" step="1" bind:value={prMinutes} required aria-describedby="pr-min-hint" />
          <div class="hint" id="pr-min-hint">{t.snap.mountMinutesHint}</div>
        </div>
      {/if}
      <div class="form-actions">
        <button type="button" onclick={() => (prOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}>{t.snap.start}</button>
      </div>
    </form>
  {/if}
</Modal>

{#if rfSnap}
  <RestoreFiles bind:open={rfOpen} tenant={rfSnap.tenant} source={rfSnap.source} time={rfSnap.time} paths={['/']} {agents} />
{/if}

