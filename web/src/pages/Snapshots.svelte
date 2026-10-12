<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, del, act, errText, qs } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { route, navigate, href } from '../lib/router.svelte';
  import { fmtBytes, fmtTime, fmtAgo } from '../lib/format';
  import { t } from '../lib/i18n';
  import { notify } from '../lib/notify.svelte';
  import { hostAgentId } from '../lib/jobs';
  import { parsePluginSnapshot, pluginKinds, restoreApplies, snapshotKind } from '../lib/plugins';
  import { buildValue, initValues, type FormValues } from '../lib/schema';
  import type { Agent, Group, Plugin, PluginRestore, PveSource, Snapshot, Source, Tenant } from '../lib/types';
  import ConsistencyBadge from '../components/ConsistencyBadge.svelte';
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
  import IconLayers from '@lucide/svelte/icons/layers';
  import IconGavel from '@lucide/svelte/icons/gavel';
  import IconUnlock from '@lucide/svelte/icons/lock-open';
  import HoldDialog from '../components/HoldDialog.svelte';

  let snaps: Snapshot[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let sources: Source[] = $state([]);
  let agents: Agent[] = $state([]);
  let plugins: Plugin[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  let tenant = $state(route.query.get('tenant') ?? '');
  let source = $state(route.query.get('source') ?? '');
  let heldOnly = $state(route.query.get('held') === 'true');

  async function load() {
    try {
      snaps = await get<Snapshot[]>(
        '/snapshots' + qs({ tenant: route.query.get('tenant'), source: route.query.get('source'), held: route.query.get('held') }),
      );
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
    navigate('/snapshots' + qs({ tenant, source: source.trim(), held: heldOnly ? 'true' : '' }));
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
  // Phase 15a options
  let rName = $state('');
  let rPrefix = $state('');
  let rPool = $state('');
  let rStart = $state(false);
  let rLinkDown = $state(false);
  let rReplace = $state(false);
  let rKeepLinks = $state(false);

  const pveSources = $derived(sources.filter((s): s is PveSource => s.kind === 'pve'));
  const nodesOf = (tenant: string | undefined) => [
    ...new Set(pveSources.filter((s) => s.tenant === tenant).flatMap((s) => Object.keys(s.config?.nodes ?? {}))),
  ];
  const nodeNames = $derived(nodesOf((sel as Snapshot | null)?.tenant));

  function openRestore(s: Snapshot, m: 'restore' | 'instant') {
    sel = s;
    mode = m;
    target = '';
    node = '';
    // the source's `storage` is the NexusBackup storage itself, not a place for restored disks
    storage = '';
    node = nodeNames[0] ?? '';
    rName = '';
    rPrefix = '';
    rPool = '';
    // instant recovery: running at once, isolated from the original by default
    rStart = m === 'instant';
    rLinkDown = m === 'instant';
    rReplace = false;
    rKeepLinks = false;
    dlgOpen = true;
  }
  $effect(() => {
    if (dlgOpen && !node && nodeNames.length) node = nodeNames[0];
  });
  const origVmid = (s: Snapshot | null) => s?.source.replace(/^(vm|ct)-/, '') ?? '';

  async function startRestore(e: SubmitEvent) {
    e.preventDefault();
    if (!sel) return;
    busy = true;
    const kind = mode === 'instant' ? 'instant_recover' : sel.source.startsWith('ct-') ? 'restore_ct' : 'restore';
    const params: Record<string, unknown> = {
      source: sel.source,
      time: sel.time,
      node,
      target: Number(target),
      storage,
      start: rStart,
      link_down: rLinkDown,
    };
    if (rName.trim() && mode !== 'instant') params.name = rName.trim();
    else if (rPrefix.trim()) params.name_prefix = rPrefix.trim();
    if (rPool.trim()) params.pool = rPool.trim();
    if (rReplace && mode === 'restore') {
      params.replace = true;
      if (rKeepLinks) params.keep_original_links = true;
    }
    const r = await act(post<{ id?: number }>('/jobs', { kind, tenant: sel.tenant, params }), (d) =>
      d.id ? t.snap.jobStarted(d.id) : t.ropts.replaceQueued,
    );
    busy = false;
    if (r) dlgOpen = false;
    if (r && !r.quorum && r.data?.id) navigate(`/jobs/${r.data.id}`);
  }

  // Restore several guests (one job each, `POST /restores`)
  let manyOpen = $state(false);
  let manyTenant = $state('');
  let manyChecked: Record<string, boolean> = $state({});
  let manyGroup = $state('');
  let manyBase = $state('');
  let groups: Group[] = $state([]);
  const manyLatest = $derived.by(() => {
    const m = new Map<string, Snapshot>();
    for (const s of snaps)
      if (s.tenant === manyTenant && s.local && /^(vm|ct)-\d+$/.test(s.source) && (m.get(s.source)?.time ?? -1) < s.time) m.set(s.source, s);
    return [...m.values()].sort((a, b) => a.source.localeCompare(b.source, undefined, { numeric: true }));
  });
  const manyPicked = $derived(manyLatest.filter((s) => manyChecked[s.source]));
  const manyTenants = $derived([...new Set(snaps.filter((s) => /^(vm|ct)-/.test(s.source)).map((s) => s.tenant))].sort());

  async function openMany() {
    manyTenant = manyTenants.includes(tenant) ? tenant : (manyTenants[0] ?? '');
    manyChecked = {};
    manyGroup = '';
    manyBase = '';
    node = nodesOf(manyTenant)[0] ?? '';
    storage = '';
    rPrefix = 'restore-';
    rPool = '';
    rStart = false;
    rLinkDown = true;
    manyOpen = true;
    try {
      groups = await get<Group[]>('/groups');
    } catch {
      groups = [];
    }
  }
  function pickGroup() {
    const g = groups.find((x) => String(x.id) === manyGroup);
    if (!g) return;
    const ids = new Set((g.guests ?? []).map(String));
    manyChecked = Object.fromEntries(manyLatest.map((s) => [s.source, ids.has(s.source.replace(/^(vm|ct)-/, ''))]));
  }

  async function startMany(e: SubmitEvent) {
    e.preventDefault();
    if (!manyPicked.length) return;
    busy = true;
    const body: Record<string, unknown> = {
      tenant: manyTenant,
      node,
      storage,
      target_base: Number(manyBase),
      start: rStart,
      link_down: rLinkDown,
      items: manyPicked.map((s) => ({ source: s.source, time: s.time })),
    };
    if (rPrefix.trim()) body.name_prefix = rPrefix.trim();
    if (rPool.trim()) body.pool = rPool.trim();
    const r = await act(post<{ ids: number[] }>('/restores', body), (d) => t.ropts.manyStarted(d.ids.length));
    busy = false;
    if (r) {
      manyOpen = false;
      navigate('/jobs');
    }
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
    // any file tree onto a host with an agent of the tenant (Phase 15b)
    const toHost: MenuItem = { label: t.snap.restoreToHost, hint: t.snap.restoreToHostHint, icon: IconHost, onselect: () => openRestoreFiles(s) };
    const pl = pluginOf(s);
    if (pl) {
      const items: MenuItem[] = (pl.kind?.restores ?? [])
        .filter((r) => r.id !== 'download' && restoreApplies(r, pl.guest))
        .map((r) => ({ label: r.title, hint: r.app_specific ? t.snap.appSpecific : undefined, icon: IconPlugin, onselect: () => openPluginRestore(s, r) }));
      // plugins with a download restore keep plain files in their snapshots
      if (pl.kind?.restores.some((r) => r.id === 'download')) items.push(toHost);
      return items;
    }
    // TrueNAS datasets and NFS/SMB shares (docs/truenas-connector.md, docs/nas-connector.md)
    if (s.source.startsWith('nas-') || s.source.startsWith('share-')) return [toHost];
    const items: MenuItem[] = [{ label: t.snap.fullRestore, hint: t.snap.fullRestoreHint, icon: IconRestore, onselect: () => openRestore(s, 'restore') }];
    if (s.source.startsWith('vm-'))
      items.push({ label: t.snap.instant, hint: t.snap.instantHintShort, icon: IconZap, onselect: () => openRestore(s, 'instant') });
    // VM/CT files: chosen in the file browser (restore micro-VM), then restored onto a host
    items.push({ label: t.snap.restoreFilesToHost, hint: t.snap.restoreFilesToHostHint, icon: IconHost, onselect: () => browse(s) });
    return items;
  }

  // Manual delete (approval `snapshot.delete`): local, unlocked, not replicated, not held snapshots only.
  const deletable = (s: Snapshot) =>
    can.configure(session.user) && s.local && !s.origin && s.lock_until <= now && s.hold?.state !== 'active';

  // Legal hold (15c): security officers set (or apply an advisory) at once; release needs approval.
  let holdOpen = $state(false);
  let holdTarget: Snapshot | null = $state(null);
  let holdReason = $state('');
  function openHold(s: Snapshot | null) {
    holdTarget = s;
    holdReason = s?.hold?.state === 'advisory' ? s.hold.reason : '';
    holdOpen = true;
  }
  async function releaseHold(s: Snapshot) {
    if (!(await askConfirm(t.snap.releaseConfirm(s.source, fmtTime(s.time))))) return;
    const path = `/snapshots/${encodeURIComponent(s.tenant)}/${encodeURIComponent(s.source)}/${s.time}/hold`;
    if (await act(del(path), t.snap.releaseQueued)) load();
  }
  const showActions = $derived(can.restore(session.user) || can.hold(session.user) || can.releaseHold(session.user));
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
  {#if can.restore(session.user) && manyTenants.length}
    <button type="button" onclick={openMany}><IconLayers aria-hidden="true" />{t.ropts.many}</button>
  {/if}
  {#if can.hold(session.user)}
    <button type="button" onclick={() => openHold(null)}><IconGavel aria-hidden="true" />{t.snap.holdRange}</button>
  {/if}
  {#if can.restore(session.user)}<a class="button" href={href('/search' + qs({ tenant }))}>{t.snap.find}</a>{/if}
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
  <label class="inline-check"><input type="checkbox" bind:checked={heldOnly} />{t.snap.heldOnly}</label>
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
            <th scope="col">{t.cons.column}</th>
            {#if showActions}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
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
                {#if s.hold?.state === 'active'}
                  <div>
                    <span class="chip warn plain hold" title={t.snap.heldTitle(s.hold.held_by, fmtTime(s.hold.held_at), s.hold.reason)}
                      ><IconGavel aria-hidden="true" />{t.snap.held}{s.hold.release_quorum ? ` · ${t.snap.releasePending}` : ''}</span
                    >
                  </div>
                {:else if s.hold}
                  <div>
                    <span class="chip info plain hold" title={t.snap.advisoryTitle(s.hold.held_by, s.hold.reason)}
                      ><IconGavel aria-hidden="true" />{t.snap.advisory(s.hold.origin ?? '?')}</span
                    >
                  </div>
                {/if}
              </td>
              <td>{s.tenant}</td>
              <td class="nowrap">{fmtTime(s.time)}</td>
              <td class="num">{fmtBytes(s.size)}</td>
              <td><Check on={s.local} /></td>
              <td><Check on={s.offsite} /></td>
              <td><Check on={s.verified} title={s.verified ? fmtAgo(s.verified) : ''} /></td>
              <td class="nowrap">{s.lock_until > now ? fmtTime(s.lock_until) : '—'}</td>
              <td><ConsistencyBadge level={s.consistency} /></td>
              {#if showActions}
                <td class="actions">
                  {#if can.restore(session.user)}
                    <button
                      type="button"
                      class="small"
                      onclick={() => browse(s)}
                      title={pl && !pl.kind ? t.snap.pluginUnknown : undefined}><IconFolder aria-hidden="true" />{download?.title ?? t.snap.browse}</button
                    >
                    {#if items.length}
                      <Menu label={t.snap.restoreMenu} ariaLabel={t.snap.restoreMenuLabel(s.source)} {items} />
                    {/if}
                  {/if}
                  {#if can.hold(session.user) && s.hold?.state !== 'active'}
                    <button type="button" class="small" onclick={() => openHold(s)} aria-label={t.snap.holdLabel(s.source, fmtTime(s.time))}
                      ><IconGavel aria-hidden="true" />{s.hold ? t.snap.applyHold : t.snap.hold}</button
                    >
                  {:else if can.releaseHold(session.user) && s.hold?.state === 'active' && !s.hold.release_quorum}
                    <button type="button" class="small" onclick={() => releaseHold(s)} aria-label={t.snap.releaseLabel(s.source, fmtTime(s.time))}
                      ><IconUnlock aria-hidden="true" />{t.snap.release}</button
                    >
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
      <fieldset>
        <legend>{t.ropts.options}</legend>
        <div class="form-grid">
          {#if mode === 'restore'}
            <div class="field">
              <label for="r-name">{t.ropts.name}</label>
              <input id="r-name" bind:value={rName} disabled={!!rPrefix.trim()} pattern="[A-Za-z0-9_][A-Za-z0-9._\-]{'{0,62}'}" aria-describedby="r-name-hint" />
              <div class="hint" id="r-name-hint">{t.ropts.nameHint('<name>-restore')}</div>
            </div>
          {/if}
          <div class="field">
            <label for="r-prefix">{t.ropts.prefix}</label>
            <input id="r-prefix" bind:value={rPrefix} disabled={!!rName.trim() && mode === 'restore'} pattern="[A-Za-z0-9_][A-Za-z0-9._\-]{'{0,62}'}" aria-describedby="r-prefix-hint" />
            <div class="hint" id="r-prefix-hint">{t.ropts.prefixHint}</div>
          </div>
          <div class="field">
            <label for="r-pool">{t.ropts.pool}</label>
            <input id="r-pool" bind:value={rPool} pattern="[A-Za-z0-9_][A-Za-z0-9._\-]{'{0,62}'}" aria-describedby="r-pool-hint" />
            <div class="hint" id="r-pool-hint">{t.ropts.poolHint}</div>
          </div>
        </div>
        <div class="field">
          <label class="inline-check"><input id="r-start" type="checkbox" bind:checked={rStart} />{mode === 'instant' ? t.ropts.irStart : t.ropts.start}</label>
        </div>
        <div class="field">
          <label class="inline-check"><input id="r-linkdown" type="checkbox" bind:checked={rLinkDown} />{t.ropts.linkDown}</label>
          <div class="hint">{t.ropts.linkDownHint}</div>
        </div>
        {#if mode === 'restore' && can.backup(session.user)}
          <div class="field">
            <label class="inline-check"><input id="r-replace" type="checkbox" bind:checked={rReplace} />{t.ropts.replace}</label>
          </div>
          {#if rReplace}
            <p class="banner warn">{t.ropts.replaceHint(origVmid(sel))}</p>
            <div class="field">
              <label class="inline-check"><input id="r-keeplinks" type="checkbox" bind:checked={rKeepLinks} />{t.ropts.keepLinks}</label>
            </div>
          {/if}
        {/if}
      </fieldset>
      <div class="form-actions">
        <button type="button" onclick={() => (dlgOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}>{t.snap.start}</button>
      </div>
    </form>
  {/if}
</Modal>

<Modal bind:open={manyOpen} title={t.ropts.manyTitle} wide>
  <form onsubmit={startMany}>
    <p class="muted">{t.ropts.manyIntro}</p>
    <div class="form-grid">
      {#if manyTenants.length > 1}
        <div class="field">
          <label for="m-tenant">{t.tenant}</label>
          <select id="m-tenant" bind:value={manyTenant} onchange={() => ((manyChecked = {}), (node = nodesOf(manyTenant)[0] ?? ''))}>
            {#each manyTenants as tn (tn)}<option value={tn}>{tn}</option>{/each}
          </select>
        </div>
      {/if}
      <div class="field">
        <label for="m-group">{t.ropts.manyGroup}</label>
        <select id="m-group" bind:value={manyGroup} onchange={pickGroup}>
          <option value="">{t.ropts.manyGroupNone}</option>
          {#each groups.filter((g) => g.tenant === manyTenant) as g (g.id)}<option value={String(g.id)}>{g.name}</option>{/each}
        </select>
      </div>
    </div>
    <fieldset>
      <legend>{t.ropts.manyGuests} <span class="muted">({t.ropts.manySelected(manyPicked.length)})</span></legend>
      {#if manyLatest.length === 0}
        <p class="empty">{t.ropts.manyNone}</p>
      {:else}
        <div class="check-list">
          {#each manyLatest as s (s.source)}
            <label class="inline-check"
              ><input type="checkbox" bind:checked={manyChecked[s.source]} /><span class="mono">{s.source}</span>
              <span class="muted">{fmtTime(s.time)}</span>
              <ConsistencyBadge level={s.consistency} /></label
            >
          {/each}
        </div>
      {/if}
    </fieldset>
    <div class="form-grid">
      <div class="field">
        <label for="m-node">{t.snap.node}</label>
        <input id="m-node" bind:value={node} list="m-nodes" required autocomplete="off" />
        <datalist id="m-nodes">{#each nodesOf(manyTenant) as n (n)}<option value={n}></option>{/each}</datalist>
      </div>
      <div class="field">
        <label for="m-base">{t.ropts.manyBase}</label>
        <input id="m-base" type="number" min="100" max="999999999" bind:value={manyBase} required />
      </div>
      <div class="field">
        <label for="m-storage">{t.snap.storage}</label>
        <input id="m-storage" bind:value={storage} required placeholder="local-lvm" />
      </div>
      <div class="field">
        <label for="m-prefix">{t.ropts.prefix}</label>
        <input id="m-prefix" bind:value={rPrefix} pattern="[A-Za-z0-9_][A-Za-z0-9._\-]{'{0,62}'}" />
      </div>
      <div class="field">
        <label for="m-pool">{t.ropts.pool}</label>
        <input id="m-pool" bind:value={rPool} pattern="[A-Za-z0-9_][A-Za-z0-9._\-]{'{0,62}'}" />
      </div>
    </div>
    <div class="field">
      <label class="inline-check"><input id="m-start" type="checkbox" bind:checked={rStart} />{t.ropts.start}</label>
    </div>
    <div class="field">
      <label class="inline-check"><input id="m-linkdown" type="checkbox" bind:checked={rLinkDown} />{t.ropts.linkDown}</label>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (manyOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={busy || !manyPicked.length}>{t.snap.start}</button>
    </div>
  </form>
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

<HoldDialog
  bind:open={holdOpen}
  target={holdTarget}
  reason={holdReason}
  tenants={session.user?.tenant ? [session.user.tenant] : tenants.map((x) => x.name)}
  tenant={route.query.get('tenant') ?? ''}
  sources={guestNames}
  ondone={load}
/>

{#if rfSnap}
  <RestoreFiles bind:open={rfOpen} tenant={rfSnap.tenant} source={rfSnap.source} time={rfSnap.time} paths={['/']} {agents} />
{/if}


<style>
  .check-list {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(22rem, 1fr));
    gap: 0.25rem 1rem;
    max-height: 18rem;
    overflow: auto;
  }
  .check-list label {
    white-space: nowrap;
  }
  /* legal-hold badge: the gavel replaces the chip dot */
  .chip.hold :global(svg) {
    width: 0.85rem;
    height: 0.85rem;
  }
</style>
