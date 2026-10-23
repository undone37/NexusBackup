<script lang="ts">
  import { jobLink } from '../lib/jobs';
  import { labelOf } from '../lib/names.svelte';
  import SourceName from '../components/SourceName.svelte';
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
  import SyntheticRestore from '../components/SyntheticRestore.svelte';
  import IconClean from '@lucide/svelte/icons/file-check';
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
  import FlaggedNotice from '../components/FlaggedNotice.svelte';
  import IconDiff from '@lucide/svelte/icons/file-diff';
  import IconCheck from '@lucide/svelte/icons/shield-check';
  import IconCloudDown from '@lucide/svelte/icons/cloud-download';
  import IconWrench from '@lucide/svelte/icons/wrench';
  import IconScan from '@lucide/svelte/icons/scan-search';
  import ScanFirst from '../components/ScanFirst.svelte';
  import ScanResults from '../components/ScanResults.svelte';
  import RecoveryCalendar from '../components/RecoveryCalendar.svelte';
  import type { ScanFirst as ScanFirstOpt } from '../lib/types';
  import { fetchFromOffsite } from '../lib/offsite';
  import InstantDisk from '../components/InstantDisk.svelte';
  import InfectedNotice from '../components/InfectedNotice.svelte';
  import ScanBack from '../components/ScanBack.svelte';
  import IconHistory from '@lucide/svelte/icons/history';
  import IconBadge from '@lucide/svelte/icons/badge-check';
  import IconDisk from '@lucide/svelte/icons/hard-drive-download';

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
  // Phase 17d: local copies, or offsite-only ones (pruned locally, still on the offsite target)
  let where = $state(route.query.get('where') ?? '');
  const offsiteOnly = (s: Snapshot) => !s.local && (s.offsite || !!s.offsite2);
  // Phase 30: a column for the second offsite target once any snapshot is there
  const hasSecond = $derived(snaps.some((s) => s.offsite2));
  const shown = $derived(
    snaps.filter((s) => (where === 'local' ? s.local : where === 'offsite' ? offsiteOnly(s) : true)),
  );

  async function load() {
    try {
      snaps = await get<Snapshot[]>(
        '/snapshots' +
          qs({ tenant: route.query.get('tenant'), source: route.query.get('source'), held: route.query.get('held') }),
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
  let prScan: ScanFirstOpt | '' = $state('');
  // manifest v1.6 `target_source`: '' = the snapshot's own source
  let prTarget = $state('');
  const prOwn = $derived(
    prSnap ? (sources.find((x) => x.id === parsePluginSnapshot(prSnap!.source)?.sourceId) ?? null) : null,
  );
  const prTargets = $derived.by(() => {
    const own = prOwn;
    if (!prSnap || !own || !prRestore?.target_source) return [];
    return sources.filter((x) => x.kind === own.kind && x.tenant === prSnap!.tenant && x.id !== own.id);
  });
  const isMount = (r: PluginRestore | null) => r?.id === 'mount';

  function openPluginRestore(s: Snapshot, r: PluginRestore) {
    prSnap = preferClean(s);
    prRestore = r;
    prValues = initValues(r.params_schema);
    prErrors = {};
    prMinutes = 60;
    prScan = '';
    prPick = '';
    prTarget = '';
    prOpen = true;
  }

  // Phase 18b: a snapshot's recoverable range (plugin metadata, e.g. PostgreSQL) bounds
  // the point-in-time target: a picker in local time fills `target_time` (UTC).
  const range = $derived((prSnap as Snapshot | null)?.meta?.recoverable ?? null);
  const hasTimeTarget = $derived(!!(prRestore as PluginRestore | null)?.params_schema?.properties?.target_time);
  let prPick = $state('');
  const two = (n: number) => String(n).padStart(2, '0');
  const localInput = (ts: number) => {
    const d = new Date(ts * 1000);
    return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}T${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
  };
  function pickTime(v: string) {
    prPick = v;
    const d = new Date(v);
    if (!v || Number.isNaN(d.getTime())) return;
    const iso = d.toISOString();
    prValues.target_time = `${iso.slice(0, 10)} ${iso.slice(11, 19)}+00`;
  }
  /** `target_time` as unix seconds, null = empty or not parseable here (the plugin checks). */
  function targetSecs(v: unknown): number | null {
    const s = String(v ?? '').trim();
    if (!s) return null;
    const n = Date.parse(s.replace(' ', 'T').replace(/([+-]\d{2})$/, '$1:00'));
    return Number.isNaN(n) ? null : Math.floor(n / 1000);
  }

  async function startPluginRestore(e: SubmitEvent) {
    e.preventDefault();
    if (!prSnap || !prRestore) return;
    const { value, errors } = buildValue(prRestore.params_schema, prValues);
    const ts = targetSecs(value.target_time);
    if (range && ts !== null && (ts < range.from_time || ts > range.to_time)) {
      errors.target_time = t.snap.outOfRange(fmtTime(range.from_time), fmtTime(range.to_time));
    }
    prErrors = errors;
    const minutes = Number(prMinutes);
    if (
      Object.keys(errors).length ||
      (isMount(prRestore) && !(Number.isInteger(minutes) && minutes >= 1 && minutes <= 1440))
    ) {
      notify('error', t.schema.invalid);
      return;
    }
    busy = true;
    const base = { source: prSnap.source, time: prSnap.time };
    const job = isMount(prRestore)
      ? { kind: 'plugin_mount', tenant: prSnap.tenant, params: { ...base, params: value, minutes } }
      : {
          kind: 'plugin_restore',
          tenant: prSnap.tenant,
          params: {
            ...base,
            restore: prRestore.id,
            params: value,
            ...(prTarget ? { target_source_id: Number(prTarget) } : {}),
            ...(prScan ? { scan_first: prScan } : {}),
          },
        };
    const r = await act(post<{ id: number }>('/jobs', job), (d) => t.snap.jobStarted(d.id), jobLink);
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
    navigate('/snapshots' + qs({ tenant, source: source.trim(), held: heldOnly ? 'true' : '', where }));
  }

  const guestNames = $derived([...new Set(snaps.map((s) => s.source))].sort());

  // Phase 21a: dialogs opened on a flagged snapshot default to the latest clean one before it;
  // Phase 28: one a malware scan found clean is preferred over newer unscanned ones;
  // Phase 29: flagged = anomaly or scan hit (not cleared); the scan back's recommended point first
  const isFlagged = (s: Snapshot) => s.flagged ?? !!s.anomalous;
  const preferScanned = (list: Snapshot[]) =>
    list.find((x) => x.clean_point) ??
    list.filter((x) => x.scan_state === 'clean').sort((a, b) => b.time - a.time)[0] ??
    list.sort((a, b) => b.time - a.time)[0] ??
    null;
  const cleanBefore = (s: Snapshot) =>
    preferScanned(
      snaps.filter(
        (x) => x.tenant === s.tenant && x.source === s.source && x.local && !isFlagged(x) && x.time < s.time,
      ),
    );
  let flaggedOf: Snapshot | null = $state(null);
  function preferClean(s: Snapshot): Snapshot {
    flaggedOf = isFlagged(s) ? s : null;
    return isFlagged(s) ? (cleanBefore(s) ?? s) : s;
  }

  // Phase 29: scan back from a flagged snapshot to the last clean one (YARA, newest first)
  let sbOpen = $state(false);
  let sbSnap: Snapshot | null = $state(null);
  const scanBackable = (s: Snapshot) => can.scan(session.user) && s.local && (isFlagged(s) || s.scan_state === 'hit');

  // A security officer clears a flag (false alarm) with a note (audited).
  let clearOpen = $state(false);
  let clearSnap: Snapshot | null = $state(null);
  let clearNote = $state('');
  async function submitClear(e: SubmitEvent) {
    e.preventDefault();
    if (!clearSnap) return;
    const s = clearSnap;
    busy = true;
    const ok = await act(
      post(`/snapshots/${encodeURIComponent(s.tenant)}/${encodeURIComponent(s.source)}/${s.time}/anomaly/clear`, {
        note: clearNote.trim(),
      }),
      t.snap.flagClearedOk,
    );
    busy = false;
    if (ok) {
      clearOpen = false;
      load();
    }
  }
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
  // Phase 30: replace by rolling the VM back in place (changed chunks only)
  let rRollback = $state(false);
  // VMware snapshots (vmw-<uuid>, #34): restored as a new VM on a Proxmox VE cluster of the tenant
  let rCluster = $state('');
  let rBridge = $state('vmbr0');
  let rScan: ScanFirstOpt | '' = $state('');

  // Phase 21e: YARA scan of a snapshot (results in ScanResults)
  let scanOpen = $state(false);
  let scanSnap: Snapshot | null = $state(null);
  async function startScan(s: Snapshot) {
    if (!(await askConfirm(t.scan.scanConfirm(s.source, fmtTime(s.time))))) return;
    const path = `/snapshots/${encodeURIComponent(s.tenant)}/${encodeURIComponent(s.source)}/${s.time}/scan`;
    const r = await act(post<{ id: number }>(path, {}), (d) => t.scan.started(d.id), jobLink);
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }

  const pveSources = $derived(sources.filter((s): s is PveSource => s.kind === 'pve'));
  const nodesOf = (tenant: string | undefined, cluster?: number) => [
    ...new Set(
      pveSources
        .filter((s) => s.tenant === tenant && (cluster === undefined || s.id === cluster))
        .flatMap((s) => Object.keys(s.config?.nodes ?? {})),
    ),
  ];
  const isVmw = $derived(!!(sel as Snapshot | null)?.source.startsWith('vmw-'));
  const tenantClusters = $derived(pveSources.filter((s) => s.tenant === (sel as Snapshot | null)?.tenant));
  const nodeNames = $derived(
    nodesOf((sel as Snapshot | null)?.tenant, isVmw && rCluster ? Number(rCluster) : undefined),
  );

  function openRestore(s: Snapshot, m: 'restore' | 'instant') {
    sel = preferClean(s);
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
    rRollback = false;
    rScan = '';
    rCluster = String(pveSources.find((x) => x.tenant === s.tenant)?.id ?? '');
    rBridge = 'vmbr0';
    dlgOpen = true;
  }
  $effect(() => {
    if (dlgOpen && !node && nodeNames.length) node = nodeNames[0];
  });
  const origVmid = (s: Snapshot | null) => s?.source.replace(/^(vm|ct)-/, '') ?? '';

  // Phase 22b: instant disk recovery (one disk attached to an existing VM)
  let idrOpen = $state(false);
  let idrSnap: Snapshot | null = $state(null);
  function openInstantDisk(s: Snapshot) {
    idrSnap = preferClean(s);
    idrOpen = true;
  }

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
    if (rScan) params.scan_first = rScan;
    if (sel.source.startsWith('vmw-')) {
      params.source_id = Number(rCluster);
      params.bridge = rBridge.trim() || 'vmbr0';
    }
    if (rReplace && mode === 'restore') {
      params.replace = true;
      if (rKeepLinks) params.keep_original_links = true;
      if (rRollback && kind === 'restore') params.rollback = true;
    }
    const r = await act(
      post<{ id?: number }>('/jobs', { kind, tenant: sel.tenant, params }),
      (d) => (d.id ? t.snap.jobStarted(d.id) : t.ropts.replaceQueued),
      jobLink,
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
    const by = new Map<string, Snapshot[]>();
    // the latest clean snapshot of each guest (Phase 21a), a scanned-clean one first (Phase 28)
    for (const s of snaps)
      if (s.tenant === manyTenant && s.local && !isFlagged(s) && /^(vm|ct)-\d+$/.test(s.source))
        by.set(s.source, [...(by.get(s.source) ?? []), s]);
    return [...by.values()]
      .map((l) => preferScanned(l)!)
      .sort((a, b) => a.source.localeCompare(b.source, undefined, { numeric: true }));
  });
  const newerFlagged = (s: Snapshot) =>
    snaps
      .filter((x) => x.tenant === s.tenant && x.source === s.source && x.local && isFlagged(x) && x.time > s.time)
      .sort((a, b) => b.time - a.time)[0];
  const manyPicked = $derived(manyLatest.filter((s) => manyChecked[s.source]));
  const manyTenants = $derived(
    [...new Set(snaps.filter((s) => /^(vm|ct)-/.test(s.source)).map((s) => s.tenant))].sort(),
  );

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
    rfSnap = preferClean(s);
    rfOpen = true;
  }

  // Phase 33: clean-file restore of agent, NAS and share snapshots (the chosen snapshot, not the clean one:
  // the clean-file restore itself steps back per file)
  let synOpen = $state(false);
  let synSnap: Snapshot | null = $state(null);
  const synthetic = (s: Snapshot): MenuItem => ({
    label: t.synth.menu,
    hint: t.synth.menuHint,
    icon: IconClean,
    onselect: () => ((synSnap = s), (synOpen = true)),
  });

  // Restore options of a snapshot, offered in one menu (long plugin restore titles fit there).
  function restoreItems(s: Snapshot): MenuItem[] {
    if (hostAgentId(s.source))
      return [
        {
          label: t.snap.restorePath,
          hint: t.snap.restorePathHint,
          icon: IconHost,
          onselect: () => openRestoreFiles(s),
        },
        ...(s.local ? [synthetic(s)] : []),
      ];
    // any file tree onto a host with an agent of the tenant (Phase 15b)
    const toHost: MenuItem = {
      label: t.snap.restoreToHost,
      hint: t.snap.restoreToHostHint,
      icon: IconHost,
      onselect: () => openRestoreFiles(s),
    };
    const pl = pluginOf(s);
    if (pl) {
      const items: MenuItem[] = (pl.kind?.restores ?? [])
        .filter((r) => r.id !== 'download' && restoreApplies(r, pl.guest))
        .map((r) => ({
          label: r.title,
          hint: r.app_specific ? t.snap.appSpecific : undefined,
          icon: IconPlugin,
          onselect: () => openPluginRestore(s, r),
        }));
      // plugins with a download restore keep plain files in their snapshots
      if (pl.kind?.restores.some((r) => r.id === 'download')) items.push(toHost);
      return items;
    }
    // TrueNAS datasets and NFS/SMB shares (docs/truenas-connector.md, docs/nas-connector.md)
    if (s.source.startsWith('nas-') || s.source.startsWith('share-'))
      return s.local ? [toHost, synthetic(s)] : [toHost];
    // VMware VMs: restored as a new Proxmox VE VM (#34)
    if (s.source.startsWith('vmw-'))
      return [
        {
          label: t.snap.vmwRestore,
          hint: t.snap.vmwRestoreHint,
          icon: IconRestore,
          onselect: () => openRestore(s, 'restore'),
        },
      ];
    const items: MenuItem[] = [
      {
        label: t.snap.fullRestore,
        hint: t.snap.fullRestoreHint,
        icon: IconRestore,
        onselect: () => openRestore(s, 'restore'),
      },
    ];
    if (s.source.startsWith('vm-')) {
      items.push({
        label: t.snap.instant,
        hint: t.snap.instantHintShort,
        icon: IconZap,
        onselect: () => openRestore(s, 'instant'),
      });
      items.push({ label: t.idr.menu, hint: t.idr.menuHint, icon: IconDisk, onselect: () => openInstantDisk(s) });
    }
    // VM/CT files: chosen in the file browser (restore micro-VM), then restored onto a host
    items.push({
      label: t.snap.restoreFilesToHost,
      hint: t.snap.restoreFilesToHostHint,
      icon: IconHost,
      onselect: () => browse(s),
    });
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
    holdTarget = s ? preferClean(s) : (flaggedOf = null);
    holdReason = s?.hold?.state === 'advisory' ? s.hold.reason : '';
    holdOpen = true;
  }
  async function releaseHold(s: Snapshot) {
    if (!(await askConfirm(t.snap.releaseConfirm(s.source, fmtTime(s.time))))) return;
    const path = `/snapshots/${encodeURIComponent(s.tenant)}/${encodeURIComponent(s.source)}/${s.time}/hold`;
    if (await act(del(path), t.snap.releaseQueued)) load();
  }
  const showActions = $derived(can.restore(session.user) || can.hold(session.user) || can.releaseHold(session.user));
  const holdSnap = $derived(holdTarget as Snapshot | null);
  async function remove(s: Snapshot) {
    if (!(await askConfirm(t.snap.deleteConfirm(s.source, fmtTime(s.time))))) return;
    const path = `/snapshots/${encodeURIComponent(s.tenant)}/${encodeURIComponent(s.source)}/${s.time}`;
    await act(del(path), t.snap.deleteQueued);
  }

  // Phase 21d: damaged snapshots per tenant, repaired per tenant
  const damagedByTenant = $derived([
    ...snaps
      .filter((s) => s.damaged)
      .reduce((m, s) => m.set(s.tenant, (m.get(s.tenant) ?? 0) + 1), new Map<string, number>()),
  ]);

  async function repair(tenant: string) {
    if (!(await askConfirm(t.snap.repairConfirm(tenant)))) return;
    const r = await act(
      post<{ id: number }>('/jobs', { kind: 'chunk_repair', tenant, params: {} }),
      t.snap.repairQueued,
      jobLink,
    );
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }

  async function fetchBack(s: Snapshot) {
    const id = await fetchFromOffsite(s.tenant, s.source, s.time, s.offsite ? 1 : 2);
    if (id) navigate(`/jobs/${id}`);
  }

  function browse(s: Snapshot) {
    navigate('/files' + qs({ tenant: s.tenant, source: s.source, time: s.time, path: '/' }));
  }

  // Phase 28: recovery calendar when the list shows one source
  const calSnaps = $derived.by(() => {
    const src = route.query.get('source');
    if (!src || !shown.length || shown.some((x) => x.source !== src)) return [];
    const tn = shown[0].tenant;
    return shown.filter((x) => x.tenant === tn);
  });
  function pickFromCalendar(s: Snapshot) {
    if (!can.restore(session.user)) return;
    if (offsiteOnly(s)) return void fetchBack(s);
    const first = restoreItems(s)[0];
    if (first) first.onselect();
    else browse(s);
  }
  /** The other actions of a snapshot row (browse and restore stay buttons of their own). */
  function snapActions(s: Snapshot): MenuItem[] {
    const at = fmtTime(s.time);
    const out: MenuItem[] = [];
    if (can.restore(session.user) && s.local)
      out.push({
        label: t.snap.changes,
        icon: IconDiff,
        title: t.snap.changesLabel(s.source, at),
        onselect: () => navigate('/changes' + qs({ tenant: s.tenant, source: s.source, time: s.time })),
      });
    if (can.scan(session.user) && s.local)
      out.push({
        label: t.scan.scan,
        icon: IconScan,
        title: t.scan.scanLabel(s.source, at),
        onselect: () => startScan(s),
      });
    if (scanBackable(s))
      out.push({
        label: t.p29.scanBack.action,
        icon: IconHistory,
        title: t.p29.scanBack.label(s.source, at),
        onselect: () => ((sbSnap = s), (sbOpen = true)),
      });
    if (can.hold(session.user) && s.anomalous)
      out.push({
        label: t.snap.clearFlag,
        icon: IconCheck,
        title: t.snap.clearFlagLabel(s.source, at),
        onselect: () => ((clearSnap = s), (clearNote = ''), (clearOpen = true)),
      });
    if (can.hold(session.user) && s.hold?.state !== 'active')
      out.push({
        label: s.hold ? t.snap.applyHold : t.snap.hold,
        icon: IconGavel,
        title: t.snap.holdLabel(s.source, at),
        onselect: () => openHold(s),
      });
    else if (can.releaseHold(session.user) && s.hold?.state === 'active' && !s.hold.release_quorum)
      out.push({
        label: t.snap.release,
        icon: IconUnlock,
        title: t.snap.releaseLabel(s.source, at),
        onselect: () => releaseHold(s),
      });
    if (deletable(s))
      out.push({
        label: t.delete,
        icon: IconTrash,
        title: t.snap.deleteLabel(s.source, at),
        onselect: () => remove(s),
      });
    return out;
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
  <div class="field">
    <label for="f-where">{t.offsite.where}</label>
    <select id="f-where" bind:value={where}>
      <option value="">{t.offsite.whereAll}</option>
      <option value="local">{t.offsite.whereLocal}</option>
      <option value="offsite">{t.offsite.whereOffsiteOnly}</option>
    </select>
  </div>
  <label class="inline-check"><input type="checkbox" bind:checked={heldOnly} />{t.snap.heldOnly}</label>
  <button type="submit">{t.snap.apply}</button>
</form>

<ErrorBanner {error} />
{#if session.vault}<p class="banner pending" role="status">{t.vault.restoreHint}</p>{/if}

{#each damagedByTenant as [tn, n] (tn)}
  <div class="banner error damaged" role="alert">
    <span>{t.snap.damagedBanner(n, tn)}</span>
    {#if can.repair(session.user)}
      <button type="button" class="small" onclick={() => repair(tn)} aria-label={t.snap.repairLabel(tn)}
        ><IconWrench aria-hidden="true" />{t.snap.repair}</button
      >
    {/if}
  </div>
{/each}

{#if calSnaps.length}<RecoveryCalendar snaps={calSnaps} onpick={pickFromCalendar} />{/if}

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
            <th scope="col">{t.snap.source}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.time}</th>
            <th scope="col" class="num">{t.snap.size}</th>
            <th scope="col">{t.dash.local}</th>
            <th scope="col">{t.dash.offsite}</th>
            {#if hasSecond}<th scope="col">{t.p30.second.column}</th>{/if}
            <th scope="col">{t.dash.verified}</th>
            <th scope="col">{t.snap.lock}</th>
            <th scope="col">{t.cons.column}</th>
            {#if showActions}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each shown as s (`${s.tenant}/${s.source}/${s.time}`)}
            {@const ag = agentOf(s)}
            {@const sh = shareName(s)}
            {@const pl = pluginOf(s)}
            {@const download = pl?.kind?.restores.find((r) => r.id === 'download')}
            {@const items = restoreItems(s)}
            <tr>
              <td>
                <SourceName source={s.source} tenant={s.tenant} />
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
                {#if s.meta?.identity?.changed}
                  <div>
                    <span
                      class="chip warn"
                      title={t.snap.identityChangedTitle(
                        s.meta.identity.previous?.vmgenid ?? '?',
                        s.meta.identity.vmgenid ?? '?',
                        s.meta.identity.previous?.smbios_uuid ?? '?',
                        s.meta.identity.smbios_uuid ?? '?',
                      )}>{t.snap.identityChanged}</span
                    >
                  </div>
                {/if}
                {#if s.meta?.zfs_snapshot}<div class="muted small mono">@{s.meta.zfs_snapshot}</div>{/if}
                {#if s.damaged}
                  <div>
                    <span class="chip bad" title={t.snap.damagedTitle(s.damaged, fmtTime(s.damaged_at ?? 0))}
                      >{t.snap.damaged}</span
                    >
                  </div>
                {/if}
                {#if s.index_state && t.snap.indexChip[s.index_state]}
                  <div>
                    <span
                      class="chip plain {s.index_state === 'failed' ? 'bad' : 'warn'}"
                      title={s.index_reason ? t.snap.indexTitle(s.index_reason) : undefined}
                      >{t.snap.indexChip[s.index_state]}</span
                    >
                  </div>
                {/if}
                {#if s.anomalous && s.anomaly}
                  <div>
                    <span class="chip bad" title={t.snap.anomalousTitle(s.anomaly.reason)}>{t.snap.anomalous}</span>
                  </div>
                  <div class="muted small reason">{s.anomaly.reason}</div>
                {:else if s.anomaly}
                  <div>
                    <span
                      class="chip info plain"
                      title={t.snap.flagClearedTitle(
                        s.anomaly.cleared_by ?? '?',
                        fmtTime(s.anomaly.cleared_at ?? 0),
                        s.anomaly.note ?? '',
                        s.anomaly.reason,
                      )}>{t.snap.flagCleared}</span
                    >
                  </div>
                {/if}
                {#if s.scan}
                  <div>
                    <button
                      type="button"
                      class="chip plain linkish {s.scan.matches ? 'bad' : s.scan.complete ? 'ok' : 'warn'}"
                      title={t.scan.chipTitle(fmtTime(s.scan.finished))}
                      onclick={() => ((scanSnap = s), (scanOpen = true))}
                      >{s.scan.matches
                        ? t.scan.hits(s.scan.matches)
                        : s.scan.complete
                          ? t.scan.clean
                          : t.scan.incomplete}</button
                    >
                  </div>
                {/if}
                {#if s.clean_point}
                  <div>
                    <span class="chip ok plain clean-point" title={t.p29.scanBack.badgeTitle}
                      ><IconBadge aria-hidden="true" />{t.p29.scanBack.badge}</span
                    >
                  </div>
                {/if}
                {#if offsiteOnly(s)}<div><span class="chip info plain">{t.offsite.onlyOffsite}</span></div>{/if}
                {#if s.hold?.state === 'active'}
                  <div>
                    <span
                      class="chip warn plain hold"
                      title={t.snap.heldTitle(s.hold.held_by, fmtTime(s.hold.held_at), s.hold.reason)}
                      ><IconGavel aria-hidden="true" />{t.snap.held}{s.hold.release_quorum
                        ? ` · ${t.snap.releasePending}`
                        : ''}</span
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
              {#if hasSecond}<td><Check on={!!s.offsite2} /></td>{/if}
              <td><Check on={s.verified} title={s.verified ? fmtAgo(s.verified) : ''} /></td>
              <td class="nowrap">{s.lock_until > now ? fmtTime(s.lock_until) : '—'}</td>
              <td><ConsistencyBadge level={s.consistency} /></td>
              {#if showActions}
                <td class="actions">
                  {#if can.restore(session.user) && offsiteOnly(s)}
                    <!-- restores need a local copy: fetch it back first (17d) -->
                    <button
                      type="button"
                      class="small"
                      onclick={() => fetchBack(s)}
                      aria-label={t.offsite.fetchLabel(s.source, fmtTime(s.time))}
                      ><IconCloudDown aria-hidden="true" />{t.offsite.fetch}</button
                    >
                  {:else if can.restore(session.user)}
                    <button
                      type="button"
                      class="small"
                      onclick={() => browse(s)}
                      disabled={s.source.startsWith('vmw-')}
                      title={s.source.startsWith('vmw-')
                        ? t.snap.vmwNoBrowse
                        : pl && !pl.kind
                          ? t.snap.pluginUnknown
                          : undefined}><IconFolder aria-hidden="true" />{download?.title ?? t.snap.browse}</button
                    >
                    {#if items.length}
                      <Menu label={t.snap.restoreMenu} ariaLabel={t.snap.restoreMenuLabel(s.source)} {items} />
                    {/if}
                  {/if}
                  {#if snapActions(s).length}
                    <Menu
                      label={t.agents.more}
                      ariaLabel={t.snap.moreLabel(s.source, fmtTime(s.time))}
                      items={snapActions(s)}
                    />
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
  title={sel
    ? mode === 'instant'
      ? t.snap.instantTitle(labelOf(sel.tenant, sel.source))
      : t.snap.restoreTitle(labelOf(sel.tenant, sel.source))
    : ''}
>
  {#if sel}
    <form onsubmit={startRestore}>
      <p class="muted">{sel.tenant} · {fmtTime(sel.time)}</p>
      {#if flaggedOf}<FlaggedNotice
          flagged={flaggedOf}
          clean={cleanBefore(flaggedOf)}
          using={sel}
          onswitch={(x) => (sel = x)}
        />{/if}
      <InfectedNotice
        snap={sel}
        production={mode === 'instant' ? !rLinkDown : rReplace || !rLinkDown}
        onisolateNet={() => ((rLinkDown = true), (rReplace = false))}
      />
      {#if mode === 'instant'}<p class="banner info">{t.snap.instantHint}</p>{/if}
      {#if isVmw}
        <p class="banner info">{t.snap.vmwHint}</p>
        {#if tenantClusters.length}
          <div class="field">
            <label for="r-cluster">{t.snap.vmwCluster}</label>
            <select id="r-cluster" bind:value={rCluster} onchange={() => (node = '')} required>
              {#each tenantClusters as c (c.id)}<option value={String(c.id)}>{c.name}</option>{/each}
            </select>
          </div>
        {:else}
          <p class="banner warn">{t.snap.vmwNoCluster}</p>
        {/if}
      {/if}
      <div class="field">
        <label for="r-node">{t.snap.node}</label>
        <input id="r-node" bind:value={node} list="r-nodes" required autocomplete="off" />
        <datalist id="r-nodes"
          >{#each nodeNames as n (n)}<option value={n}></option>{/each}</datalist
        >
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
              <input
                id="r-name"
                bind:value={rName}
                disabled={!!rPrefix.trim()}
                pattern="[A-Za-z0-9_][A-Za-z0-9._\-]{'{0,62}'}"
                aria-describedby="r-name-hint"
              />
              <div class="hint" id="r-name-hint">{t.ropts.nameHint('<name>-restore')}</div>
            </div>
          {/if}
          <div class="field">
            <label for="r-prefix">{t.ropts.prefix}</label>
            <input
              id="r-prefix"
              bind:value={rPrefix}
              disabled={!!rName.trim() && mode === 'restore'}
              pattern="[A-Za-z0-9_][A-Za-z0-9._\-]{'{0,62}'}"
              aria-describedby="r-prefix-hint"
            />
            <div class="hint" id="r-prefix-hint">{t.ropts.prefixHint}</div>
          </div>
          <div class="field">
            <label for="r-pool">{t.ropts.pool}</label>
            <input
              id="r-pool"
              bind:value={rPool}
              pattern="[A-Za-z0-9_][A-Za-z0-9._\-]{'{0,62}'}"
              aria-describedby="r-pool-hint"
            />
            <div class="hint" id="r-pool-hint">{t.ropts.poolHint}</div>
          </div>
          {#if isVmw}
            <div class="field">
              <label for="r-bridge">{t.snap.vmwBridge}</label>
              <input
                id="r-bridge"
                bind:value={rBridge}
                required
                pattern="[A-Za-z0-9_][A-Za-z0-9_\-]{'{0,31}'}"
                spellcheck="false"
              />
            </div>
          {/if}
        </div>
        <div class="field">
          <label class="inline-check"
            ><input id="r-start" type="checkbox" bind:checked={rStart} />{mode === 'instant'
              ? t.ropts.irStart
              : t.ropts.start}</label
          >
        </div>
        <div class="field">
          <label class="inline-check"
            ><input id="r-linkdown" type="checkbox" bind:checked={rLinkDown} />{t.ropts.linkDown}</label
          >
          <div class="hint">{t.ropts.linkDownHint}</div>
        </div>
        <ScanFirst bind:value={rScan} linkDown />
        {#if mode === 'restore' && can.backup(session.user) && !isVmw}
          <div class="field">
            <label class="inline-check"
              ><input id="r-replace" type="checkbox" bind:checked={rReplace} />{t.ropts.replace}</label
            >
          </div>
          {#if rReplace}
            {#if sel?.source.startsWith('vm-')}
              <div class="field">
                <label class="inline-check"
                  ><input id="r-rollback" type="checkbox" bind:checked={rRollback} />{t.p30.rollback.label}</label
                >
                <div class="hint">{t.p30.rollback.hint(origVmid(sel))}</div>
              </div>
            {/if}
            <p class="banner warn">{t.ropts.replaceHint(origVmid(sel))}</p>
            <div class="field">
              <label class="inline-check"
                ><input id="r-keeplinks" type="checkbox" bind:checked={rKeepLinks} />{t.ropts.keepLinks}</label
              >
            </div>
          {/if}
        {/if}
      </fieldset>
      <div class="form-actions">
        <button type="button" onclick={() => (dlgOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}
          >{session.vault ? t.vault.requestRestore : t.snap.start}</button
        >
      </div>
    </form>
  {/if}
</Modal>

<InstantDisk bind:open={idrOpen} snap={idrSnap} nodes={nodesOf(idrSnap?.tenant)} />

<Modal bind:open={manyOpen} title={t.ropts.manyTitle} wide>
  <form onsubmit={startMany}>
    <p class="muted">{t.ropts.manyIntro}</p>
    <div class="form-grid">
      {#if manyTenants.length > 1}
        <div class="field">
          <label for="m-tenant">{t.tenant}</label>
          <select
            id="m-tenant"
            bind:value={manyTenant}
            onchange={() => ((manyChecked = {}), (node = nodesOf(manyTenant)[0] ?? ''))}
          >
            {#each manyTenants as tn (tn)}<option value={tn}>{tn}</option>{/each}
          </select>
        </div>
      {/if}
      <div class="field">
        <label for="m-group">{t.ropts.manyGroup}</label>
        <select id="m-group" bind:value={manyGroup} onchange={pickGroup}>
          <option value="">{t.ropts.manyGroupNone}</option>
          {#each groups.filter((g) => g.tenant === manyTenant) as g (g.id)}<option value={String(g.id)}>{g.name}</option
            >{/each}
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
              <ConsistencyBadge level={s.consistency} />
              {#if newerFlagged(s)}<span class="chip warn plain"
                  >{t.snap.flaggedSkipped(fmtTime(newerFlagged(s).time))}</span
                >{/if}</label
            >
          {/each}
        </div>
      {/if}
    </fieldset>
    <div class="form-grid">
      <div class="field">
        <label for="m-node">{t.snap.node}</label>
        <input id="m-node" bind:value={node} list="m-nodes" required autocomplete="off" />
        <datalist id="m-nodes"
          >{#each nodesOf(manyTenant) as n (n)}<option value={n}></option>{/each}</datalist
        >
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
      <label class="inline-check"
        ><input id="m-linkdown" type="checkbox" bind:checked={rLinkDown} />{t.ropts.linkDown}</label
      >
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (manyOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={busy || !manyPicked.length}
        >{session.vault ? t.vault.requestRestore : t.snap.start}</button
      >
    </div>
  </form>
</Modal>

<Modal
  bind:open={prOpen}
  title={prSnap && prRestore ? t.snap.pluginRestoreTitle(prRestore.title, labelOf(prSnap.tenant, prSnap.source)) : ''}
  wide
>
  {#if prSnap && prRestore}
    <form onsubmit={startPluginRestore}>
      <p class="muted">
        {prSnap.tenant} · {fmtTime(prSnap.time)}
        {#if prRestore.app_specific}<span class="chip info">{t.snap.appSpecific}</span>{/if}
      </p>
      {#if flaggedOf}<FlaggedNotice
          flagged={flaggedOf}
          clean={cleanBefore(flaggedOf)}
          using={prSnap}
          onswitch={(x) => (prSnap = x)}
        />{/if}
      {#if range && hasTimeTarget}
        <div class="range" role="group" aria-labelledby="pr-range-label">
          <p id="pr-range-label">
            <strong>{t.snap.recoverable}</strong>
            {#if range.from_time >= range.to_time}
              {t.snap.recoverableBaseOnly(fmtTime(range.to_time), range.to_lsn, range.unit === 'binlog')}
            {:else}
              {t.snap.recoverableRange(fmtTime(range.from_time), fmtTime(range.to_time))}
              <span class="muted mono"
                >{t.snap.positionUnit(range.unit)}
                {range.from_lsn} → {range.to_lsn}{range.timeline ? ` · ${t.snap.timeline} ${range.timeline}` : ''}</span
              >
            {/if}
          </p>
          {#if range.from_time < range.to_time}
            <div class="field">
              <label for="pr-pick">{t.snap.pickTime}</label>
              <input
                id="pr-pick"
                type="datetime-local"
                step="1"
                min={localInput(range.from_time)}
                max={localInput(range.to_time)}
                value={prPick}
                oninput={(e) => pickTime(e.currentTarget.value)}
                aria-describedby="pr-pick-hint"
              />
              <div class="hint" id="pr-pick-hint">{t.snap.pickTimeHint}</div>
            </div>
          {/if}
        </div>
      {/if}
      {#if prTargets.length}
        <div class="field">
          <label for="pr-target">{t.snap.targetSource}</label>
          <select id="pr-target" bind:value={prTarget} aria-describedby="pr-target-hint">
            <option value="">{t.snap.targetSourceOwn(prOwn?.name ?? '')}</option>
            {#each prTargets as x (x.id)}<option value={String(x.id)}>{x.name}</option>{/each}
          </select>
          <div class="hint" id="pr-target-hint">{t.snap.targetSourceHint}</div>
        </div>
      {/if}
      {#if prRestore.params_schema && Object.keys(prRestore.params_schema.properties ?? {}).length}
        <SchemaForm schema={prRestore.params_schema} bind:values={prValues} errors={prErrors} />
      {:else if !isMount(prRestore)}
        <p class="muted">{t.snap.noParams}</p>
      {/if}
      {#if !isMount(prRestore)}<InfectedNotice snap={prSnap} production />{/if}
      {#if !isMount(prRestore)}<ScanFirst bind:value={prScan} />{/if}
      {#if isMount(prRestore)}
        <div class="field">
          <label for="pr-min">{t.snap.mountMinutes}</label>
          <input
            id="pr-min"
            type="number"
            min="1"
            max="1440"
            step="1"
            bind:value={prMinutes}
            required
            aria-describedby="pr-min-hint"
          />
          <div class="hint" id="pr-min-hint">{t.snap.mountMinutesHint}</div>
        </div>
      {/if}
      <div class="form-actions">
        <button type="button" onclick={() => (prOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}
          >{session.vault ? t.vault.requestRestore : t.snap.start}</button
        >
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
>
  {#if flaggedOf && holdSnap}
    <FlaggedNotice
      flagged={flaggedOf}
      clean={cleanBefore(flaggedOf)}
      using={holdSnap}
      onswitch={(x) => (holdTarget = x)}
    />
  {/if}
</HoldDialog>

{#if rfSnap}
  <RestoreFiles
    bind:open={rfOpen}
    tenant={rfSnap.tenant}
    source={rfSnap.source}
    time={rfSnap.time}
    paths={['/']}
    {agents}
  >
    {#if flaggedOf}<FlaggedNotice
        flagged={flaggedOf}
        clean={cleanBefore(flaggedOf)}
        using={rfSnap}
        onswitch={(x) => (rfSnap = x)}
      />{/if}
  </RestoreFiles>
{/if}

{#if synSnap}
  <SyntheticRestore bind:open={synOpen} tenant={synSnap.tenant} source={synSnap.source} time={synSnap.time} {agents} />
{/if}

<ScanResults bind:open={scanOpen} snap={scanSnap} />

{#if sbSnap}<ScanBack
    bind:open={sbOpen}
    tenant={sbSnap.tenant}
    source={sbSnap.source}
    time={sbSnap.time}
    ondone={load}
  />{/if}

<Modal bind:open={clearOpen} title={t.snap.clearTitle}>
  {#if clearSnap}
    <form onsubmit={submitClear}>
      <p><span class="mono">{clearSnap.source}</span> · {clearSnap.tenant} · {fmtTime(clearSnap.time)}</p>
      <p class="banner warn">{clearSnap.anomaly?.reason}</p>
      <p class="muted">{t.snap.clearIntro}</p>
      <div class="field">
        <label for="clear-note">{t.snap.clearNote}</label>
        <input id="clear-note" bind:value={clearNote} required maxlength="1000" />
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (clearOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy || !clearNote.trim()}>{t.snap.clearSubmit}</button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  .damaged {
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
  }
  .damaged button {
    flex: none;
  }
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
  .range {
    border: 1px solid var(--border);
    border-radius: var(--radius, 6px);
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.75rem;
  }
  .range p {
    margin: 0 0 0.25rem;
  }
  /* the scan chip opens the results: a button that looks like the other chips */
  button.linkish {
    border: 0;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.78rem;
    font-weight: 600;
    line-height: 1.45;
    min-height: 0;
    padding: 0.08rem 0.55rem 0.08rem 0.45rem;
  }
  .reason {
    max-width: 22rem;
    font-size: 0.8rem;
  }
  /* legal-hold / recommended-point badges: the icon replaces the chip dot */
  .chip.clean-point :global(svg),
  .chip.hold :global(svg) {
    width: 0.85rem;
    height: 0.85rem;
  }
</style>
