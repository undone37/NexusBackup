<script lang="ts">
  import Menu, { type MenuItem } from '../components/Menu.svelte';
  import JobState from '../components/JobState.svelte';
  import { rowClick } from '../lib/rowlink';
  import { askConfirm } from '../lib/confirm.svelte';
  import { onMount, onDestroy } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { href } from '../lib/router.svelte';
  import { t } from '../lib/i18n';
  import { runJob } from '../lib/jobs';
  import { isPluginKind, pluginKinds, pointer } from '../lib/plugins';
  import { buildValue, initValues, secretFlags, type FormValues } from '../lib/schema';
  import type { Agent, Group, Plugin, PluginSource, Source, SourceKind, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import SchemaForm from '../components/SchemaForm.svelte';
  import PauseDialog from '../components/PauseDialog.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { absHostPath, fmtTime } from '../lib/format';
  import { isPaused } from '../lib/schedule';
  import Inventory from '../components/Inventory.svelte';
  import ChangeTrends from '../components/ChangeTrends.svelte';
  import FileSelection from '../components/FileSelection.svelte';
  import SourceLimits from '../components/SourceLimits.svelte';
  import { limitsConfig, limitsForm } from '../lib/limits';
  import { fmtAgo, fmtBytes } from '../lib/format';
  import IconPlus from '@lucide/svelte/icons/plus';

  let items: Source[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let agents: Agent[] = $state([]);
  let plugins: Plugin[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  let protection = $state(new Map<number, { n: number; last: NonNullable<Group['last_backup']> | null }>());
  async function load() {
    try {
      [items, tenants, agents] = await Promise.all([
        get<Source[]>('/sources'),
        get<Tenant[]>('/tenants'),
        get<Agent[]>('/agents'),
      ]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    // per source: its groups and the newest of their last backups (the Protection column)
    try {
      const gs = await get<Group[]>('/groups');
      const m = new Map<number, { n: number; last: NonNullable<Group['last_backup']> | null }>();
      for (const g of gs) {
        const e = m.get(g.source_id) ?? { n: 0, last: null };
        e.n += 1;
        if (g.last_backup && (!e.last || g.last_backup.id > e.last.id)) e.last = g.last_backup;
        m.set(g.source_id, e);
      }
      protection = m;
    } catch {
      /* no access to groups: no Protection column figures */
    }
    try {
      plugins = await get<Plugin[]>('/plugins');
    } catch {
      /* no plugin kinds offered */
    }
    loaded = true;
  }
  onMount(load);

  // Plugin kinds (`plugin:<kind>`): new sources only for enabled plugins; existing ones
  // stay editable while their plugin's current version is installed.
  const kindsAll = $derived(pluginKinds(plugins));
  const kindsEnabled = $derived([...pluginKinds(plugins, true).entries()]);
  const kindTitle = (k: string) => t.sources.kinds[k] ?? kindsAll.get(k)?.kind.title ?? k;
  const isPlugin = (x: Source): x is PluginSource => isPluginKind(x.kind);

  /** First endpoint of a plugin source as host:port (from the manifest's JSON pointers). */
  function endpointOf(x: PluginSource): string {
    const ep = kindsAll.get(x.kind)?.kind.endpoints?.[0];
    if (!ep) return '—';
    const host = pointer(x.config, ep.host);
    const port = ep.port ? (pointer(x.config, ep.port) ?? ep.default_port) : ep.default_port;
    return host ? `${host}${port ? `:${port}` : ''}` : '—';
  }
  /** A few non-secret config values for the table. */
  function summaryOf(x: PluginSource): string {
    const secret = kindsAll.get(x.kind)?.kind.secret_fields ?? [];
    return (
      Object.entries(x.config ?? {})
        // short single-line values only (no PEM blocks or long lists)
        .filter(
          ([k, v]) =>
            !k.endsWith('_set') &&
            !secret.includes(k) &&
            v !== '' &&
            v !== null &&
            !(Array.isArray(v) && v.some((i) => typeof i === 'object')) &&
            !String(v).includes('\n') &&
            String(v).length <= 64,
        )
        .slice(0, 3)
        .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : String(v)}`)
        .join(' · ')
    );
  }

  // "Validate connection": plugin_validate job on the stored config.
  const ctl = new AbortController();
  onDestroy(() => ctl.abort());
  // guest inventory (Phase 13c): PVE, TrueNAS, VMware and plugin kinds that list guests
  const hasInventory = (x: Source) =>
    x.kind === 'pve' ||
    x.kind === 'truenas' ||
    x.kind === 'vmware' ||
    (isPlugin(x) && !!kindsAll.get(x.kind)?.kind.guests?.list);
  let invOf: Source | null = $state(null);
  let invOpen = $state(false);

  let checks: Record<number, { busy: boolean; ok?: boolean; text?: string; job?: number }> = $state({});
  async function validate(x: PluginSource) {
    checks[x.id] = { busy: true };
    try {
      const r = await runJob('plugin_validate', x.tenant, { source_id: x.id }, ctl.signal);
      if (!r) {
        delete checks[x.id];
        return;
      }
      const res = r.job.result;
      checks[x.id] =
        r.job.state !== 'ok'
          ? { busy: false, ok: false, text: t.sources.validateFailed, job: r.job.id }
          : res?.valid
            ? { busy: false, ok: true, text: t.sources.valid, job: r.job.id }
            : { busy: false, ok: false, text: t.sources.invalid(res?.field, res?.message), job: r.job.id };
    } catch (e) {
      checks[x.id] = { busy: false, ok: false, text: errText(e) };
    }
  }

  let open = $state(false);
  let editing: Source | null = $state(null);
  // plugin config form (generated from the kind's config_schema)
  let pv: FormValues = $state({});
  let pErrors: Record<string, string> = $state({});
  let f = $state({
    kind: 'pve' as SourceKind,
    tenant: '',
    name: '',
    host: '',
    port: 8006,
    ca_pem: '',
    token_id: '',
    token_secret: '',
    nodes: '{}',
    storage: '',
    fleecing_storage: '',
    fl_min_pct: 15,
    fl_min_gib: 20,
    fl_cancel_pct: 5,
    // linux
    agent_id: '',
    paths: '',
    excludes: '',
    hooks: false,
    // Phase 15e: agents + shares
    include: '',
    exclude_regex: '',
    cross_mounts: false,
    skip_fstypes: '',
    // truenas
    connect_addr: '',
    tn_user: 'nexusbackup',
    ssh_host: '',
    ssh_port: 22,
    ssh_user: 'nexusbackup',
    host_key: '',
    key_pem: '',
    public_key: '',
    from: '',
    datasets: '',
    recursive: false,
    sudo: true,
    zfs_sudo: true,
    // vmware
    vm_user: '',
    datacenter: 'ha-datacenter',
    nfc_hosts: '',
    // nfs / smb shares
    version: '4.2',
    export: '',
    mount_port: 20048,
    share: '',
    sh_user: '',
    domain: '',
    sec: 'ntlmssp' as 'ntlmssp' | 'krb5',
    password: '',
    keytab: '',
    principal: '',
    sign: true,
    seal: false,
    snapshot_dir: '',
    snapshot_prefix: '',
    snapshot_order: 'name' as 'name' | 'mtime',
    threads: 16,
    xattrs: true,
    timeout_secs: 60,
    // Phase 22b: caps / read limit, TrueNAS "use existing snapshots"
    lim: limitsForm(),
    tn_existing: false,
    tn_prefix: 'auto-',
  });
  const pk = $derived(isPluginKind(f.kind) ? (kindsAll.get(f.kind) ?? null) : null);
  const pSecretSet = $derived.by(() => {
    const x = editing;
    return x && isPlugin(x) ? secretFlags(x.config, pk?.kind.secret_fields ?? []) : {};
  });
  const isShare = $derived(f.kind === 'nfs' || f.kind === 'smb');
  const tenantAgents = $derived(agents.filter((a) => a.tenant === f.tenant));
  // Keep the agent selection valid when the tenant changes.
  $effect(() => {
    if (open && f.kind === 'linux' && !tenantAgents.some((a) => a.id === f.agent_id))
      f.agent_id = tenantAgents[0]?.id ?? '';
  });
  const agentName = (id: string) => agents.find((a) => a.id === id)?.name ?? id;
  const lines = (s: string) =>
    s
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);

  function edit(x: Source | null) {
    editing = x;
    const c = x?.kind === 'pve' ? x.config : undefined;
    const l = x?.kind === 'linux' ? x.config : undefined;
    const n = x?.kind === 'truenas' ? x.config : undefined;
    const v = x?.kind === 'vmware' ? x.config : undefined;
    const sh = x?.kind === 'nfs' || x?.kind === 'smb' ? x.config : undefined;
    f = {
      kind: x?.kind ?? 'pve',
      tenant: x?.tenant ?? tenants[0]?.name ?? '',
      name: x?.name ?? '',
      host: c?.host ?? n?.host ?? v?.host ?? sh?.host ?? '',
      port: c?.port ?? n?.port ?? v?.port ?? sh?.port ?? (x?.kind === 'nfs' ? 2049 : x?.kind === 'smb' ? 445 : 8006),
      ca_pem: c?.ca_pem ?? n?.ca_pem ?? v?.ca_pem ?? '',
      token_id: c?.token_id ?? '',
      token_secret: '',
      nodes: JSON.stringify(c?.nodes ?? {}, null, 2),
      storage: c?.storage ?? '',
      fleecing_storage: c?.fleecing_storage ?? '',
      fl_min_pct: c?.fleecing_guard?.min_free_pct ?? 15,
      fl_min_gib: c?.fleecing_guard?.min_free_gib ?? 20,
      fl_cancel_pct: c?.fleecing_guard?.cancel_free_pct ?? 5,
      agent_id: l?.agent_id ?? '',
      paths: (l?.paths ?? []).join('\n'),
      excludes: (l?.excludes ?? sh?.excludes ?? []).join('\n'),
      hooks: l?.hooks ?? false,
      include: (l?.include ?? sh?.include ?? []).join('\n'),
      exclude_regex: (l?.exclude_regex ?? sh?.exclude_regex ?? []).join('\n'),
      cross_mounts: l?.cross_mounts ?? false,
      skip_fstypes: (l?.skip_fstypes ?? []).join('\n'),
      connect_addr: n?.connect_addr ?? '',
      tn_user: n?.user ?? 'nexusbackup',
      ssh_host: n?.ssh.host ?? '',
      ssh_port: n?.ssh.port ?? 22,
      ssh_user: n?.ssh.user ?? 'nexusbackup',
      host_key: n?.ssh.host_key ?? '',
      key_pem: '',
      public_key: n?.ssh.public_key ?? '',
      from: n?.ssh.from ?? '',
      datasets: (n?.datasets ?? []).join('\n'),
      recursive: n?.recursive ?? false,
      sudo: n?.sudo ?? true,
      zfs_sudo: n?.zfs_sudo ?? true,
      vm_user: v?.user ?? '',
      datacenter: v?.datacenter ?? 'ha-datacenter',
      nfc_hosts: (v?.nfc_hosts ?? []).join('\n'),
      version: sh?.version ?? (x?.kind === 'smb' ? '3' : '4.2'),
      export: sh?.export ?? '',
      mount_port: sh?.mount_port ?? 20048,
      share: sh?.share ?? '',
      sh_user: sh?.user ?? '',
      domain: sh?.domain ?? '',
      sec: sh?.sec ?? 'ntlmssp',
      password: '',
      keytab: '',
      principal: sh?.principal ?? '',
      sign: sh?.sign ?? true,
      seal: sh?.seal ?? false,
      snapshot_dir: sh?.snapshot_dir ?? '',
      snapshot_prefix: sh?.snapshot_prefix ?? '',
      snapshot_order: sh?.snapshot_order ?? 'name',
      threads: sh?.threads ?? 16,
      xattrs: sh?.xattrs ?? true,
      timeout_secs: sh?.timeout_secs ?? 60,
      lim: limitsForm(c ?? n ?? sh),
      tn_existing: !!n?.existing_snapshots,
      tn_prefix: n?.existing_snapshots ?? 'auto-',
    };
    const ps = x && isPlugin(x) ? x : null;
    const k = ps ? kindsAll.get(ps.kind) : undefined;
    pv = k && ps ? initValues(k.kind.config_schema, ps.config, k.kind.secret_fields ?? []) : {};
    pErrors = {};
    lastKind = f.kind;
    open = true;
  }

  // New sources default to the port and protocol version of their kind.
  const defaultPorts: Record<string, number> = {
    pve: 8006,
    linux: 8006,
    truenas: 443,
    vmware: 443,
    nfs: 2049,
    smb: 445,
  };
  let lastKind = 'pve';
  $effect(() => {
    if (!open || editing || f.kind === lastKind) return;
    if (isPluginKind(f.kind)) {
      pv = initValues(kindsAll.get(f.kind)?.kind.config_schema);
      pErrors = {};
    }
    if (f.port === defaultPorts[lastKind]) f.port = defaultPorts[f.kind] ?? f.port;
    if (f.kind === 'nfs' && !['3', '4.0', '4.1', '4.2'].includes(f.version)) f.version = '4.2';
    if (f.kind === 'smb' && !['2.1', '3', '3.0', '3.02', '3.1.1'].includes(f.version)) f.version = '3';
    lastKind = f.kind;
  });
  // SMB 2.1 has no encryption.
  $effect(() => {
    if (f.kind === 'smb' && f.version === '2.1' && f.seal) f.seal = false;
  });

  /** Keytab file -> base64 (sent once, write-only). */
  async function pickKeytab(e: Event) {
    const file = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!file) {
      f.keytab = '';
      return;
    }
    const b = new Uint8Array(await file.arrayBuffer());
    let bin = '';
    for (const x of b) bin += String.fromCharCode(x);
    f.keytab = btoa(bin);
  }

  /**
   * Config of an nfs/smb source, or null (after telling the user) when invalid.
   * Only set fields are sent: the API refuses SMB fields on NFS sources and vice versa.
   */
  function shareConfig(): Record<string, unknown> | null {
    const excludes = lines(f.excludes);
    if (excludes.length > 256) {
      notify('error', t.sources.excludesInvalid);
      return null;
    }
    const sel = selection(false);
    if (!sel) return null;
    const config: Record<string, unknown> = {
      host: f.host.trim(),
      port: Number(f.port),
      version: f.version,
      excludes,
      ...sel,
      threads: Number(f.threads),
      xattrs: f.xattrs,
      timeout_secs: Number(f.timeout_secs),
    };
    if (!withLimits(config)) return null;
    if (f.snapshot_dir.trim()) {
      config.snapshot_dir = f.snapshot_dir.trim();
      if (f.snapshot_prefix.trim()) config.snapshot_prefix = f.snapshot_prefix.trim();
      config.snapshot_order = f.snapshot_order;
    }
    if (f.kind === 'nfs') {
      if (!f.export.trim().startsWith('/')) {
        notify('error', t.sources.sh.exportInvalid);
        return null;
      }
      config.export = f.export.trim();
      if (f.version === '3') config.mount_port = Number(f.mount_port);
      return config;
    }
    config.share = f.share.trim();
    if (f.sh_user.trim()) config.user = f.sh_user.trim();
    if (f.domain.trim()) config.domain = f.domain.trim();
    config.sec = f.sec;
    config.sign = f.sign;
    config.seal = f.version !== '2.1' && f.seal;
    // Write-only secrets: only sent when entered.
    if (f.sec === 'krb5') {
      config.principal = f.principal.trim();
      if (f.keytab) config.keytab = f.keytab;
    } else if (f.password) {
      config.password = f.password;
    }
    return config;
  }

  /** Config of a truenas source, or null (after telling the user) when invalid. */
  function truenasConfig(): Record<string, unknown> | null {
    const datasets = lines(f.datasets);
    if (!datasets.length || datasets.length > 64) {
      notify('error', t.sources.tn.datasetsInvalid);
      return null;
    }
    const ssh: Record<string, unknown> = {
      host: f.ssh_host || f.host,
      port: Number(f.ssh_port),
      user: f.ssh_user,
      host_key: f.host_key.trim(),
    };
    if (f.public_key.trim()) ssh.public_key = f.public_key.trim();
    if (f.from.trim()) ssh.from = f.from.trim();
    // Write-only secrets: only sent when entered.
    if (f.key_pem.trim()) ssh.key_pem = f.key_pem.trim() + '\n';
    const config: Record<string, unknown> = {
      host: f.host,
      port: Number(f.port),
      ca_pem: f.ca_pem,
      user: f.tn_user,
      ssh,
      datasets,
      recursive: f.recursive,
      sudo: f.sudo,
      zfs_sudo: f.zfs_sudo,
    };
    if (f.connect_addr.trim()) config.connect_addr = f.connect_addr.trim();
    if (f.token_secret) config.token_secret = f.token_secret;
    if (f.tn_existing) config.existing_snapshots = f.tn_prefix.trim();
    if (!withLimits(config)) return null;
    return config;
  }

  /** Config of a vmware source; the password is write-only (only sent when entered). */
  function vmwareConfig(): Record<string, unknown> {
    const config: Record<string, unknown> = {
      host: f.host.trim(),
      port: Number(f.port),
      ca_pem: f.ca_pem,
      user: f.vm_user.trim(),
      datacenter: f.datacenter.trim(),
      transport: 'nfc',
    };
    const hosts = lines(f.nfc_hosts);
    if (hosts.length) config.nfc_hosts = hosts;
    if (f.password) config.password = f.password;
    return config;
  }

  /** Phase 22b: adds the caps / read limit; false (after telling the user) when invalid. */
  function withLimits(config: Record<string, unknown>): boolean {
    const l = limitsConfig(f.lim, f.kind === 'pve');
    if (typeof l === 'string') {
      notify('error', t.limits.invalid[l as keyof typeof t.limits.invalid]);
      return false;
    }
    Object.assign(config, l);
    return true;
  }

  /** Config of a linux source, or null (after telling the user) when invalid. */
  function linuxConfig(): Record<string, unknown> | null {
    const paths = lines(f.paths);
    const excludes = lines(f.excludes);
    if (!paths.length || paths.length > 64 || paths.some((p) => !absHostPath(p))) {
      notify('error', t.sources.pathsInvalid);
      return null;
    }
    if (excludes.length > 256) {
      notify('error', t.sources.excludesInvalid);
      return null;
    }
    const sel = selection(true);
    if (!sel) return null;
    return { agent_id: f.agent_id, paths, excludes, hooks: f.hooks, ...sel };
  }

  /** Include roots, regex excludes (+ nested mounts for agents), or null (after telling the user). */
  function selection(agent: boolean): Record<string, unknown> | null {
    const include = lines(f.include);
    const exclude_regex = lines(f.exclude_regex);
    if (include.length > 256 || include.some((p) => (agent ? !absHostPath(p) : !p.startsWith('/')))) {
      notify('error', t.sources.includeInvalid);
      return null;
    }
    // regex syntax (Rust regex, not JavaScript) is checked by the appliance
    const out: Record<string, unknown> = { include, exclude_regex };
    if (agent) {
      out.cross_mounts = f.cross_mounts;
      out.skip_fstypes = lines(f.skip_fstypes);
    }
    return out;
  }

  function pveConfig(): Record<string, unknown> | null {
    let nodes: Record<string, unknown>;
    try {
      nodes = JSON.parse(f.nodes || '{}');
    } catch {
      notify('error', `${t.err.invalidJson}: ${t.sources.nodes}`);
      return null;
    }
    const config: Record<string, unknown> = {
      host: f.host,
      port: Number(f.port),
      ca_pem: f.ca_pem,
      token_id: f.token_id,
      nodes,
      storage: f.storage,
      fleecing_storage: f.fleecing_storage,
    };
    // only what differs from nexus-pve's defaults is stored
    const guard: Record<string, number> = {};
    if (Number(f.fl_min_pct) !== 15) guard.min_free_pct = Number(f.fl_min_pct);
    if (Number(f.fl_min_gib) !== 20) guard.min_free_gib = Number(f.fl_min_gib);
    if (Number(f.fl_cancel_pct) !== 5) guard.cancel_free_pct = Number(f.fl_cancel_pct);
    if (Object.keys(guard).length) config.fleecing_guard = guard;
    // Write-only secret: only sent when entered.
    if (f.token_secret) config.token_secret = f.token_secret;
    if (!withLimits(config)) return null;
    return config;
  }

  /** Config of a plugin source from the generated form, or null when invalid. */
  function pluginConfig(): Record<string, unknown> | null {
    if (!pk) return null;
    const secretFields = pk.kind.secret_fields ?? [];
    let r = buildValue(pk.kind.config_schema, pv, { secretFields, secretSet: pSecretSet });
    // Like the server: a stored secret is only kept while the endpoint (host/port) stays the same.
    const old = editing && isPlugin(editing) ? editing.config : null;
    const moved =
      old &&
      (pk.kind.endpoints ?? []).some((ep) =>
        [ep.host, ep.port].some(
          (ptr) => ptr && JSON.stringify(pointer(old, ptr)) !== JSON.stringify(pointer(r.value, ptr)),
        ),
      );
    if (moved) r = buildValue(pk.kind.config_schema, pv, { secretFields });
    pErrors = r.errors;
    if (Object.keys(r.errors).length) {
      notify('error', t.schema.invalid);
      return null;
    }
    return r.value;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const config = isPluginKind(f.kind)
      ? pluginConfig()
      : f.kind === 'linux'
        ? linuxConfig()
        : f.kind === 'truenas'
          ? truenasConfig()
          : f.kind === 'vmware'
            ? vmwareConfig()
            : f.kind === 'nfs' || f.kind === 'smb'
              ? shareConfig()
              : pveConfig();
    if (!config) return;
    const r = editing
      ? await act(put<Source>(`/sources/${editing.id}`, { name: f.name, config }), t.saved)
      : await act(post<Source>('/sources', { tenant: f.tenant, kind: f.kind, name: f.name, config }), t.created);
    if (r) {
      load();
      // TrueNAS: keep the dialog open with the authorized_keys line to paste on TrueNAS
      const s = r.data as Source;
      if (!r.quorum && s?.kind === 'truenas' && s.config?.authorized_keys) {
        edit(s);
        return;
      }
      open = false;
    }
  }

  // Maintenance mode (Phase 13b): no scheduled backups of the source's groups.
  let maintOpen = $state(false);
  let maintSource: Source | null = $state(null);
  async function maintenance(u: number | null) {
    const x = maintSource;
    if (
      x &&
      (await act(post(`/sources/${x.id}/maintenance`, u === null ? {} : { until: u }), t.runctl.maintenanceDone))
    ) {
      maintOpen = false;
      load();
    }
  }
  async function endMaintenance(x: Source) {
    if (await act(post(`/sources/${x.id}/maintenance/end`), t.runctl.maintenanceEnded)) load();
  }

  // Phase 22b: split a share source by include roots (one new source per root).
  let splitOpen = $state(false);
  let splitOf: Source | null = $state(null);
  let sp = $state({ roots: '', password: '', copy_groups: true });
  function openSplit(x: Source) {
    splitOf = x;
    sp = {
      roots: (x.kind === 'nfs' || x.kind === 'smb' ? (x.config.include ?? []) : []).join('\n'),
      password: '',
      copy_groups: true,
    };
    splitOpen = true;
  }
  async function split(e: SubmitEvent) {
    e.preventDefault();
    const x = splitOf;
    if (!x) return;
    const body: Record<string, unknown> = { roots: lines(sp.roots), copy_groups: sp.copy_groups };
    if (sp.password) body.password = sp.password;
    const r = await act(post<{ sources: number[] }>(`/sources/${x.id}/split`, body), t.nas.splitDone);
    if (r) {
      splitOpen = false;
      load();
    }
  }
  const sizingText = (x: Source) =>
    x.sizing
      ? t.nas.sizing(
          x.sizing.entries.toLocaleString(),
          fmtBytes(x.sizing.est_ram_bytes),
          x.sizing.mem_total ? fmtBytes(x.sizing.mem_total) : null,
        )
      : '';

  async function remove(x: Source) {
    if (!(await askConfirm(t.confirmDelete(`${t.groups.source} "${x.name}"`)))) return;
    if (await act(del(`/sources/${x.id}`), t.deleted)) load();
  }
  /** The other actions of a source row (Edit is a button of its own). */
  function sourceActions(x: Source): MenuItem[] {
    const out: MenuItem[] = [];
    if (isPlugin(x)) out.push({ label: t.sources.validate, onselect: () => validate(x) });
    if (hasInventory(x)) out.push({ label: t.inventory.open, onselect: () => ((invOf = x), (invOpen = true)) });
    if (x.kind === 'nfs' || x.kind === 'smb') out.push({ label: t.nas.split, onselect: () => openSplit(x) });
    if (can.backup(session.user))
      out.push(
        isPaused(x.maintenance_until)
          ? { label: t.runctl.endMaintenance, onselect: () => endMaintenance(x) }
          : { label: t.runctl.maintenance, onselect: () => ((maintSource = x), (maintOpen = true)) },
      );
    out.push({ label: t.delete, onselect: () => remove(x) });
    return out;
  }
</script>

<div class="page-head">
  <h1>{t.sources.title}</h1>
  <button type="button" class="primary" onclick={() => edit(null)}
    ><IconPlus aria-hidden="true" />{t.sources.new}</button
  >
  <p class="lede">{t.sources.lede}</p>
</div>
<ErrorBanner {error} />

<div class="card">
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if items.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.name}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.kind}</th>
            <th scope="col">{t.sources.protection}</th>
            <th scope="col">{t.sources.target}</th>
            <th scope="col">{t.sources.details}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            <tr use:rowClick={() => edit(x)}>
              <td
                ><strong>{x.name}</strong>
                {#if isPaused(x.maintenance_until)}<span class="chip warn"
                    >{x.maintenance_until === -1
                      ? t.runctl.inMaintenance
                      : t.runctl.maintenanceUntil(fmtTime(x.maintenance_until))}</span
                  >{/if}
                {#if x.overlaps?.length}<span class="chip warn" title={t.nas.overlapTitle}
                    >{t.nas.overlap(x.overlaps.map((o) => o.name).join(', '))}</span
                  >{/if}
                {#if x.sizing}<div class="hint">
                    {sizingText(x)}
                    {#if x.sizing.warn}<span class="chip warn" title={t.nas.sizingWarn}>{t.nas.sizingWarnShort}</span
                      >{/if}
                  </div>{/if}</td
              >
              <td>{x.tenant}</td>
              <td>{kindTitle(x.kind)}</td>
              <td class="nowrap">
                {#if protection.get(x.id)}
                  {@const pr = protection.get(x.id)!}
                  <a href={href('/groups')}>{t.policies.groupsN(pr.n)}</a>
                  {#if pr.last}<div>
                      <JobState state={pr.last.state} />
                      {#if pr.last.finished}<span class="muted small" title={fmtTime(pr.last.finished)}
                          >{fmtAgo(pr.last.finished)}</span
                        >{/if}
                    </div>{/if}
                {:else if loaded}
                  <span class="chip warn" title={t.sources.unprotectedHint}>{t.sources.unprotected}</span>
                {/if}
              </td>
              {#if isPlugin(x)}
                {@const c = checks[x.id]}
                <td class="mono wrap">{endpointOf(x)}</td>
                <td>
                  <span class="mono">{summaryOf(x)}</span>
                  {#if c?.busy}
                    <div class="muted" role="status">{t.sources.validating}</div>
                  {:else if c}
                    <div role="status">
                      <span class="chip {c.ok ? 'ok' : 'bad'}">{c.text}</span>
                      {#if c.job}<a href={href(`/jobs/${c.job}`)}>{t.sources.job(c.job)}</a>{/if}
                    </div>
                  {/if}
                </td>
              {:else if x.kind === 'linux'}
                <td>{t.sources.agent} <strong>{agentName(x.config?.agent_id)}</strong></td>
                <td
                  class="mono wrap"
                  title={x.config?.excludes?.length
                    ? `${t.sources.excludes}: ${x.config.excludes.join(' ')}`
                    : undefined}>{(x.config?.paths ?? []).join(' ')}</td
                >
              {:else if x.kind === 'nfs'}
                <td class="mono wrap">{x.config?.host}:{x.config?.export}</td>
                <td class="mono wrap"
                  >NFS {x.config?.version ?? '4.2'}{x.config?.snapshot_dir ? ` · ${x.config.snapshot_dir}` : ''}</td
                >
              {:else if x.kind === 'smb'}
                <td class="mono wrap">//{x.config?.host}/{x.config?.share}</td>
                <td class="mono wrap"
                  >SMB {x.config?.version ?? '3'} · {x.config?.sec ?? 'ntlmssp'}{x.config?.seal ? ' · seal' : ''}{x
                    .config?.snapshot_dir
                    ? ` · ${x.config.snapshot_dir}`
                    : ''}</td
                >
              {:else if x.kind === 'truenas'}
                <td class="mono wrap">{x.config?.host}:{x.config?.port}</td>
                <td class="mono wrap">{(x.config?.datasets ?? []).join(' ')}{x.config?.recursive ? ' (+)' : ''}</td>
              {:else if x.kind === 'vmware'}
                <td class="mono wrap">{x.config?.host}:{x.config?.port}</td>
                <td class="mono wrap">{x.config?.user} · {x.config?.datacenter} · NFC</td>
              {:else}
                <td class="mono wrap">{x.config?.host}:{x.config?.port}</td>
                <td class="mono wrap">{x.config?.token_id}</td>
              {/if}
              <td class="actions">
                <button type="button" class="small" onclick={() => edit(x)}>{t.edit}</button>
                <Menu label={t.agents.more} ariaLabel={t.sources.moreLabel(x.name)} items={sourceActions(x)} />
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<ChangeTrends />

<Modal bind:open title={editing ? `${t.groups.source}: ${editing.name}` : t.sources.new} wide>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="s-kind">{t.sources.kind}</label>
        <select id="s-kind" bind:value={f.kind} disabled={!!editing} required>
          <option value="pve">{t.sources.kinds.pve}</option>
          <option value="linux">{t.sources.kinds.linux}</option>
          <option value="truenas">{t.sources.kinds.truenas}</option>
          <option value="vmware">{t.sources.kinds.vmware}</option>
          <option value="nfs">{t.sources.kinds.nfs}</option>
          <option value="smb">{t.sources.kinds.smb}</option>
          {#if kindsEnabled.length || (editing && isPlugin(editing))}
            <optgroup label={t.sources.pluginKinds}>
              {#each kindsEnabled as [k, info] (k)}<option value={k}>{info.kind.title}</option>{/each}
              {#if editing && isPlugin(editing) && !kindsEnabled.some(([k]) => k === editing!.kind)}
                <option value={editing.kind}>{t.sources.pluginDisabled(kindTitle(editing.kind))}</option>
              {/if}
            </optgroup>
          {/if}
        </select>
      </div>
      <div class="field">
        <label for="s-tenant">{t.tenant}</label>
        <select id="s-tenant" bind:value={f.tenant} disabled={!!editing} required>
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="s-name">{t.name}</label>
        <input id="s-name" bind:value={f.name} required />
      </div>
      {#if isPluginKind(f.kind)}
        <!-- plugin settings follow below the grid -->
      {:else if f.kind === 'linux'}
        <div class="field">
          <label for="s-agent">{t.sources.agent}</label>
          <select
            id="s-agent"
            bind:value={f.agent_id}
            required
            aria-describedby={tenantAgents.length ? undefined : 's-agent-hint'}
          >
            {#each tenantAgents as a (a.id)}<option value={a.id}>{a.name} ({a.host})</option>{/each}
          </select>
          {#if !tenantAgents.length}<div class="hint" id="s-agent-hint">{t.sources.noAgents}</div>{/if}
        </div>
      {:else if isShare}
        <div class="field">
          <label for="n-host">{t.sources.sh.host}</label>
          <input id="n-host" bind:value={f.host} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="n-port">{t.sources.sh.port}</label>
          <input id="n-port" type="number" min="1" max="65535" bind:value={f.port} required />
        </div>
        <div class="field">
          <label for="n-ver">{t.sources.sh.version}</label>
          <select id="n-ver" bind:value={f.version}>
            {#each f.kind === 'nfs' ? ['4.2', '4.1', '4.0', '3'] : ['3', '3.1.1', '3.02', '3.0', '2.1'] as v (v)}
              <option value={v}>{f.kind === 'nfs' ? 'NFS' : 'SMB'} {v}</option>
            {/each}
          </select>
        </div>
        {#if f.kind === 'nfs'}
          <div class="field">
            <label for="n-exp">{t.sources.sh.export}</label>
            <input id="n-exp" class="mono" bind:value={f.export} required spellcheck="false" placeholder="/srv/share" />
          </div>
          {#if f.version === '3'}
            <div class="field">
              <label for="n-mp">{t.sources.sh.mountPort}</label>
              <input
                id="n-mp"
                type="number"
                min="1"
                max="65535"
                bind:value={f.mount_port}
                required
                aria-describedby="n-mp-hint"
              />
              <div class="hint" id="n-mp-hint">{t.sources.sh.mountPortHint}</div>
            </div>
          {/if}
        {:else}
          <div class="field">
            <label for="n-share">{t.sources.sh.share}</label>
            <input id="n-share" bind:value={f.share} required spellcheck="false" />
          </div>
          <div class="field">
            <label for="n-auth">{t.sources.sh.auth}</label>
            <select id="n-auth" bind:value={f.sec}>
              <option value="ntlmssp">{t.sources.sh.auths.ntlmssp}</option>
            </select>
          </div>
          <div class="field">
            <label for="n-user">{t.sources.sh.user}</label>
            <input id="n-user" bind:value={f.sh_user} required={f.sec === 'ntlmssp'} spellcheck="false" />
          </div>
          <div class="field">
            <label for="n-dom">{t.sources.sh.domain}</label>
            <input id="n-dom" bind:value={f.domain} spellcheck="false" />
          </div>
          {#if f.sec === 'ntlmssp'}
            <div class="field">
              <label for="n-pw">{t.sources.sh.password}</label>
              <input
                id="n-pw"
                type="password"
                bind:value={f.password}
                autocomplete="new-password"
                required={!(editing?.kind === 'smb' && editing.config?.password_set)}
                aria-describedby="n-pw-hint"
              />
              <div class="hint" id="n-pw-hint">
                {editing?.kind === 'smb' && editing.config?.password_set ? t.writeOnlyKeep : t.writeOnlyHint}
              </div>
            </div>
          {:else}
            <div class="field">
              <label for="n-princ">{t.sources.sh.principal}</label>
              <input id="n-princ" class="mono" bind:value={f.principal} required spellcheck="false" />
            </div>
            <div class="field">
              <label for="n-kt">{t.sources.sh.keytab}</label>
              <input
                id="n-kt"
                type="file"
                onchange={pickKeytab}
                required={!(editing?.kind === 'smb' && editing.config?.keytab_set)}
                aria-describedby="n-kt-hint"
              />
              <div class="hint" id="n-kt-hint">
                {editing?.kind === 'smb' && editing.config?.keytab_set ? t.sources.sh.keytabSet : t.writeOnlyHint}
              </div>
            </div>
          {/if}
        {/if}
        <div class="field">
          <label for="n-sd">{t.sources.sh.snapshotDir}</label>
          <input
            id="n-sd"
            class="mono"
            bind:value={f.snapshot_dir}
            spellcheck="false"
            placeholder=".zfs/snapshot"
            aria-describedby="n-sd-hint"
          />
          <div class="hint" id="n-sd-hint">{t.sources.sh.snapshotDirHint}</div>
        </div>
        {#if f.snapshot_dir.trim()}
          <div class="field">
            <label for="n-sp">{t.sources.sh.snapshotPrefix}</label>
            <input id="n-sp" class="mono" bind:value={f.snapshot_prefix} spellcheck="false" placeholder="auto-" />
          </div>
          <div class="field">
            <label for="n-so">{t.sources.sh.snapshotOrder}</label>
            <select id="n-so" bind:value={f.snapshot_order}>
              <option value="name">{t.sources.sh.orders.name}</option>
              <option value="mtime">{t.sources.sh.orders.mtime}</option>
            </select>
          </div>
        {/if}
        <div class="field">
          <label for="n-thr">{t.sources.sh.threads}</label>
          <input id="n-thr" type="number" min="1" max="64" bind:value={f.threads} required />
        </div>
        <div class="field">
          <label for="n-to">{t.sources.sh.timeout}</label>
          <input id="n-to" type="number" min="1" max="600" bind:value={f.timeout_secs} required />
        </div>
      {:else if f.kind === 'truenas'}
        <div class="field">
          <label for="t-host">{t.sources.tn.host}</label>
          <input id="t-host" bind:value={f.host} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-port">{t.sources.tn.port}</label>
          <input id="t-port" type="number" min="1" max="65535" bind:value={f.port} required />
        </div>
        <div class="field">
          <label for="t-ca">{t.sources.tn.connectAddr}</label>
          <input id="t-ca" class="mono" bind:value={f.connect_addr} spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-user">{t.sources.tn.user}</label>
          <input id="t-user" class="mono" bind:value={f.tn_user} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-key">{t.sources.tn.apiKey}</label>
          <input
            id="t-key"
            type="password"
            bind:value={f.token_secret}
            autocomplete="new-password"
            required={!editing}
            aria-describedby="t-key-hint"
          />
          <div class="hint" id="t-key-hint">
            {editing?.kind === 'truenas' && editing.config?.token_secret_set ? t.writeOnlyKeep : t.writeOnlyHint}
          </div>
        </div>
        <div class="field">
          <label for="t-sh">{t.sources.tn.sshHost}</label>
          <input id="t-sh" bind:value={f.ssh_host} placeholder={f.host} spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-sp">{t.sources.tn.sshPort}</label>
          <input id="t-sp" type="number" min="1" max="65535" bind:value={f.ssh_port} required />
        </div>
        <div class="field">
          <label for="t-su">{t.sources.tn.sshUser}</label>
          <input id="t-su" class="mono" bind:value={f.ssh_user} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-from">{t.sources.tn.from}</label>
          <input id="t-from" class="mono" bind:value={f.from} spellcheck="false" />
        </div>
      {:else if f.kind === 'vmware'}
        <div class="field">
          <label for="v-host">{t.sources.vm.host}</label>
          <input id="v-host" bind:value={f.host} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="v-port">{t.sources.vm.port}</label>
          <input id="v-port" type="number" min="1" max="65535" bind:value={f.port} required />
        </div>
        <div class="field">
          <label for="v-user">{t.sources.vm.user}</label>
          <input
            id="v-user"
            class="mono"
            bind:value={f.vm_user}
            required
            spellcheck="false"
            autocomplete="off"
            aria-describedby="v-user-hint"
          />
          <div class="hint" id="v-user-hint">{t.sources.vm.userHint}</div>
        </div>
        <div class="field">
          <label for="v-pw">{t.sources.vm.password}</label>
          <input
            id="v-pw"
            type="password"
            bind:value={f.password}
            autocomplete="new-password"
            required={!editing}
            aria-describedby="v-pw-hint"
          />
          <div class="hint" id="v-pw-hint">
            {editing?.kind === 'vmware' && editing.config?.password_set ? t.writeOnlyKeep : t.writeOnlyHint}
          </div>
        </div>
        <div class="field">
          <label for="v-dc">{t.sources.vm.datacenter}</label>
          <input
            id="v-dc"
            class="mono"
            bind:value={f.datacenter}
            required
            spellcheck="false"
            aria-describedby="v-dc-hint"
          />
          <div class="hint" id="v-dc-hint">{t.sources.vm.datacenterHint}</div>
        </div>
        <div class="field">
          <label for="v-tr">{t.sources.vm.transport}</label>
          <select id="v-tr" disabled aria-describedby="v-tr-hint">
            <option value="nfc" selected>{t.sources.vm.transportNfc}</option>
          </select>
          <div class="hint" id="v-tr-hint">{t.sources.vm.transportHint}</div>
        </div>
      {:else}
        <div class="field">
          <label for="s-host">{t.sources.host}</label>
          <input id="s-host" bind:value={f.host} required />
        </div>
        <div class="field">
          <label for="s-port">{t.sources.port}</label>
          <input id="s-port" type="number" min="1" max="65535" bind:value={f.port} required />
        </div>
        <div class="field">
          <label for="s-tid">{t.sources.tokenId}</label>
          <input id="s-tid" class="mono" bind:value={f.token_id} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="s-sec">{t.sources.tokenSecret}</label>
          <input
            id="s-sec"
            type="password"
            bind:value={f.token_secret}
            autocomplete="new-password"
            required={!editing}
            aria-describedby="s-sec-hint"
          />
          <div class="hint" id="s-sec-hint">
            {editing?.kind === 'pve' && editing.config?.token_secret_set ? t.writeOnlyKeep : t.writeOnlyHint}
          </div>
        </div>
        <div class="field">
          <label for="s-st">{t.sources.storage}</label>
          <input id="s-st" bind:value={f.storage} />
        </div>
        <div class="field">
          <label for="s-fl">{t.sources.fleecing}</label>
          <input id="s-fl" bind:value={f.fleecing_storage} />
        </div>
        <fieldset class="fl-guard">
          <legend>{t.sources.fleecingGuard}</legend>
          <p class="hint">{t.sources.fleecingGuardHint}</p>
          <div class="field">
            <label for="s-fl-pct">{t.sources.fleecingMinPct}</label>
            <input id="s-fl-pct" type="number" min="0" max="90" step="1" bind:value={f.fl_min_pct} />
          </div>
          <div class="field">
            <label for="s-fl-gib">{t.sources.fleecingMinGib}</label>
            <input id="s-fl-gib" type="number" min="0" step="1" bind:value={f.fl_min_gib} />
          </div>
          <div class="field">
            <label for="s-fl-cancel">{t.sources.fleecingCancelPct}</label>
            <input id="s-fl-cancel" type="number" min="0" max="90" step="1" bind:value={f.fl_cancel_pct} />
          </div>
          <p class="hint">{t.sources.fleecingGuardRule}</p>
        </fieldset>
      {/if}
    </div>
    {#if isPluginKind(f.kind)}
      {#if pk}
        <p class="muted">{t.sources.pluginHint(pk.plugin.name, pk.plugin.version, pk.plugin.publisher)}</p>
        <SchemaForm
          schema={pk.kind.config_schema}
          bind:values={pv}
          errors={pErrors}
          secretFields={pk.kind.secret_fields ?? []}
          secretSet={pSecretSet}
        />
      {:else}
        <p class="banner warn">{t.sources.noSchema}</p>
      {/if}
    {:else if f.kind === 'linux'}
      <div class="field">
        <label for="s-paths">{t.sources.paths}</label>
        <textarea
          id="s-paths"
          bind:value={f.paths}
          required
          spellcheck="false"
          placeholder={'/etc\n/home'}
          aria-describedby="s-paths-hint"></textarea>
        <div class="hint" id="s-paths-hint">{t.sources.pathsHint}</div>
      </div>
      <div class="field">
        <label for="s-excl">{t.sources.excludes}</label>
        <textarea
          id="s-excl"
          bind:value={f.excludes}
          spellcheck="false"
          placeholder={'*.tmp\n/var/cache/**'}
          aria-describedby="s-excl-hint"></textarea>
        <div class="hint" id="s-excl-hint">{t.sources.excludesHint}</div>
      </div>
      <div class="field">
        <label class="inline-check"
          ><input type="checkbox" bind:checked={f.hooks} aria-describedby="s-hooks-hint" />{t.sources.hooks}</label
        >
        <div class="hint" id="s-hooks-hint">{t.sources.hooksHint}</div>
      </div>
      <fieldset class="field">
        <legend>{t.sources.selection}</legend>
        <FileSelection bind:include={f.include} bind:regex={f.exclude_regex} share={false} />
        <div class="field">
          <label class="inline-check"
            ><input type="checkbox" bind:checked={f.cross_mounts} aria-describedby="s-xm-hint" />{t.sources
              .crossMounts}</label
          >
          <div class="hint" id="s-xm-hint">{t.sources.crossMountsHint}</div>
        </div>
        {#if f.cross_mounts}
          <div class="field">
            <label for="s-fst">{t.sources.skipFstypes}</label>
            <textarea
              id="s-fst"
              bind:value={f.skip_fstypes}
              spellcheck="false"
              placeholder={'vfat\ntmpfs'}
              aria-describedby="s-fst-hint"></textarea>
            <div class="hint" id="s-fst-hint">{t.sources.skipFstypesHint}</div>
          </div>
        {/if}
        <p class="hint">{t.sources.agentVersionNote}</p>
      </fieldset>
    {:else if isShare}
      {#if f.kind === 'smb'}
        <div class="field">
          <label class="inline-check"><input type="checkbox" bind:checked={f.sign} />{t.sources.sh.sign}</label>
          <label class="inline-check"
            ><input type="checkbox" bind:checked={f.seal} disabled={f.version === '2.1'} />{t.sources.sh.seal}</label
          >
        </div>
      {/if}
      <div class="field">
        <label class="inline-check"><input type="checkbox" bind:checked={f.xattrs} />{t.sources.sh.xattrs}</label>
      </div>
      <div class="field">
        <label for="n-excl">{t.sources.sh.excludes}</label>
        <textarea
          id="n-excl"
          bind:value={f.excludes}
          spellcheck="false"
          placeholder={'*.tmp\n/scratch/**'}
          aria-describedby="n-excl-hint"></textarea>
        <div class="hint" id="n-excl-hint">{t.sources.sh.excludesHint}</div>
      </div>
      <FileSelection bind:include={f.include} bind:regex={f.exclude_regex} share={true} />
      <p class="muted">{f.kind === 'nfs' ? t.sources.sh.nfsHint : t.sources.sh.shareHint}</p>
    {:else if f.kind === 'vmware'}
      <div class="field">
        <label for="v-cert">{t.sources.vm.cert}</label>
        <textarea
          id="v-cert"
          class="mono"
          bind:value={f.ca_pem}
          required
          spellcheck="false"
          aria-describedby="v-cert-hint"></textarea>
        <div class="hint" id="v-cert-hint">{t.sources.vm.certHint}</div>
      </div>
      <div class="field">
        <label for="v-nfc">{t.sources.vm.nfcHosts}</label>
        <textarea
          id="v-nfc"
          class="mono"
          bind:value={f.nfc_hosts}
          spellcheck="false"
          placeholder={'esx1.example.com\nesx2.example.com'}
          aria-describedby="v-nfc-hint"></textarea>
        <div class="hint" id="v-nfc-hint">{t.sources.vm.nfcHostsHint}</div>
      </div>
    {:else if f.kind === 'truenas'}
      <div class="field">
        <label for="t-ds">{t.sources.tn.datasets}</label>
        <textarea
          id="t-ds"
          class="mono"
          bind:value={f.datasets}
          required
          spellcheck="false"
          placeholder={'tank/data\ntank/smb'}
          aria-describedby="t-ds-hint"></textarea>
        <div class="hint" id="t-ds-hint">{t.sources.tn.datasetsHint}</div>
      </div>
      <div class="field">
        <label class="inline-check"><input type="checkbox" bind:checked={f.recursive} />{t.sources.tn.recursive}</label>
        <label class="inline-check"><input type="checkbox" bind:checked={f.sudo} />{t.sources.tn.sudo}</label>
        <label class="inline-check"><input type="checkbox" bind:checked={f.zfs_sudo} />{t.sources.tn.zfsSudo}</label>
      </div>
      <div class="field">
        <label class="inline-check"
          ><input type="checkbox" bind:checked={f.tn_existing} aria-describedby="t-ex-hint" />{t.nas.existing}</label
        >
        <div class="hint" id="t-ex-hint">{t.nas.existingHint}</div>
      </div>
      {#if f.tn_existing}
        <div class="field">
          <label for="t-ex-p">{t.nas.existingPrefix}</label>
          <input
            id="t-ex-p"
            class="mono"
            bind:value={f.tn_prefix}
            required
            pattern="[A-Za-z0-9][A-Za-z0-9_\-]{'{0,31}'}"
            spellcheck="false"
          />
        </div>
      {/if}
      <div class="field">
        <label for="t-cert">{t.sources.tn.cert}</label>
        <textarea
          id="t-cert"
          class="mono"
          bind:value={f.ca_pem}
          required
          spellcheck="false"
          aria-describedby="t-cert-hint"></textarea>
        <div class="hint" id="t-cert-hint">{t.sources.tn.certHint}</div>
      </div>
      <div class="field">
        <label for="t-hk">{t.sources.tn.hostKey}</label>
        <input
          id="t-hk"
          class="mono"
          bind:value={f.host_key}
          required
          spellcheck="false"
          aria-describedby="t-hk-hint"
        />
        <div class="hint" id="t-hk-hint">{t.sources.tn.hostKeyHint}</div>
      </div>
      <div class="field">
        <label for="t-pem">{t.sources.tn.keyPem}</label>
        <textarea
          id="t-pem"
          class="mono"
          bind:value={f.key_pem}
          required={!editing}
          spellcheck="false"
          autocomplete="off"
          aria-describedby="t-pem-hint"></textarea>
        <div class="hint" id="t-pem-hint">
          {editing?.kind === 'truenas' && editing.config?.ssh?.key_pem_set ? t.writeOnlyKeep : t.writeOnlyHint}
        </div>
      </div>
      <div class="field">
        <label for="t-pub">{t.sources.tn.publicKey}</label>
        <input id="t-pub" class="mono" bind:value={f.public_key} spellcheck="false" />
      </div>
      {#if editing?.kind === 'truenas' && editing.config?.authorized_keys}
        <div class="field">
          <label for="t-ak">{t.sources.tn.authorizedKeys}</label>
          <textarea id="t-ak" class="mono" readonly value={editing.config.authorized_keys} aria-describedby="t-ak-hint"
          ></textarea>
          <div class="hint" id="t-ak-hint">{t.sources.tn.authorizedKeysHint}</div>
        </div>
      {/if}
    {:else}
      <div class="field">
        <label for="s-ca">{t.sources.caPem}</label>
        <textarea id="s-ca" bind:value={f.ca_pem} spellcheck="false"></textarea>
      </div>
      <div class="field">
        <label for="s-nodes">{t.sources.nodes}</label>
        <textarea id="s-nodes" bind:value={f.nodes} spellcheck="false"></textarea>
      </div>
    {/if}
    {#if f.kind === 'pve' || f.kind === 'truenas' || isShare}
      <SourceLimits bind:form={f.lim} pve={f.kind === 'pve'} />
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button
        type="submit"
        class="primary"
        disabled={(f.kind === 'linux' && !f.agent_id) || (isPluginKind(f.kind) && !pk)}
        >{editing ? t.save : t.create}</button
      >
    </div>
  </form>
</Modal>

<PauseDialog
  bind:open={maintOpen}
  title={t.runctl.maintenanceTitle(maintSource?.name ?? '')}
  hint={t.runctl.maintenanceHint}
  submit={t.runctl.startMaintenance}
  onsubmit={maintenance}
/>
<Modal bind:open={invOpen} title={t.inventory.title(invOf?.name ?? '')} wide>
  {#if invOf}<Inventory source={invOf} />{/if}
</Modal>
<Modal bind:open={splitOpen} title={t.nas.splitTitle(splitOf?.name ?? '')}>
  <form onsubmit={split}>
    <p class="hint">{t.nas.splitHint}</p>
    <div class="field">
      <label for="sp-roots">{t.nas.roots}</label>
      <textarea
        id="sp-roots"
        class="mono"
        bind:value={sp.roots}
        required
        spellcheck="false"
        placeholder={'/projects\n/home'}
        aria-describedby="sp-roots-hint"></textarea>
      <div class="hint" id="sp-roots-hint">{t.nas.rootsHint}</div>
    </div>
    {#if splitOf?.kind === 'smb'}
      <div class="field">
        <label for="sp-pw">{t.sources.sh.password}</label>
        <input
          id="sp-pw"
          type="password"
          autocomplete="new-password"
          bind:value={sp.password}
          required
          aria-describedby="sp-pw-hint"
        />
        <div class="hint" id="sp-pw-hint">{t.nas.splitPassword}</div>
      </div>
    {/if}
    <div class="field">
      <label class="inline-check"><input type="checkbox" bind:checked={sp.copy_groups} />{t.nas.copyGroups}</label>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (splitOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.nas.split}</button>
    </div>
  </form>
</Modal>
