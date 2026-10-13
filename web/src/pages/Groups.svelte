<script lang="ts">
  import { askConfirm } from '../lib/confirm.svelte';
  import { onMount, onDestroy } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { href } from '../lib/router.svelte';
  import { fmtAgo, fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { runJob } from '../lib/jobs';
  import { isPluginKind, pluginKinds } from '../lib/plugins';
  import type { Agent, Group, GroupMode, IndexRules, Inventory, Plugin, PluginGuest, Policy, Source, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import BackupNow from '../components/BackupNow.svelte';
  import PauseDialog from '../components/PauseDialog.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { isPaused, timeZones } from '../lib/schedule';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconPlay from '@lucide/svelte/icons/play';

  let items: Group[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let sources: Source[] = $state([]);
  let policies: Policy[] = $state([]);
  let agents: Agent[] = $state([]);
  let plugins: Plugin[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      [items, tenants, sources, policies, agents] = await Promise.all([
        get<Group[]>('/groups'),
        get<Tenant[]>('/tenants'),
        get<Source[]>('/sources'),
        get<Policy[]>('/policies'),
        get<Agent[]>('/agents'),
      ]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    try {
      plugins = await get<Plugin[]>('/plugins');
    } catch {
      /* plugin sources then offer no guest list */
    }
    loaded = true;
  }
  onMount(load);
  const kinds = $derived(pluginKinds(plugins));
  const kindTitle = (k: string) => t.sources.kinds[k] ?? kinds.get(k)?.kind.title ?? '—';

  const sourceName = (id: number) => sources.find((s) => s.id === id)?.name ?? `#${id}`;
  const policyName = (id: number) => policies.find((p) => p.id === id)?.name ?? `#${id}`;
  const agentName = (id: string) => agents.find((a) => a.id === id)?.name ?? id;
  const guestText = (g: number | string) => (typeof g === 'string' ? agentName(g) : String(g));

  let open = $state(false);
  let editing: Group | null = $state(null);
  let f = $state({
    tenant: '',
    name: '',
    source_id: 0,
    policy_id: 0,
    guests: '',
    datasets: [] as string[],
    mode: 'explicit' as GroupMode,
    selector: [] as string[],
    exclude: [] as string[],
    timezone: 'UTC',
    // Phase 15e/f
    disksAll: '',
    disksPer: '',
    disksMode: 'placeholder' as 'placeholder' | 'omit',
    parallel: 1,
  });
  const zones = timeZones();
  const tenantSources = $derived(sources.filter((s) => s.tenant === f.tenant));
  // A linux source backs up exactly one host: guests = [its agent id], no VM/CT IDs.
  const linuxSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s?.kind === 'linux' ? s : null;
  });
  // A truenas source: guests = a subset of its datasets (none = all).
  const nasSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s?.kind === 'truenas' ? s : null;
  });
  // An nfs/smb source is one share: the group has no guests.
  const shareSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s?.kind === 'nfs' || s?.kind === 'smb' ? s : null;
  });
  // A plugin source: guests are ids from the plugin's guest list (if its kind has one), else none.
  const pluginSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s && isPluginKind(s.kind) ? s : null;
  });
  const pluginGuests = $derived(pluginSource ? (kinds.get(pluginSource.kind)?.kind.guests ?? null) : null);
  const GUEST_RE = /^[A-Za-z0-9._-]{1,64}$/;
  // Phase 15e/f: disk selection (PVE) and parallel guests (PVE, plugins)
  const pveSource = $derived(sources.find((x) => x.id === Number(f.source_id))?.kind === 'pve');
  const parallelSource = $derived(pveSource || !!pluginSource);
  const DISK_RE = /^[a-z]+[0-9]{1,3}$/;
  const diskList = (v: string) => v.split(/[\s,]+/).filter(Boolean);
  /** `{"*": [...], "<vmid>": [...]}` from the two fields, or null (after telling the user). */
  function excludeDisks(): Record<string, string[]> | null {
    const out: Record<string, string[]> = {};
    const all = diskList(f.disksAll);
    const bad = all.find((d) => !DISK_RE.test(d));
    if (bad) {
      notify('error', t.groups.excludeDisksInvalid(bad));
      return null;
    }
    if (all.length) out['*'] = all;
    for (const line of f.disksPer.split('\n').map((l) => l.trim()).filter(Boolean)) {
      const m = /^(\d+)\s*:\s*(.+)$/.exec(line);
      const disks = m ? diskList(m[2]) : [];
      if (!m || !disks.length || disks.some((d) => !DISK_RE.test(d))) {
        notify('error', t.groups.excludeDisksInvalid(line));
        return null;
      }
      out[m[1]] = [...(out[m[1]] ?? []), ...disks];
    }
    return out;
  }
  const diskCount = (x: Group) => Object.values(x.exclude_disks ?? {}).reduce((n, l) => n + l.length, 0);

  // Auto-protect (Phase 13c): PVE, TrueNAS and plugin kinds with a guest list have an
  // inventory; their groups may take all guests or the guests with given tags.
  const invSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    if (!s) return null;
    return s.kind === 'pve' || s.kind === 'truenas' || (isPluginKind(s.kind) && !!kinds.get(s.kind)?.kind.guests?.list) ? s : null;
  });
  let inv = $state<Inventory | null>(null);
  let invBusy = $state(false);
  let invJob: number | null = $state(null);
  async function loadInventory(id: number) {
    try {
      const r = await get<Inventory>(`/sources/${id}/inventory`);
      if (Number(f.source_id) === id) inv = r;
    } catch {
      inv = null;
    }
  }
  $effect(() => {
    const s = invSource;
    inv = null;
    if (open && s) loadInventory(s.id);
  });
  async function refreshInventory() {
    const s = invSource;
    if (!s) return;
    invBusy = true;
    invJob = null;
    try {
      const r = await runJob('inventory', s.tenant, { source_id: s.id }, ctl.signal);
      if (r && r.job.state !== 'ok') {
        invJob = r.job.id;
        notify('error', t.groups.refreshFailed);
      }
      await loadInventory(s.id);
    } catch (e) {
      notify('error', errText(e));
    } finally {
      invBusy = false;
    }
  }
  const present = $derived(inv?.guests.filter((g) => g.gone === null) ?? []);
  const allTags = $derived([...new Set([...present.flatMap((g) => g.tags), ...f.selector])].sort());
  const matched = $derived(present.filter((g) => f.mode === 'all' || g.tags.some((x) => f.selector.includes(x))));
  const protectedNow = $derived(matched.filter((g) => !f.exclude.includes(g.guest)).length);
  const MODES: GroupMode[] = ['explicit', 'all', 'tags'];
  let tagInput = $state('');
  const TAG_RE = /^\S(?:[^\x00-\x1f\x7f]{0,126}\S)?$/;
  function addTag() {
    const x = tagInput.trim();
    if (!x) return;
    if (!TAG_RE.test(x)) {
      notify('error', t.groups.tagInvalid(x));
      return;
    }
    if (!f.selector.includes(x)) f.selector = [...f.selector, x];
    tagInput = '';
  }

  // "Load <guests.title>": plugin_guests job against the source.
  const ctl = new AbortController();
  onDestroy(() => ctl.abort());
  let guestList: { source: number; guests: PluginGuest[] } | null = $state(null);
  let guestsBusy = $state(false);
  let guestsJob: number | null = $state(null);
  async function loadGuests() {
    const s = pluginSource;
    if (!s) return;
    guestsBusy = true;
    guestsJob = null;
    try {
      const r = await runJob('plugin_guests', s.tenant, { source_id: s.id }, ctl.signal);
      if (r && r.job.state === 'ok') guestList = { source: s.id, guests: r.job.result?.guests ?? [] };
      else if (r) {
        guestsJob = r.job.id;
        notify('error', t.groups.guestsFailed);
      }
    } catch (e) {
      notify('error', errText(e));
    } finally {
      guestsBusy = false;
    }
  }
  /** Loaded guests of the selected source plus already selected ids that were not listed. */
  const guestChoices = $derived.by(() => {
    const listed = guestList && guestList.source === Number(f.source_id) ? guestList.guests : [];
    const extra = f.datasets.filter((g) => !listed.some((x) => x.id === g)).map((id) => ({ id, title: id }) as PluginGuest);
    return [...listed, ...extra];
  });

  // Keep the source selection valid when the tenant changes.
  $effect(() => {
    if (open && !tenantSources.some((s) => s.id === f.source_id)) f.source_id = tenantSources[0]?.id ?? 0;
  });

  function edit(x: Group | null) {
    editing = x;
    const tenant = x?.tenant ?? tenants[0]?.name ?? '';
    f = {
      tenant,
      name: x?.name ?? '',
      source_id: x?.source_id ?? sources.find((s) => s.tenant === tenant)?.id ?? 0,
      policy_id: x?.policy_id ?? policies[0]?.id ?? 0,
      guests: (x?.guests ?? []).filter((g) => typeof g === 'number').join(', '),
      datasets: (x?.guests ?? []).filter((g): g is string => typeof g === 'string'),
      timezone: x?.timezone ?? 'UTC',
      mode: x?.mode ?? 'explicit',
      selector: [...(x?.selector ?? [])],
      exclude: [...(x?.exclude ?? [])],
      disksAll: (x?.exclude_disks?.['*'] ?? []).join(', '),
      disksPer: Object.entries(x?.exclude_disks ?? {})
        .filter(([k]) => k !== '*')
        .map(([k, l]) => `${k}: ${l.join(', ')}`)
        .join('\n'),
      disksMode: x?.exclude_disks_mode ?? 'placeholder',
      parallel: x?.parallel_guests ?? 1,
    };
    // Phase 31b: on by default for new Proxmox VE groups
    indexFiles = x ? !!x.index_files : true;
    rules = null;
    scope = { defaults: true, include: '', exclude: '' };
    if (x) loadRules(x.id);
    tagInput = '';
    lastSource = f.source_id;
    guestList = null;
    open = true;
  }
  // Phase 15g/31b: file index of VM/CT disks (pve groups only, PUT /groups/{id}/index-files)
  let indexFiles = $state(true);
  // Phase 31b: search scope rules (GET/PUT /groups/{id}/index-rules); new groups start with the defaults
  const DEFAULT_EXCLUDES = [
    '/$Recycle.Bin', '/Windows', '/Program Files', '/Program Files (x86)', '/ProgramData', '/System Volume Information',
    '/Users/*/AppData', '/Recovery', '/proc', '/sys', '/dev', '/run', '/tmp', '/usr', '/lib', '/lib64', '/boot',
    '/var/cache', '/var/tmp', '/var/lib/docker', '/var/lib/containerd',
  ];
  let rules: IndexRules | null = $state(null);
  let scope = $state({ defaults: true, include: '', exclude: '' });
  const canWrite = $derived(can.manageTenant(session.user));
  async function loadRules(id: number) {
    try {
      const r = await get<IndexRules>(`/groups/${id}/index-rules`);
      if (editing?.id !== id) return;
      rules = r;
      scope = { defaults: r.defaults, include: r.include.join('\n'), exclude: r.exclude.join('\n') };
    } catch {
      /* no rules shown: the defaults apply */
    }
  }
  const ruleLines = (v: string) => v.split('\n').map((l) => l.trim()).filter(Boolean);
  // absolute, / separators, no empty or relative components; * only inside a component
  const RULE_RE = /^(\/[^/\\\x00-\x1f]+)+$/;
  const ruleOk = (r: string) => RULE_RE.test(r) && !r.split('/').some((c) => c === '.' || c === '..') && r.length <= 1024;
  /** The rules from the form, or null after telling the user what is wrong. */
  function scopeBody(): { defaults: boolean; include: string[]; exclude: string[] } | null {
    const include = ruleLines(scope.include);
    const exclude = ruleLines(scope.exclude);
    const bad = [...include, ...exclude].find((r) => !ruleOk(r));
    if (bad) {
      notify('error', t.groups.scopeInvalid(bad));
      return null;
    }
    if (include.length > 64 || exclude.length > 64) {
      notify('error', t.groups.scopeTooMany);
      return null;
    }
    return { defaults: scope.defaults, include, exclude };
  }
  const sameRules = (a: { defaults: boolean; include: string[]; exclude: string[] }, b: IndexRules | null) =>
    b
      ? a.defaults === b.defaults && a.include.join('\n') === b.include.join('\n') && a.exclude.join('\n') === b.exclude.join('\n')
      : a.defaults && !a.include.length && !a.exclude.length;
  // Another source: the selected guests/datasets belonged to the old one.
  let lastSource = 0;
  $effect(() => {
    if (!open || Number(f.source_id) === lastSource) return;
    lastSource = Number(f.source_id);
    f.datasets = [];
    f.exclude = [];
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    let guests: (number | string)[];
    const auto = !!invSource && f.mode !== 'explicit';
    if (auto) {
      guests = [];
      if (f.mode === 'tags' && !f.selector.length) {
        notify('error', t.groups.tags);
        return;
      }
    } else if (linuxSource) {
      guests = [linuxSource.config.agent_id];
    } else if (pluginSource) {
      // (f.datasets holds the selected guest ids of a plugin source too)
      guests = pluginGuests?.list ? f.datasets : [];
      const bad = (guests as string[]).find((g) => !GUEST_RE.test(g));
      if (bad) {
        notify('error', t.groups.guestInvalid(bad));
        return;
      }
    } else if (shareSource) {
      guests = [];
    } else if (nasSource) {
      guests = f.datasets.filter((d) => nasSource.config.datasets.includes(d));
    } else {
      guests = f.guests.split(/[\s,]+/).filter(Boolean).map(Number);
      if (guests.some((g) => !Number.isInteger(g) || Number(g) < 100)) {
        notify('error', t.groups.guests);
        return;
      }
    }
    const exclude_disks = pveSource ? excludeDisks() : {};
    if (!exclude_disks) return;
    const scopeNew = canWrite ? scopeBody() : null;
    if (canWrite && !scopeNew) return;
    // The tenant is fixed after creation (PUT rejects unknown fields, incl. tenant).
    // Excluding another disk comes back as 202 {quorum_id}: act() reports it as pending.
    const body = {
      name: f.name,
      source_id: Number(f.source_id),
      policy_id: Number(f.policy_id),
      guests,
      mode: auto ? f.mode : 'explicit',
      selector: auto && f.mode === 'tags' ? f.selector : [],
      exclude: auto ? f.exclude : [],
      timezone: f.timezone,
      exclude_disks,
      exclude_disks_mode: f.disksMode,
      parallel_guests: parallelSource ? Number(f.parallel) || 1 : 1,
    };
    const r = editing
      ? await act(put(`/groups/${editing.id}`, body), t.saved)
      : await act(post('/groups', { tenant: f.tenant, ...body }), t.created);
    if (r) {
      const id = editing?.id ?? (r.data as Partial<Group>).id;
      const was = editing ? !!editing.index_files : ((r.data as Partial<Group>).index_files ?? false);
      if (pveSource && id && !r.quorum && indexFiles !== was)
        await act(put(`/groups/${id}/index-files`, { enabled: indexFiles }), indexFiles ? t.groups.indexFilesOn : t.groups.indexFilesOff);
      if (scopeNew && id && !r.quorum && !sameRules(scopeNew, rules))
        await act(put(`/groups/${id}/index-rules`, scopeNew), t.groups.scopeSaved);
      open = false;
      load();
    }
  }

  // Run control (Phase 13b): back up now, pause / resume.
  let bnOpen = $state(false);
  let pauseOpen = $state(false);
  let target: Group | null = $state(null);
  async function pause(u: number | null) {
    if (target && (await act(post(`/groups/${target.id}/pause`, u === null ? {} : { until: u }), t.runctl.pausedDone))) {
      pauseOpen = false;
      load();
    }
  }
  async function resume(x: Group) {
    if (await act(post(`/groups/${x.id}/resume`), t.runctl.resumedDone)) load();
  }

  async function remove(x: Group) {
    if (!(await askConfirm(t.confirmDelete(`${t.dash.group} "${x.name}"`)))) return;
    if (await act(del(`/groups/${x.id}`), t.deleted)) load();
  }
</script>

<div class="page-head">
  <h1>{t.groups.title}</h1>
  <button type="button" class="primary" onclick={() => edit(null)}><IconPlus aria-hidden="true" />{t.groups.new}</button>
  <p class="lede">{t.groups.lede}</p>
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
            <th scope="col">{t.groups.source}</th>
            <th scope="col">{t.groups.policy}</th>
            <th scope="col">{t.groups.guestsShort}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            <tr>
              <td
                ><strong>{x.name}</strong>
                {#if isPaused(x.paused_until)}<span class="chip warn"
                    >{x.paused_until === -1 ? t.runctl.pausedForever : t.runctl.pausedUntil(fmtTime(x.paused_until))}</span
                  >{/if}
                {#if isPaused(x.maintenance_until)}<span class="chip warn">{t.runctl.inMaintenance}</span>{/if}
                {#if x.blackout_active}<span class="chip plain">{t.runctl.blackoutNow}</span>{/if}
                {#if x.index_files}<span class="chip plain">{t.groups.indexFilesShort}</span>{/if}
                {#if x.timezone && x.timezone !== 'UTC'}<div class="muted">{x.timezone}</div>{/if}
                {#if diskCount(x) || (x.parallel_guests ?? 1) > 1}<div class="muted">
                    {[diskCount(x) ? t.groups.disksShort(diskCount(x)) : '', (x.parallel_guests ?? 1) > 1 ? t.groups.parallelShort(x.parallel_guests) : '']
                      .filter(Boolean)
                      .join(' · ')}
                  </div>{/if}</td
              >
              <td>{x.tenant}</td>
              <td>{sourceName(x.source_id)}</td>
              <td>{policyName(x.policy_id)}</td>
              <td class="mono"
                >{#if x.mode && x.mode !== 'explicit'}{t.groups.auto(x.mode, x.selector.join(', '))}{#if x.exclude.length}<span
                      class="muted"> · {t.groups.except(x.exclude.join(', '))}</span
                    >{/if}{:else}{x.guests.length
                    ? x.guests.map(guestText).join(', ')
                    : kindTitle(sources.find((s) => s.id === x.source_id)?.kind ?? '')}{/if}</td
              >
              <td class="actions">
                {#if can.backup(session.user)}
                  <button
                    type="button"
                    class="small"
                    onclick={() => {
                      target = x;
                      bnOpen = true;
                    }}><IconPlay aria-hidden="true" />{t.runctl.backupNow}</button
                  >
                  {#if isPaused(x.paused_until)}
                    <button type="button" class="small" onclick={() => resume(x)}>{t.runctl.resume}</button>
                  {:else}
                    <button
                      type="button"
                      class="small"
                      onclick={() => {
                        target = x;
                        pauseOpen = true;
                      }}>{t.runctl.pause}</button
                    >
                  {/if}
                {/if}
                <button type="button" class="small" onclick={() => edit(x)}>{t.edit}</button>
                <button type="button" class="small danger" onclick={() => remove(x)}>{t.delete}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal bind:open title={editing ? `${t.dash.group}: ${editing.name}` : t.groups.new}>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="g-tenant">{t.tenant}</label>
        <select id="g-tenant" bind:value={f.tenant} disabled={!!editing} required>
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="g-name">{t.name}</label>
        <input id="g-name" bind:value={f.name} required />
      </div>
      <div class="field">
        <label for="g-src">{t.groups.source}</label>
        <select id="g-src" bind:value={f.source_id} required>
          {#each tenantSources as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="g-pol">{t.groups.policy}</label>
        <select id="g-pol" bind:value={f.policy_id} required>
          {#each policies as p (p.id)}<option value={p.id}>{p.name} ({p.schedule}){p.tier ? ` · ${t.tiers.names[p.tier]}` : ''}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="g-tz">{t.runctl.timezone}</label>
        <input id="g-tz" list="g-tz-list" bind:value={f.timezone} required aria-describedby="g-tz-hint" />
        <datalist id="g-tz-list">{#each zones as z (z)}<option value={z}></option>{/each}</datalist>
        <div class="hint" id="g-tz-hint">{t.runctl.timezoneHint}</div>
      </div>
    </div>
    {#if invSource}
      <fieldset class="field">
        <legend>{t.groups.mode}</legend>
        <div class="row">
          {#each MODES as m (m)}
            <label class="inline-check"><input type="radio" name="g-mode" value={m} bind:group={f.mode} />{t.groups.modes[m]}</label>
          {/each}
        </div>
        <p class="hint">{t.groups.modeHint[f.mode]}</p>
      </fieldset>
    {/if}
    {#if invSource && f.mode !== 'explicit'}
      <div class="row">
        <span class="muted">{inv?.refreshed ? t.groups.refreshed(fmtAgo(inv.refreshed)) : t.groups.noInventory}</span>
        <button type="button" class="small" disabled={invBusy} onclick={refreshInventory}
          >{invBusy ? t.groups.refreshing : t.groups.refresh}</button
        >
        {#if invJob}<a href={href(`/jobs/${invJob}`)}>{t.jobs.detail(invJob)}</a>{/if}
      </div>
      {#if f.mode === 'tags'}
        <fieldset class="field">
          <legend>{t.groups.tags}</legend>
          {#each allTags as x (x)}
            <label class="inline-check mono"><input type="checkbox" value={x} bind:group={f.selector} />{x}</label>
          {:else}
            <p class="hint">{t.groups.tagNone}</p>
          {/each}
          <div class="row">
            <input
              class="mono"
              aria-label={t.groups.tagAdd}
              placeholder={t.groups.tagAdd}
              bind:value={tagInput}
              onkeydown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addTag();
                }
              }}
            />
            <button type="button" class="small" onclick={addTag}>{t.groups.tagAddBtn}</button>
          </div>
        </fieldset>
      {/if}
      <fieldset class="field">
        <legend>{t.groups.exclude}</legend>
        <p class="hint">{t.groups.excludeHint}</p>
        {#each matched as g (g.guest)}
          <label class="inline-check"
            ><input type="checkbox" value={g.guest} bind:group={f.exclude} /><span class="mono">{g.guest}</span>{#if g.name !== g.guest}<span
                >{g.name}</span
              >{/if}</label
          >
        {/each}
        <p class="muted" role="status">{t.groups.preview(protectedNow, matched.length - protectedNow)}</p>
      </fieldset>
    {:else if linuxSource}
      <p class="muted">{t.groups.linuxGuest(agentName(linuxSource.config.agent_id))}</p>
    {:else if pluginSource}
      {#if pluginGuests?.list}
        <fieldset class="field">
          <legend>{t.groups.pluginGuests(pluginGuests.title)}</legend>
          <div class="row">
            <button type="button" class="small" disabled={guestsBusy} onclick={loadGuests}
              >{guestsBusy ? t.groups.loadingGuests : t.groups.loadGuests(pluginGuests.title)}</button
            >
            {#if guestsJob}<a href={href(`/jobs/${guestsJob}`)}>{t.jobs.detail(guestsJob)}</a>{/if}
          </div>
          {#each guestChoices as g (g.id)}
            <label class="inline-check"
              ><input type="checkbox" value={g.id} bind:group={f.datasets} /><span class="mono">{g.id}</span
              >{#if g.title !== g.id}<span>{g.title}</span>{/if}{#if g.size !== undefined}<span class="muted"
                  >{fmtBytes(g.size)}</span
                >{/if}</label
            >
          {:else}
            <p class="hint">{t.groups.guestsLoadHint(pluginGuests.title)}</p>
          {/each}
        </fieldset>
      {:else}
        <p class="muted">{t.groups.wholeSource}</p>
      {/if}
    {:else if shareSource}
      <p class="muted">{t.groups.wholeShare}</p>
    {:else if nasSource}
      <fieldset class="field">
        <legend>{t.groups.datasets}</legend>
        {#each nasSource.config.datasets as d (d)}
          <label class="inline-check mono"><input type="checkbox" value={d} bind:group={f.datasets} />{d}</label>
        {/each}
      </fieldset>
    {:else}
      <div class="field">
        <label for="g-guests">{t.groups.guests}</label>
        <input id="g-guests" class="mono" bind:value={f.guests} placeholder="100, 101, 200" />
      </div>
    {/if}
    {#if pveSource}
      <fieldset class="field">
        <legend>{t.groups.indexFiles}</legend>
        <div class="row">
          {#each [true, false] as on (on)}
            <label class="inline-check"
              ><input type="radio" name="g-idx" value={on} bind:group={indexFiles} aria-describedby="g-idx-hint" />{t.groups.indexFilesModes[
                on ? 'on' : 'off'
              ]}</label
            >
          {/each}
        </div>
        <p class="hint" id="g-idx-hint">{t.groups.indexFilesHint}</p>
      </fieldset>
      <fieldset class="field">
        <legend>{t.groups.disks}</legend>
        <div class="field">
          <label for="g-disks">{t.groups.excludeDisks}</label>
          <input id="g-disks" class="mono" bind:value={f.disksAll} placeholder="scsi1, virtio2" aria-describedby="g-disks-hint" />
          <div class="hint" id="g-disks-hint">{t.groups.excludeDisksHint}</div>
        </div>
        <div class="field">
          <label for="g-disks-per">{t.groups.excludeDisksPer}</label>
          <textarea id="g-disks-per" class="mono" bind:value={f.disksPer} spellcheck="false" placeholder={t.groups.excludeDisksPerHint}
          ></textarea>
        </div>
        <div class="field">
          <span class="muted">{t.groups.restoreMode}</span>
          <div class="row">
            {#each ['placeholder', 'omit'] as m (m)}
              <label class="inline-check"
                ><input type="radio" name="g-dmode" value={m} bind:group={f.disksMode} />{t.groups.restoreModes[m]}</label
              >
            {/each}
          </div>
        </div>
      </fieldset>
    {/if}
    <fieldset class="field" id="g-scope">
      <legend>{t.groups.scope}</legend>
      <p class="hint">{t.groups.scopeHint}</p>
      <label class="inline-check"
        ><input type="checkbox" bind:checked={scope.defaults} disabled={!canWrite} aria-describedby="g-scope-defaults" />{t.groups.scopeDefaults}</label
      >
      <p class="hint mono" id="g-scope-defaults">{t.groups.scopeDefaultList((rules?.default_excludes ?? DEFAULT_EXCLUDES).join(', '))}</p>
      <div class="form-grid">
        <div class="field">
          <label for="g-scope-inc">{t.groups.scopeInclude}</label>
          <textarea id="g-scope-inc" class="mono" rows="3" bind:value={scope.include} readonly={!canWrite} spellcheck="false" placeholder="/var/log"
          ></textarea>
        </div>
        <div class="field">
          <label for="g-scope-exc">{t.groups.scopeExclude}</label>
          <textarea id="g-scope-exc" class="mono" rows="3" bind:value={scope.exclude} readonly={!canWrite} spellcheck="false" placeholder="/data/tmp"
          ></textarea>
        </div>
      </div>
    </fieldset>
    {#if parallelSource}
      <div class="field">
        <label for="g-par">{t.groups.parallel}</label>
        <input id="g-par" type="number" min="1" max="8" bind:value={f.parallel} required aria-describedby="g-par-hint" />
        <div class="hint" id="g-par-hint">{t.groups.parallelHint}</div>
      </div>
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>

<BackupNow bind:open={bnOpen} group={target} label={guestText} />
<PauseDialog
  bind:open={pauseOpen}
  title={t.runctl.pauseTitle(target?.name ?? '')}
  hint={t.runctl.pauseHint}
  submit={t.runctl.pause}
  onsubmit={pause}
/>
