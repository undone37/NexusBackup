<script lang="ts">
  // Phase 27: agent releases (image + signed uploads), versions overview, rollouts with
  // waves / canary / thresholds / windows, automatic mode per tenant or group, rollback
  // with approval (docs/agent-update-plan.md "Implementation").
  import { onMount } from 'svelte';
  import { get, post, put, del, postRaw, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { session } from '../../lib/session.svelte';
  import { can } from '../../lib/roles';
  import { notify } from '../../lib/notify.svelte';
  import { navigate, href } from '../../lib/router.svelte';
  import { fmtAgo, fmtBytes, fmtTime } from '../../lib/format';
  import { cmpVersion } from '../../lib/plugins';
  import { t } from '../../lib/i18n';
  import type {
    Agent,
    AgentRelease,
    AgentReleases,
    AgentUpdateSetting,
    Group,
    Rollout,
    RolloutDetail,
    RolloutScope,
    Tenant,
    UpdateWindow,
  } from '../../lib/types';
  import Modal from '../../components/Modal.svelte';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import ProgressBar from '../../components/ProgressBar.svelte';
  import BlackoutEditor from '../../components/BlackoutEditor.svelte';
  import AgentInstallers from '../../components/AgentInstallers.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconUpload from '@lucide/svelte/icons/upload';

  let { tenants }: { tenants: Tenant[] } = $props();

  const admin = $derived(session.user?.role === 'admin');
  const writer = $derived(can.manageTenant(session.user));
  // rollouts and automatic mode are appliance-wide: not for tenant-scoped users
  const viewRollouts = $derived(
    !!session.user && !session.user.tenant && ['admin', 'security_officer', 'operator', 'viewer'].includes(session.user.role),
  );

  let rel: AgentReleases = $state({ recommended: null, releases: [] });
  let agents: Agent[] = $state([]);
  let groups: Group[] = $state([]);
  let rollouts: Rollout[] = $state([]);
  let settings: AgentUpdateSetting[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let now = $state(Date.now() / 1000);

  async function load() {
    try {
      [rel, agents, groups] = await Promise.all([
        get<AgentReleases>('/agent-releases'),
        get<Agent[]>('/agents'),
        get<Group[]>('/groups'),
      ]);
      if (viewRollouts) {
        [rollouts, settings] = await Promise.all([
          get<Rollout[]>('/agent-rollouts'),
          get<AgentUpdateSetting[]>('/agent-update-settings'),
        ]);
      }
      error = null;
    } catch (e) {
      error = errText(e);
    }
    now = Date.now() / 1000;
    loaded = true;
  }
  onMount(() => {
    load();
    // running rollouts move on their own: refresh while the tab is open
    const iv = setInterval(() => {
      if (rollouts.some((r) => r.state === 'running') && !document.hidden) load();
    }, 15000);
    return () => clearInterval(iv);
  });

  const recommended = $derived(rel.releases.find((r) => r.version === rel.recommended && r.signed) ?? null);
  const signedVersions = $derived(
    rel.releases.filter((r) => r.signed).map((r) => r.version).sort((a, b) => cmpVersion(b, a)),
  );

  // ---------------------------------------------------------------- releases
  let fileInput: HTMLInputElement | undefined = $state();
  let uploading = $state(false);
  async function upload(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    (e.currentTarget as HTMLInputElement).value = '';
    if (!f) return;
    uploading = true;
    const r = await act(postRaw<{ version: string }>('/agent-releases', f, { 'Content-Type': 'application/x-tar' }), (d) =>
      t.agentUpd.uploaded(d.version),
    );
    uploading = false;
    if (r) load();
  }
  async function removeRelease(r: AgentRelease) {
    if (!(await askConfirm(t.confirmDelete(t.agentUpd.deleteRelease(r.version))))) return;
    if (await act(del(`/agent-releases/${encodeURIComponent(r.version)}`), t.deleted)) load();
  }
  let artOpen = $state(false);
  let artRelease: AgentRelease | null = $state(null);
  function showArtifacts(r: AgentRelease) {
    artRelease = r;
    artOpen = true;
  }

  // ---------------------------------------------------------------- versions
  const enrolled = $derived(agents.filter((a) => a.cert_sha256));
  const isOutdated = (a: Agent) => !!rel.recommended && !!a.version && cmpVersion(a.version, rel.recommended) < 0;
  const isUnsupported = (a: Agent) => !!a.protocol && cmpVersion(a.protocol, '1.8') < 0;
  let filter = $state('all');
  const shown = $derived(
    enrolled.filter((a) => filter === 'all' || (filter === 'outdated' ? isOutdated(a) : isUnsupported(a))),
  );
  const perVersion = $derived.by(() => {
    const m = new Map<string, number>();
    for (const a of enrolled) m.set(a.version ?? '', (m.get(a.version ?? '') ?? 0) + 1);
    return [...m.entries()].sort((a, b) => cmpVersion(b[0] || '0', a[0] || '0'));
  });
  const stateCls: Record<string, string> = {
    pending: 'info',
    sending: 'info',
    installing: 'info',
    ok: 'ok',
    failed: 'bad',
    rolled_back: 'warn',
  };

  async function updateOne(a: Agent) {
    const v = rel.recommended;
    if (!v || !(await askConfirm(t.agentUpd.updateConfirm(a.name, v)))) return;
    const r = await act(
      post<{ id: number }>('/jobs', { kind: 'agent_update', tenant: a.tenant, params: { agent_id: a.id, version: v } }),
      (d) => t.snap.jobStarted(d.id),
    );
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }

  // tags
  const TAG_RE = /^[a-z0-9_.-]{1,32}$/;
  let tagOpen = $state(false);
  let tagAgent: Agent | null = $state(null);
  let tagText = $state('');
  function editTags(a: Agent) {
    tagAgent = a;
    tagText = (a.tags ?? []).join(', ');
    tagOpen = true;
  }
  async function saveTags(e: SubmitEvent) {
    e.preventDefault();
    if (!tagAgent) return;
    const tags = [...new Set(tagText.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean))];
    const bad = tags.find((x) => !TAG_RE.test(x));
    if (bad || tags.length > 16) {
      notify('error', t.agentUpd.tagsInvalid(bad ?? tags[16]));
      return;
    }
    if (await act(put(`/agents/${encodeURIComponent(tagAgent.id)}/tags`, { tags }), t.saved)) {
      tagOpen = false;
      load();
    }
  }

  // ---------------------------------------------------------------- rollouts
  const rolloutCls: Record<string, string> = {
    pending_approval: 'info',
    running: 'accent',
    paused: 'warn',
    cancelled: 'plain',
    done: 'ok',
    rejected: 'bad',
  };
  const itemCls: Record<string, string> = {
    waiting: 'plain',
    queued: 'info',
    running: 'accent',
    ok: 'ok',
    failed: 'bad',
    skipped: 'plain',
    cancelled: 'plain',
  };
  const finished = (r: Rollout) => r.counts.ok + r.counts.failed + r.counts.skipped + r.counts.cancelled;
  const pct = (r: Rollout) => (r.counts.total ? (100 * finished(r)) / r.counts.total : 0);
  const groupName = (id: number | null | undefined) => groups.find((g) => g.id === id)?.name ?? `#${id}`;
  const scopeText = (s: RolloutScope) =>
    t.agentUpd.scopeText({
      tenant: s.tenant,
      group: s.group_id ? groupName(s.group_id) : undefined,
      os: s.os ? (t.agentUpd.oses[s.os] ?? s.os) : undefined,
      tag: s.tag,
      agents: s.agents ? s.agents.length : undefined,
    });

  async function control(r: Rollout, verb: 'pause' | 'resume' | 'cancel') {
    if (verb === 'cancel' && !(await askConfirm(t.agentUpd.cancelConfirm(r.version)))) return;
    if (verb === 'pause' && !(await askConfirm(t.agentUpd.pauseConfirm(r.version)))) return;
    const ok = { pause: t.agentUpd.paused, resume: t.agentUpd.resumed, cancel: t.agentUpd.cancelled }[verb];
    if (await act(post(`/agent-rollouts/${r.id}/${verb}`), ok)) {
      await load();
      if (detail?.id === r.id) openDetail(r);
    }
  }

  let detailOpen = $state(false);
  let detail: RolloutDetail | null = $state(null);
  async function openDetail(r: Rollout) {
    try {
      detail = await get<RolloutDetail>(`/agent-rollouts/${r.id}`);
      detailOpen = true;
    } catch (e) {
      notify('error', errText(e));
    }
  }
  const agentName = (id: string) => agents.find((a) => a.id === id)?.name ?? id;

  // new rollout
  type ScopeKind = 'all' | 'tenant' | 'group' | 'os' | 'tag' | 'agents';
  let newOpen = $state(false);
  let nf = $state({
    version: '',
    scopeKind: 'all' as ScopeKind,
    tenant: '',
    group: 0,
    os: 'linux',
    tag: '',
    agents: [] as string[],
    canaryMode: 'count' as 'count' | 'pct',
    canary: 1,
    canaryPct: 10,
    soak: 60,
    concurrency: 5,
    maxFailures: 3,
    maxFailurePct: 20,
    windows: [] as UpdateWindow[],
    rollback: false,
  });
  function newRollout() {
    nf = {
      version: rel.recommended ?? signedVersions[0] ?? '',
      scopeKind: 'all',
      tenant: tenants[0]?.name ?? '',
      group: groups[0]?.id ?? 0,
      os: 'linux',
      tag: '',
      agents: [],
      canaryMode: 'count',
      canary: 1,
      canaryPct: 10,
      soak: 60,
      concurrency: 5,
      maxFailures: 3,
      maxFailurePct: 20,
      windows: [],
      rollback: false,
    };
    newOpen = true;
  }
  // a version older than some enrolled agent needs the rollback flag
  const newest = $derived(
    enrolled.map((a) => a.version).filter((v): v is string => !!v).sort((a, b) => cmpVersion(b, a))[0] ?? null,
  );
  const needsRollback = $derived(!!nf.version && !!newest && cmpVersion(nf.version, newest) < 0);
  const allTags = $derived([...new Set(enrolled.flatMap((a) => a.tags ?? []))].sort());

  async function saveRollout(e: SubmitEvent) {
    e.preventDefault();
    const scope: RolloutScope = {};
    if (nf.scopeKind === 'tenant') scope.tenant = nf.tenant;
    if (nf.scopeKind === 'group') scope.group_id = Number(nf.group);
    if (nf.scopeKind === 'os') scope.os = nf.os;
    if (nf.scopeKind === 'tag') scope.tag = nf.tag.trim();
    if (nf.scopeKind === 'agents') scope.agents = [...nf.agents];
    const body = {
      version: nf.version,
      scope,
      ...(nf.canaryMode === 'count' ? { canary: Number(nf.canary) } : { canary_pct: Number(nf.canaryPct) }),
      soak_minutes: Number(nf.soak),
      concurrency: Number(nf.concurrency),
      max_failures: Number(nf.maxFailures),
      max_failure_pct: Number(nf.maxFailurePct),
      windows: nf.windows.map((w) => ({ days: w.days, from: w.from, to: w.to })),
      rollback: nf.rollback,
    };
    const r = await act(post<Rollout>('/agent-rollouts', body), (d) => t.agentUpd.created(d.id));
    if (r) {
      newOpen = false;
      load();
    }
  }

  // ---------------------------------------------------------------- automatic mode
  let setOpen = $state(false);
  let sf = $state({ tenant: '', group: 0, mode: 'automatic' as 'manual' | 'automatic', canary: 1, soak: 60, windows: [] as UpdateWindow[] });
  function editSetting(s?: AgentUpdateSetting) {
    sf = s
      ? {
          tenant: s.tenant,
          group: s.group_id ?? 0,
          mode: s.mode,
          canary: s.canary,
          soak: s.soak_minutes,
          windows: s.windows.map((w) => ({ ...w, days: [...w.days] })),
        }
      : { tenant: tenants[0]?.name ?? '', group: 0, mode: 'automatic', canary: 1, soak: 60, windows: [] };
    setOpen = true;
  }
  async function saveSetting(e: SubmitEvent) {
    e.preventDefault();
    const body = {
      tenant: sf.tenant,
      ...(Number(sf.group) ? { group_id: Number(sf.group) } : {}),
      mode: sf.mode,
      windows: sf.windows.map((w) => ({ days: w.days, from: w.from, to: w.to })),
      canary: Number(sf.canary),
      soak_minutes: Number(sf.soak),
    };
    if (await act(put('/agent-update-settings', body), t.saved)) {
      setOpen = false;
      load();
    }
  }
  const windowsText = (ws: UpdateWindow[]) =>
    ws.length ? ws.map((w) => `${w.days.length ? w.days.join(',') : t.agentUpd.daily} ${w.from}-${w.to}`).join('; ') : t.agentUpd.anyTime;
</script>

<ErrorBanner {error} />
<p class="lede">{t.agentUpd.intro}</p>

<section class="card" data-testid="agent-releases">
  <div class="card-head">
    <h2>{t.agentUpd.releases}</h2>
    {#if admin}
      <button type="button" class="primary" disabled={uploading} onclick={() => fileInput?.click()}
        ><IconUpload aria-hidden="true" />{t.agentUpd.upload}</button
      >
      <input bind:this={fileInput} type="file" accept=".tar,application/x-tar" class="visually-hidden" tabindex="-1" aria-hidden="true" onchange={upload} />
    {/if}
  </div>
  {#if admin}<p class="hint">{t.agentUpd.uploadHint}</p>{/if}
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else}
    <p>{rel.recommended ? t.agentUpd.recommendedIs(rel.recommended) : t.agentUpd.noRecommended}</p>
    {#if rel.releases.length}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.agentUpd.version}</th>
              <th scope="col">{t.agentUpd.source}</th>
              <th scope="col">{t.agentUpd.signature}</th>
              <th scope="col">{t.agentUpd.released}</th>
              <th scope="col">{t.agentUpd.notes}</th>
              <th scope="col">{t.agentUpd.artifacts}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each [...rel.releases].sort((a, b) => cmpVersion(b.version, a.version)) as r (r.version + r.source)}
              <tr>
                <td>
                  <strong class="mono">{r.version}</strong>
                  {#if r.version === rel.recommended && r.signed}<span class="chip accent">{t.agentUpd.recommended}</span>{/if}
                  {#if r.protocol}<div class="muted">{t.agentUpd.protocol(r.protocol)}</div>{/if}
                </td>
                <td>{t.agentUpd.sources[r.source] ?? r.source}</td>
                <td>
                  {#if r.signed}
                    <span class="chip ok">{t.agentUpd.signedBy(r.key ?? '?')}</span>
                  {:else}
                    <span class="chip bad">{t.agentUpd.unsigned}</span>
                    {#if r.error}<div class="muted">{r.error}</div>{/if}
                  {/if}
                </td>
                <td class="nowrap">{r.released ?? '—'}</td>
                <td>{r.notes ?? ''}</td>
                <td>
                  <button type="button" class="small" onclick={() => showArtifacts(r)}>{t.agentUpd.artifactsN(r.artifacts.length)}</button>
                </td>
                <td class="actions">
                  {#if admin && r.source === 'upload'}
                    <button type="button" class="small danger" onclick={() => removeRelease(r)}>{t.delete}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</section>

<section class="card" data-testid="agent-versions">
  <div class="card-head">
    <h2>{t.agentUpd.versions}</h2>
    <div class="field inline">
      <label for="upd-filter">{t.agentUpd.filter}</label>
      <select id="upd-filter" bind:value={filter}>
        {#each Object.entries(t.agentUpd.filters) as [k, v] (k)}<option value={k}>{v}</option>{/each}
      </select>
    </div>
  </div>
  <p class="hint">{t.agentUpd.versionsIntro}</p>
  {#if loaded}
    <p class="chips">
      {#each perVersion as [v, n] (v)}
        <span class="chip {rel.recommended && v && cmpVersion(v, rel.recommended) < 0 ? 'warn' : 'ok'}"
          >{t.agentUpd.perVersion(v || t.agentUpd.unknownVersion, n)}</span
        >
      {/each}
    </p>
    {#if shown.length === 0}
      <p class="empty">{t.agentUpd.noAgents}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.agentUpd.agent}</th>
              <th scope="col">{t.agentUpd.version}</th>
              <th scope="col">{t.agentUpd.platform}</th>
              <th scope="col">{t.agentUpd.tags}</th>
              <th scope="col">{t.agentUpd.updateState}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each shown as a (a.id)}
              <tr>
                <td><strong>{a.name}</strong> <div class="muted">{a.tenant}</div></td>
                <td>
                  <span class="mono">{a.version ?? '—'}</span>
                  {#if isOutdated(a)}<span class="chip warn">{t.agentUpd.outdated}</span>{/if}
                  {#if isUnsupported(a)}<span class="chip bad">{t.agentUpd.unsupported}</span>{/if}
                  {#if a.protocol}<div class="muted">{t.agentUpd.protocol(a.protocol)}</div>{/if}
                </td>
                <td>
                  {a.os ?? '—'}
                  <div class="muted">
                    {[a.arch, a.install ? (t.agentUpd.installs[a.install] ?? a.install) : null, a.gui_version ? t.agentUpd.gui(a.gui_version) : null]
                      .filter(Boolean)
                      .join(' · ')}
                  </div>
                </td>
                <td>
                  {#each a.tags ?? [] as tg (tg)}<span class="chip plain">{tg}</span>{/each}
                  {#if writer}
                    <button type="button" class="small" aria-label={t.agentUpd.tagsTitle(a.name)} onclick={() => editTags(a)}>{t.agentUpd.editTags}</button>
                  {/if}
                </td>
                <td>
                  {#if a.update_state}
                    <span class="chip {stateCls[a.update_state] ?? 'plain'}">{t.agentUpd.updateStates[a.update_state] ?? a.update_state}</span>
                    {#if a.update_target}<div class="muted">{t.agentUpd.target(a.update_target)}</div>{/if}
                    {#if a.update_at}<div class="muted" title={fmtTime(a.update_at)}>{fmtAgo(a.update_at, now)}</div>{/if}
                    {#if a.update_error}<div class="err-text">{a.update_error}</div>{/if}
                    {#if a.update_attempts && a.update_attempts > 1}<div class="muted">{t.agentUpd.attempts(a.update_attempts)}</div>{/if}
                  {:else}—{/if}
                </td>
                <td class="actions">
                  {#if admin && isOutdated(a) && recommended}
                    <button type="button" class="small" onclick={() => updateOne(a)}>{t.agentUpd.updateTo(recommended.version)}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</section>

{#if viewRollouts}
  <section class="card" data-testid="agent-rollouts">
    <div class="card-head">
      <h2>{t.agentUpd.rollouts}</h2>
      {#if admin}
        <button type="button" class="primary" disabled={!signedVersions.length} onclick={newRollout}
          ><IconPlus aria-hidden="true" />{t.agentUpd.newRollout}</button
        >
      {/if}
    </div>
    <p class="hint">{t.agentUpd.rolloutsIntro}</p>
    {#if loaded && rollouts.length === 0}
      <p class="empty">{t.agentUpd.noRollouts}</p>
    {:else if loaded}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">{t.agentUpd.version}</th>
              <th scope="col">{t.agentUpd.scope}</th>
              <th scope="col">{t.state}</th>
              <th scope="col">{t.agentUpd.progress}</th>
              <th scope="col">{t.agentUpd.wave}</th>
              <th scope="col">{t.time}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each rollouts as r (r.id)}
              <tr>
                <td class="mono">{r.id}</td>
                <td>
                  <strong class="mono">{r.version}</strong>
                  {#if r.rollback}<span class="chip warn">{t.agentUpd.rollback}</span>{/if}
                  {#if r.automatic}<span class="chip info">{t.agentUpd.automatic}</span>{/if}
                </td>
                <td>{scopeText(r.scope)}</td>
                <td>
                  <span class="chip {rolloutCls[r.state] ?? 'plain'}">{t.agentUpd.rolloutStates[r.state] ?? r.state}</span>
                  {#if r.reason}<div class="muted">{r.reason}</div>{/if}
                </td>
                <td class="progress">
                  <ProgressBar value={pct(r)} label={t.agentUpd.progressLabel(r.version)} size="s" />
                  <div class="muted">{t.agentUpd.progressText(r.counts)}</div>
                  {#if t.agentUpd.counts(r.counts)}<div class="muted">{t.agentUpd.counts(r.counts)}</div>{/if}
                </td>
                <td>{t.agentUpd.waves[r.wave] ?? r.wave}</td>
                <td class="nowrap" title={fmtTime(r.created)}>{t.agentUpd.createdBy(r.created_by, fmtAgo(r.created, now))}</td>
                <td class="actions">
                  <button type="button" class="small" onclick={() => openDetail(r)}>{t.agentUpd.details}</button>
                  {#if admin && r.state === 'running'}
                    <button type="button" class="small" onclick={() => control(r, 'pause')}>{t.agentUpd.pause}</button>
                  {/if}
                  {#if admin && r.state === 'paused'}
                    <button type="button" class="small" onclick={() => control(r, 'resume')}>{t.agentUpd.resume}</button>
                  {/if}
                  {#if admin && ['running', 'paused', 'pending_approval'].includes(r.state)}
                    <button type="button" class="small danger" onclick={() => control(r, 'cancel')}>{t.agentUpd.cancelRollout}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <section class="card" data-testid="agent-update-settings">
    <div class="card-head">
      <h2>{t.agentUpd.auto}</h2>
      {#if admin}
        <button type="button" class="primary" onclick={() => editSetting()}><IconPlus aria-hidden="true" />{t.agentUpd.addSetting}</button>
      {/if}
    </div>
    <p class="hint">{t.agentUpd.autoIntro}</p>
    {#if loaded && settings.length === 0}
      <p class="empty">{t.agentUpd.noSettings}</p>
    {:else if loaded}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.tenant}</th>
              <th scope="col">{t.agentUpd.group}</th>
              <th scope="col">{t.agentUpd.mode}</th>
              <th scope="col">{t.agentUpd.windows}</th>
              <th scope="col">{t.agentUpd.canary}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each settings as s (`${s.tenant}/${s.group_id ?? 0}`)}
              <tr>
                <td>{s.tenant}</td>
                <td>{s.group_id ? groupName(s.group_id) : t.agentUpd.wholeTenant}</td>
                <td><span class="chip {s.mode === 'automatic' ? 'info' : 'plain'}">{t.agentUpd.modes[s.mode]}</span></td>
                <td>{windowsText(s.windows)}</td>
                <td class="nowrap">{t.agentUpd.canaryShort(s.canary)}, {t.agentUpd.soakShort(s.soak_minutes)}</td>
                <td class="actions">
                  {#if admin}<button type="button" class="small" onclick={() => editSetting(s)}>{t.edit}</button>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{:else if loaded && !admin}
  <p class="muted">{t.agentUpd.readOnly}</p>
{/if}

<Modal bind:open={artOpen} title="{t.agentUpd.artifacts} {artRelease?.version ?? ''}" wide>
  {#if artRelease}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.name}</th>
            <th scope="col">{t.kind}</th>
            <th scope="col">{t.agentUpd.platform}</th>
            <th scope="col">{t.agentUpd.version}</th>
            <th scope="col">SHA-256</th>
          </tr>
        </thead>
        <tbody>
          {#each artRelease.artifacts as x (x.name)}
            <tr>
              <td class="mono">{x.name} <div class="muted">{fmtBytes(x.size)}</div></td>
              <td>{x.kind}</td>
              <td class="nowrap">{x.os} {x.arch}</td>
              <td class="mono">{x.version}</td>
              <td><div class="mono sha">{x.sha256}</div></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if artRelease.signed && can.download(session.user) && writer}
      <h3>{t.agentUpd.installers}</h3>
      <AgentInstallers release={artRelease} />
    {/if}
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (artOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<Modal bind:open={tagOpen} title={t.agentUpd.tagsTitle(tagAgent?.name ?? '')}>
  <form onsubmit={saveTags}>
    <div class="field">
      <label for="upd-tags">{t.agentUpd.tagsLabel}</label>
      <input id="upd-tags" class="mono" bind:value={tagText} autocomplete="off" spellcheck="false" aria-describedby="upd-tags-hint" />
      <div class="hint" id="upd-tags-hint">{t.agentUpd.tagsHint}</div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (tagOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.save}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={detailOpen} title={t.agentUpd.detailsTitle(detail?.id ?? 0, detail?.version ?? '')} wide>
  {#if detail}
    {@const d = detail}
    <div class="detail-head">
      <span class="chip {rolloutCls[d.state] ?? 'plain'}">{t.agentUpd.rolloutStates[d.state] ?? d.state}</span>
      {#if d.rollback}<span class="chip warn">{t.agentUpd.rollback}</span>{/if}
      {#if d.automatic}<span class="chip info">{t.agentUpd.automatic}</span>{/if}
      <span>{scopeText(d.scope)}</span>
    </div>
    {#if d.reason}<p class="banner warn">{d.reason}</p>{/if}
    <ProgressBar value={pct(d)} label={t.agentUpd.progressLabel(d.version)} />
    <p class="muted">
      {t.agentUpd.progressText(d.counts)} · {t.agentUpd.canaryShort(d.canary_pct !== null ? d.canary_pct : d.canary)}{d.canary_pct !== null ? ' %' : ''},
      {t.agentUpd.soakShort(d.soak_minutes)} · {t.agentUpd.concurrency}: {d.concurrency} · {t.agentUpd.maxFailures}: {d.max_failures} / {d.max_failure_pct} % ·
      {windowsText(d.windows)}
    </p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.agentUpd.agent}</th>
            <th scope="col">{t.agentUpd.wave}</th>
            <th scope="col">{t.state}</th>
            <th scope="col">{t.agentUpd.version}</th>
            <th scope="col">{t.time}</th>
          </tr>
        </thead>
        <tbody>
          {#each d.items as it (it.agent_id)}
            <tr>
              <td><strong>{it.name || agentName(it.agent_id)}</strong> <div class="muted">{it.tenant}</div></td>
              <td>{t.agentUpd.waves[it.wave] ?? it.wave}</td>
              <td>
                <span class="chip {itemCls[it.state] ?? 'plain'}">{t.agentUpd.itemStates[it.state] ?? it.state}</span>
                {#if it.attempts > 1}<span class="muted">{t.agentUpd.attempts(it.attempts)}</span>{/if}
                {#if it.error}<div class="err-text">{it.error}</div>{/if}
                {#if it.job_id}<div><a href={href(`/jobs/${it.job_id}`)} onclick={() => (detailOpen = false)}>{t.agentUpd.job(it.job_id)}</a></div>{/if}
              </td>
              <td class="mono">{t.agentUpd.fromTo(it.from_version, it.version ?? d.version)}</td>
              <td class="nowrap" title={fmtTime(it.updated)}>{fmtAgo(it.updated, now)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <div class="form-actions">
      {#if admin && d.state === 'running'}<button type="button" onclick={() => control(d, 'pause')}>{t.agentUpd.pause}</button>{/if}
      {#if admin && d.state === 'paused'}<button type="button" onclick={() => control(d, 'resume')}>{t.agentUpd.resume}</button>{/if}
      <button type="button" class="primary" onclick={() => (detailOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<Modal bind:open={newOpen} title={t.agentUpd.newRollout} wide>
  <form onsubmit={saveRollout}>
    <div class="form-grid">
      <div class="field">
        <label for="ro-version">{t.agentUpd.version}</label>
        <select id="ro-version" bind:value={nf.version} required>
          {#each signedVersions as v (v)}<option value={v}>{v}{v === rel.recommended ? ` (${t.agentUpd.recommended})` : ''}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="ro-scope">{t.agentUpd.scope}</label>
        <select id="ro-scope" bind:value={nf.scopeKind}>
          {#each Object.entries(t.agentUpd.scopes) as [k, v] (k)}<option value={k}>{v}</option>{/each}
        </select>
      </div>
      {#if nf.scopeKind === 'tenant'}
        <div class="field">
          <label for="ro-tenant">{t.tenant}</label>
          <select id="ro-tenant" bind:value={nf.tenant} required>
            {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
          </select>
        </div>
      {:else if nf.scopeKind === 'group'}
        <div class="field">
          <label for="ro-group">{t.agentUpd.group}</label>
          <select id="ro-group" bind:value={nf.group} required>
            {#each groups as g (g.id)}<option value={g.id}>{g.tenant} / {g.name}</option>{/each}
          </select>
        </div>
      {:else if nf.scopeKind === 'os'}
        <div class="field">
          <label for="ro-os">{t.agentUpd.scopes.os}</label>
          <select id="ro-os" bind:value={nf.os}>
            {#each Object.entries(t.agentUpd.oses) as [k, v] (k)}<option value={k}>{v}</option>{/each}
          </select>
        </div>
      {:else if nf.scopeKind === 'tag'}
        <div class="field">
          <label for="ro-tag">{t.agentUpd.scopes.tag}</label>
          <input id="ro-tag" class="mono" list="ro-tags" bind:value={nf.tag} required pattern="[a-z0-9_.\-]{'{'}1,32{'}'}" autocomplete="off" />
          <datalist id="ro-tags">{#each allTags as tg (tg)}<option value={tg}></option>{/each}</datalist>
        </div>
      {:else if nf.scopeKind === 'agents'}
        <div class="field">
          <label for="ro-agents">{t.agentUpd.selectAgents}</label>
          <select id="ro-agents" multiple size="6" bind:value={nf.agents} required aria-describedby="ro-agents-hint">
            {#each enrolled as a (a.id)}<option value={a.id}>{a.tenant} / {a.name} ({a.version ?? '?'})</option>{/each}
          </select>
          <div class="hint" id="ro-agents-hint">{t.agentUpd.selectAgentsHint}</div>
        </div>
      {/if}
    </div>

    <fieldset class="field">
      <legend>{t.agentUpd.canaryMode}</legend>
      <p class="hint">{t.agentUpd.canaryHint}</p>
      <label class="inline-check"><input type="radio" value="count" bind:group={nf.canaryMode} />{t.agentUpd.canaryCount}</label>
      <label class="inline-check"><input type="radio" value="pct" bind:group={nf.canaryMode} />{t.agentUpd.canaryPct}</label>
      <div class="form-grid">
        {#if nf.canaryMode === 'count'}
          <div class="field">
            <label for="ro-canary">{t.agentUpd.canary}</label>
            <input id="ro-canary" type="number" min="0" max="1000" bind:value={nf.canary} required />
          </div>
        {:else}
          <div class="field">
            <label for="ro-canary-pct">{t.agentUpd.canaryPctLabel}</label>
            <input id="ro-canary-pct" type="number" min="1" max="100" bind:value={nf.canaryPct} required />
          </div>
        {/if}
        <div class="field">
          <label for="ro-soak">{t.agentUpd.soak}</label>
          <input id="ro-soak" type="number" min="0" max="10080" bind:value={nf.soak} required />
        </div>
      </div>
    </fieldset>

    <div class="form-grid">
      <div class="field">
        <label for="ro-conc">{t.agentUpd.concurrency}</label>
        <input id="ro-conc" type="number" min="1" max="100" bind:value={nf.concurrency} required />
      </div>
      <div class="field">
        <label for="ro-maxf">{t.agentUpd.maxFailures}</label>
        <input id="ro-maxf" type="number" min="0" max="10000" bind:value={nf.maxFailures} required aria-describedby="ro-thr-hint" />
      </div>
      <div class="field">
        <label for="ro-maxp">{t.agentUpd.maxFailurePct}</label>
        <input id="ro-maxp" type="number" min="0" max="100" bind:value={nf.maxFailurePct} required aria-describedby="ro-thr-hint" />
      </div>
    </div>
    <div class="field"><div class="hint" id="ro-thr-hint">{t.agentUpd.thresholdHint}</div></div>

    <BlackoutEditor bind:windows={nf.windows} mode="span" legend={t.agentUpd.windows} hint={t.agentUpd.windowsHint} idp="ro-w" />

    <div class="field">
      <label class="inline-check"><input type="checkbox" bind:checked={nf.rollback} aria-describedby="ro-rb-hint" />{t.agentUpd.rollbackLabel}</label>
      <div class="hint" id="ro-rb-hint">{t.agentUpd.rollbackHint}</div>
      {#if needsRollback && !nf.rollback}
        <p class="banner warn" role="alert">{t.agentUpd.rollbackNeeded(nf.version, newest ?? '')}</p>
      {/if}
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (newOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={setOpen} title={t.agentUpd.settingTitle} wide>
  <form onsubmit={saveSetting}>
    <div class="form-grid">
      <div class="field">
        <label for="us-tenant">{t.tenant}</label>
        <select id="us-tenant" bind:value={sf.tenant} required>
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="us-group">{t.agentUpd.group}</label>
        <select id="us-group" bind:value={sf.group}>
          <option value={0}>{t.agentUpd.wholeTenant}</option>
          {#each groups.filter((g) => g.tenant === sf.tenant) as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="us-mode">{t.agentUpd.mode}</label>
        <select id="us-mode" bind:value={sf.mode}>
          {#each Object.entries(t.agentUpd.modes) as [k, v] (k)}<option value={k}>{v}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="us-canary">{t.agentUpd.canary}</label>
        <input id="us-canary" type="number" min="0" max="1000" bind:value={sf.canary} required />
      </div>
      <div class="field">
        <label for="us-soak">{t.agentUpd.soak}</label>
        <input id="us-soak" type="number" min="0" max="10080" bind:value={sf.soak} required />
      </div>
    </div>
    <BlackoutEditor bind:windows={sf.windows} mode="span" legend={t.agentUpd.windows} hint={t.agentUpd.windowsHint} idp="us-w" />
    <div class="form-actions">
      <button type="button" onclick={() => (setOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.save}</button>
    </div>
  </form>
</Modal>

<style>
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }
  .progress {
    min-width: 10rem;
  }
  .sha {
    width: 17rem;
    word-break: break-all;
    font-size: 0.8em;
  }
  .detail-head {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
    margin-bottom: 0.75rem;
  }
  .err-text {
    color: var(--bad);
  }
  .field.inline {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0;
  }
</style>
