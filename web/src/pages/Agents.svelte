<script lang="ts">
  import { askConfirm } from '../lib/confirm.svelte';
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { navigate, route } from '../lib/router.svelte';
  import { agentStatus, jobLink } from '../lib/jobs';
  import { fmtAgo, fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Agent, AgentToken, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import AgentsRescue from './AgentsRescue.svelte';
  import { can } from '../lib/roles';
  import { session } from '../lib/session.svelte';
  import AgentEndpoint from '../components/AgentEndpoint.svelte';
  import Menu, { type MenuItem } from '../components/Menu.svelte';
  import { rowClick } from '../lib/rowlink';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';
  import Fleet from './agents/Fleet.svelte';
  import Updates from './agents/Updates.svelte';
  import AgentInstallers from '../components/AgentInstallers.svelte';
  import type { AgentRelease, AgentReleases } from '../lib/types';

  // Phase 24d: tabs Agents | Fleet (fleet secrets, discovered agents, CSV bulk enrollment)
  // Phase 27: Updates (releases, versions, rollouts, automatic mode)
  const TABS = ['agents', 'fleet', 'updates'];
  const tab = $derived(TABS.includes(route.query.get('tab') ?? '') ? route.query.get('tab')! : 'agents');
  const tabsId = $props.id();
  function keys(e: KeyboardEvent) {
    if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) return;
    e.preventDefault();
    const i = TABS.indexOf(tab);
    const next =
      e.key === 'Home'
        ? TABS[0]
        : e.key === 'End'
          ? TABS[TABS.length - 1]
          : TABS[(i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length];
    navigate(`/agents?tab=${next}`);
    queueMicrotask(() => document.getElementById(`${tabsId}-tab-${next}`)?.focus());
  }

  let items: Agent[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let now = $state(Date.now() / 1000);

  async function load() {
    try {
      [items, tenants] = await Promise.all([get<Agent[]>('/agents'), get<Tenant[]>('/tenants')]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    now = Date.now() / 1000;
    loaded = true;
  }
  onMount(load);

  const statusCls = { enrolled: 'ok', pending: 'info', expired: 'warn' };
  const hasToken = (a: Agent) => a.token_expires !== null && a.token_expires > now;
  // Phase 19a: bare-metal recovery / P2V (Linux agents only)
  let rescue: ReturnType<typeof AgentsRescue> | undefined = $state();
  const bmrOk = (a: Agent) => can.backup(session.user) && !a.os?.startsWith('Windows');
  // the row's other actions (the main one is a button of its own)
  function agentActions(a: Agent, st: ReturnType<typeof agentStatus>): MenuItem[] {
    const out: MenuItem[] = [];
    if (st === 'enrolled') {
      if (hasToken(a)) out.push({ label: t.agents.reenroll, onselect: () => enroll(a) });
      out.push({ label: t.agents.renew, onselect: () => renew(a) });
      out.push({ label: t.agents.update, onselect: () => update(a) });
      out.push({ label: t.agents.reenrollToken, onselect: () => newToken(a) });
    } else if (hasToken(a)) {
      out.push({ label: t.agents.newToken, onselect: () => newToken(a) });
    }
    out.push({ label: t.agents.limits, onselect: () => limits(a) });
    if (bmrOk(a)) out.push({ label: t.bmr.action, onselect: () => rescue?.openFor(a) });
    out.push({ label: t.delete, onselect: () => remove(a) });
    return out;
  }

  // Create
  let open = $state(false);
  let f = $state({ tenant: '', name: '', host: '', port: 7444 });

  function create() {
    f = { tenant: tenants[0]?.name ?? '', name: '', host: '', port: 7444 };
    open = true;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const body = { tenant: f.tenant, name: f.name.trim(), host: f.host.trim(), port: Number(f.port) };
    const r = await act(post<Agent & { token: string; install_command: string }>('/agents', body), t.created);
    if (!r) return;
    open = false;
    if (!r.quorum && r.data.token) showToken(r.data.name, r.data);
    load();
  }

  // One-time token: kept only while the dialog is open, dropped as soon as it closes.
  let tok: (AgentToken & { name: string }) | null = $state(null);
  let tokOpen = $state(false);
  function showToken(name: string, d: { token: string; install_command: string; token_expires: number | null }) {
    tok = { name, token: d.token, install_command: d.install_command, token_expires: d.token_expires ?? 0 };
    tokOpen = true;
    loadInstallers();
  }
  // Phase 27: signed installers of the recommended release, offered next to the token
  let installers: AgentRelease | null = $state(null);
  async function loadInstallers() {
    if (!can.download(session.user)) return;
    try {
      const r = await get<AgentReleases>('/agent-releases');
      installers = r.releases.find((x) => x.version === r.recommended && x.signed) ?? null;
    } catch {
      installers = null;
    }
  }
  $effect(() => {
    if (!tokOpen) tok = null;
  });

  async function newToken(a: Agent) {
    const enrolled = agentStatus(a, now) === 'enrolled';
    if (!(await askConfirm(enrolled ? t.agents.reenrollConfirm(a.name) : t.agents.newTokenConfirm(a.name)))) return;
    const r = await act(post<AgentToken>(`/agents/${encodeURIComponent(a.id)}/token`), t.saved);
    if (!r) return;
    if (!r.quorum && r.data.token) showToken(a.name, r.data);
    load();
  }

  async function enroll(a: Agent) {
    const r = await act(
      post<{ id: number }>(`/agents/${encodeURIComponent(a.id)}/enroll`),
      (d) => t.snap.jobStarted(d.id),
      jobLink,
    );
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }

  async function update(a: Agent) {
    if (!(await askConfirm(t.agents.updateConfirm(a.name)))) return;
    const r = await act(
      post<{ id: number }>('/jobs', { kind: 'agent_update', tenant: a.tenant, params: { agent_id: a.id } }),
      (d) => t.snap.jobStarted(d.id),
    );
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }

  // Phase 15f: certificate renewal over the session, appliance-side limits
  async function renew(a: Agent) {
    if (!(await askConfirm(t.agents.renewConfirm(a.name)))) return;
    const r = await act(
      post<{ id: number }>('/jobs', { kind: 'agent_renew', tenant: a.tenant, params: { agent_id: a.id } }),
      (d) => t.snap.jobStarted(d.id),
    );
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }

  const MIB = 1 << 20;
  let limOpen = $state(false);
  let limAgent: Agent | null = $state(null);
  let lim = $state({ mib: 0 as number, nice: 0 as number });
  function limits(a: Agent) {
    limAgent = a;
    const l = a.limits as { bwlimit?: number; nice?: number };
    lim = { mib: (l.bwlimit ?? 0) / MIB, nice: l.nice ?? 0 };
    limOpen = true;
  }
  async function saveLimits(e: SubmitEvent) {
    e.preventDefault();
    if (!limAgent) return;
    const bwlimit = Math.round((Number(lim.mib) || 0) * MIB);
    if (bwlimit !== 0 && bwlimit < 65536) {
      notify('error', t.agents.bwlimitInvalid);
      return;
    }
    const body = { bwlimit, nice: Number(lim.nice) || 0 };
    if (await act(put(`/agents/${encodeURIComponent(limAgent.id)}/limits`, body), t.saved)) {
      limOpen = false;
      load();
    }
  }
  const limitText = (a: Agent) => {
    const l = a.limits as { bwlimit?: number; nice?: number };
    if (!l.bwlimit && !l.nice) return t.agents.limitsNone;
    return t.agents.limitsShort(l.bwlimit ? `${fmtBytes(l.bwlimit)}/s` : '', l.nice ?? 0);
  };

  // Phase 24a: endpoint status and settings
  let epOpen = $state(false);
  let epAgent: Agent | null = $state(null);
  function endpoint(a: Agent) {
    epAgent = a;
    epOpen = true;
  }
  async function epSaved() {
    await load();
    epAgent = items.find((x) => x.id === epAgent?.id) ?? null;
  }
  const pendingRequest = (a: Agent) =>
    a.last_request && !a.last_request.refused && now - a.last_request.received < 3600 ? a.last_request : null;

  async function remove(a: Agent) {
    if (!(await askConfirm(t.confirmDelete(t.agents.deleteWhat(a.name))))) return;
    if (await act(del(`/agents/${encodeURIComponent(a.id)}`), t.deleted)) load();
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      notify('ok', t.users.copied);
    } catch {
      /* clipboard unavailable (non-secure context): the text is selectable */
    }
  }
</script>

<div class="page-head">
  <h1>{t.agents.title}</h1>
  {#if tab === 'agents'}
    <button type="button" class="primary" onclick={create}><IconPlus aria-hidden="true" />{t.agents.new}</button>
  {/if}
  {#if tab !== 'updates'}<p class="lede">{tab === 'fleet' ? t.fleet.intro : t.agents.intro}</p>{/if}
</div>

<div class="tabs" role="tablist" aria-label={t.agents.title} tabindex="-1" onkeydown={keys}>
  {#each TABS as x (x)}
    <button
      type="button"
      role="tab"
      id="{tabsId}-tab-{x}"
      aria-selected={x === tab}
      aria-controls="{tabsId}-panel"
      tabindex={x === tab ? 0 : -1}
      onclick={() => navigate(`/agents?tab=${x}`)}>{t.agents.tabs[x]}</button
    >
  {/each}
</div>

<div id="{tabsId}-panel" role="tabpanel" aria-labelledby="{tabsId}-tab-{tab}">
  {#if tab === 'fleet'}
    <Fleet {tenants} />
  {:else if tab === 'updates'}
    <Updates {tenants} />
  {:else}
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
                <th scope="col">{t.agents.status}</th>
                <th scope="col">{t.ep.column}</th>
                <th scope="col">{t.agents.version} / {t.agents.os}</th>
                <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
              </tr>
            </thead>
            <tbody>
              {#each items as a (a.id)}
                {@const st = agentStatus(a, now)}
                <tr use:rowClick={st === 'enrolled' ? () => endpoint(a) : null}>
                  <td>
                    <strong>{a.name}</strong>
                    <div class="muted mono small">{a.host}:{a.port}</div>
                    <div class="muted mono small">{a.id}</div>
                  </td>
                  <td>{a.tenant}</td>
                  <td>
                    <span class="chip {statusCls[st]}">{t.agents.statuses[st]}</span>
                    {#if st === 'enrolled' && hasToken(a)}
                      <div class="muted small">{t.agents.tokenUntil(fmtTime(a.token_expires))}</div>
                    {:else if st === 'pending'}
                      <div class="muted small">{t.agents.expires}: {fmtTime(a.token_expires)}</div>
                    {/if}
                    {#if a.cert_expires}<div
                        class="muted small"
                        title={a.cert_sha256 ? `SHA-256 ${a.cert_sha256}` : undefined}
                      >
                        {t.agents.certUntil(fmtTime(a.cert_expires))}
                      </div>{/if}
                    {#if a.cert_renewal_pending}<div><span class="chip info">{t.agents.renewalPending}</span></div>{/if}
                  </td>
                  <td>
                    {#if st === 'enrolled'}
                      {#if a.reachable === true}
                        <span class="chip ok" title={t.ep.lastPoll(fmtTime(a.last_poll ?? null))}>{t.ep.reachable}</span
                        >
                      {:else if a.reachable === false}
                        <span class="chip warn" title={t.ep.lastPoll(fmtTime(a.last_poll ?? null))}
                          >{t.ep.unreachable}</span
                        >
                      {:else}
                        <span class="chip info">{t.ep.neverPolled}</span>
                      {/if}
                      {#if a.via === 'edge'}<span class="chip info">{t.ep.viaEdge}</span>{/if}
                    {/if}
                    <div class="muted small" title={fmtTime(a.last_seen)}>
                      {t.agents.lastSeen}: {fmtAgo(a.last_seen, now)}
                    </div>
                    {#if st === 'enrolled'}
                      {#if a.power?.on_battery}
                        <div class="muted small">
                          {t.ep.onBattery(a.power.battery_percent != null ? String(a.power.battery_percent) : '')}
                        </div>
                      {/if}
                      {#if a.power?.metered}<div class="muted small">
                          {t.ep.metered}{a.power.network_name ? ` (${a.power.network_name})` : ''}
                        </div>{/if}
                      {#if pendingRequest(a)}
                        <div>
                          <span class="chip info">{t.ep.requested(fmtAgo(a.last_request!.received, now))}</span>
                        </div>
                      {:else if a.last_request?.refused && now - a.last_request.received < 3600}
                        <div class="muted small">{t.ep.requestRefused(a.last_request.refused)}</div>
                      {/if}
                      {#if a.missed_at}<div class="muted small">{t.ep.missed(fmtTime(a.missed_at))}</div>{/if}
                    {/if}
                    {#if limitText(a) !== t.agents.limitsNone}<div class="muted small">
                        {t.agents.limits}: {limitText(a)}
                      </div>{/if}
                  </td>
                  <td>
                    <span class="mono">{a.version ?? '—'}</span>
                    {#if a.os}<div class="muted small">{a.os}</div>{/if}
                  </td>
                  <td class="actions">
                    <!-- the main action visible, everything else in the menu -->
                    {#if st === 'enrolled'}
                      <button type="button" class="small" onclick={() => endpoint(a)}>{t.ep.button}</button>
                    {:else if hasToken(a)}
                      <button type="button" class="small primary" onclick={() => enroll(a)}>{t.agents.enroll}</button>
                    {:else}
                      <button type="button" class="small" onclick={() => newToken(a)}>{t.agents.newToken}</button>
                    {/if}
                    <Menu label={t.agents.more} ariaLabel={t.agents.moreLabel(a.name)} items={agentActions(a, st)} />
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}
</div>

<AgentsRescue bind:this={rescue} agents={items} />

<Modal bind:open title={t.agents.new}>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="a-tenant">{t.tenant}</label>
        <select id="a-tenant" bind:value={f.tenant} required>
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="a-name">{t.name}</label>
        <input id="a-name" bind:value={f.name} required maxlength="64" autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label for="a-host">{t.agents.host}</label>
        <input id="a-host" class="mono" bind:value={f.host} required autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label for="a-port">{t.agents.port}</label>
        <input id="a-port" type="number" min="1" max="65535" bind:value={f.port} required />
      </div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={tokOpen} title={t.agents.tokenTitle(tok?.name ?? '')} wide>
  {#if tok}
    <p class="banner warn" role="alert">{t.agents.tokenOnce}</p>
    <p>{t.agents.tokenSteps}</p>
    <div class="field">
      <span class="muted">{t.agents.installCommand}</span>
      <code class="secret">{tok.install_command}</code>
      <button type="button" class="small" onclick={() => copy(tok!.install_command)}>{t.users.copy}</button>
    </div>
    <div class="field">
      <span class="muted">{t.agents.token}</span>
      <code class="secret">{tok.token}</code>
      <button type="button" class="small" onclick={() => copy(tok!.token)}>{t.users.copy}</button>
    </div>
    {#if tok.token_expires}<p class="muted">{t.agents.expires}: {fmtTime(tok.token_expires)}</p>{/if}
    {#if can.download(session.user)}
      <h3>{t.agentUpd.installers}</h3>
      <AgentInstallers release={installers} />
    {/if}
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (tokOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<Modal bind:open={limOpen} title={t.agents.limitsTitle(limAgent?.name ?? '')}>
  <form onsubmit={saveLimits}>
    <p class="hint">{t.agents.limitsIntro}</p>
    <div class="form-grid">
      <div class="field">
        <label for="l-bw">{t.agents.bwlimit}</label>
        <input
          id="l-bw"
          type="number"
          min="0"
          step="0.0625"
          bind:value={lim.mib}
          required
          aria-describedby="l-bw-hint"
        />
        <div class="hint" id="l-bw-hint">{t.agents.bwlimitHint}</div>
      </div>
      <div class="field">
        <label for="l-nice">{t.agents.nice}</label>
        <input
          id="l-nice"
          type="number"
          min="0"
          max="19"
          bind:value={lim.nice}
          required
          aria-describedby="l-nice-hint"
        />
        <div class="hint" id="l-nice-hint">{t.agents.niceHint}</div>
      </div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (limOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.save}</button>
    </div>
  </form>
</Modal>

<AgentEndpoint bind:open={epOpen} agent={epAgent} onsaved={epSaved} />
