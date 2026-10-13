<script lang="ts">
  import { askConfirm } from '../lib/confirm.svelte';
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { navigate } from '../lib/router.svelte';
  import { agentStatus } from '../lib/jobs';
  import { fmtAgo, fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Agent, AgentToken, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import AgentEndpoint from '../components/AgentEndpoint.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';

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
  const shortFp = (fp: string) => (fp.length > 12 ? `${fp.slice(0, 12)}…` : fp);

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
    const r = await act(post<{ id: number }>(`/agents/${encodeURIComponent(a.id)}/enroll`), (d) => t.snap.jobStarted(d.id));
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
  <button type="button" class="primary" onclick={create}><IconPlus aria-hidden="true" />{t.agents.new}</button>
  <p class="lede">{t.agents.intro}</p>
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
            <th scope="col">{t.agents.hostShort}</th>
            <th scope="col">{t.agents.status}</th>
            <th scope="col">{t.agents.lastSeen}</th>
            <th scope="col">{t.ep.column}</th>
            <th scope="col">{t.agents.version} / {t.agents.os}</th>
            <th scope="col">{t.agents.cert}</th>
            <th scope="col">{t.agents.limits}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as a (a.id)}
            {@const st = agentStatus(a, now)}
            <tr>
              <td><strong>{a.name}</strong> <div class="muted mono">{a.id}</div></td>
              <td>{a.tenant}</td>
              <td class="mono">{a.host}:{a.port}</td>
              <td>
                <span class="chip {statusCls[st]}">{t.agents.statuses[st]}</span>
                {#if st === 'enrolled' && hasToken(a)}
                  <div class="muted">{t.agents.tokenUntil(fmtTime(a.token_expires))}</div>
                {:else if st === 'pending'}
                  <div class="muted">{t.agents.expires}: {fmtTime(a.token_expires)}</div>
                {/if}
              </td>
              <td class="nowrap" title={fmtTime(a.last_seen)}>{fmtAgo(a.last_seen, now)}</td>
              <td>
                {#if st === 'enrolled'}
                  {#if a.reachable === true}
                    <span class="chip ok" title={t.ep.lastPoll(fmtTime(a.last_poll ?? null))}>{t.ep.reachable}</span>
                  {:else if a.reachable === false}
                    <span class="chip warn" title={t.ep.lastPoll(fmtTime(a.last_poll ?? null))}>{t.ep.unreachable}</span>
                  {:else}
                    <span class="chip info">{t.ep.neverPolled}</span>
                  {/if}
                  {#if a.power?.on_battery}
                    <div class="muted">{t.ep.onBattery(a.power.battery_percent != null ? String(a.power.battery_percent) : '')}</div>
                  {/if}
                  {#if a.power?.metered}<div class="muted">{t.ep.metered}{a.power.network_name ? ` (${a.power.network_name})` : ''}</div>{/if}
                  {#if pendingRequest(a)}
                    <div><span class="chip info">{t.ep.requested(fmtAgo(a.last_request!.received, now))}</span></div>
                  {:else if a.last_request?.refused && now - a.last_request.received < 3600}
                    <div class="muted">{t.ep.requestRefused(a.last_request.refused)}</div>
                  {/if}
                  {#if a.missed_at}<div class="muted">{t.ep.missed(fmtTime(a.missed_at))}</div>{/if}
                {:else}—{/if}
              </td>
              <td>
                <span class="mono">{a.version ?? '—'}</span>
                {#if a.os}<div class="muted">{a.os}</div>{/if}
              </td>
              <td class="mono">
                {#if a.cert_sha256}<span title="SHA-256 {a.cert_sha256}">{shortFp(a.cert_sha256)}</span>{:else}—{/if}
                {#if a.cert_expires}<div class="muted">{t.agents.certUntil(fmtTime(a.cert_expires))}</div>{/if}
                {#if a.cert_renewal_pending}<div><span class="chip info">{t.agents.renewalPending}</span></div>{/if}
              </td>
              <td class="nowrap">{limitText(a)}</td>
              <td class="actions">
                <!-- Enrolling needs a valid one-time token; enrolled agents can re-enroll after "New token". -->
                {#if st !== 'enrolled' || hasToken(a)}
                  <button
                    type="button"
                    class="small"
                    disabled={!hasToken(a)}
                    title={hasToken(a) ? undefined : t.agents.enrollNeedsToken}
                    onclick={() => enroll(a)}>{st === 'enrolled' ? t.agents.reenroll : t.agents.enroll}</button
                  >
                {/if}
                <button type="button" class="small" onclick={() => newToken(a)}
                  >{st === 'enrolled' ? t.agents.reenrollToken : t.agents.newToken}</button
                >
                {#if st === 'enrolled'}
                  <button type="button" class="small" onclick={() => renew(a)}>{t.agents.renew}</button>
                  <button type="button" class="small" onclick={() => update(a)}>{t.agents.update}</button>
                {/if}
                <button type="button" class="small" onclick={() => limits(a)}>{t.agents.limits}</button>
                {#if st === 'enrolled'}
                  <button type="button" class="small" onclick={() => endpoint(a)}>{t.ep.button}</button>
                {/if}
                <button type="button" class="small danger" onclick={() => remove(a)}>{t.delete}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

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
        <input id="l-bw" type="number" min="0" step="0.0625" bind:value={lim.mib} required aria-describedby="l-bw-hint" />
        <div class="hint" id="l-bw-hint">{t.agents.bwlimitHint}</div>
      </div>
      <div class="field">
        <label for="l-nice">{t.agents.nice}</label>
        <input id="l-nice" type="number" min="0" max="19" bind:value={lim.nice} required aria-describedby="l-nice-hint" />
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
