<script lang="ts">
  import { jobLink } from '../lib/jobs';
  // Phase 19a: bare-metal recovery and P2V of Linux agent hosts (docs/bmr.md).
  // The per-agent dialog (token, sessions, P2V form) and the "Recoveries" overview of the Agents page.
  import { onMount } from 'svelte';
  import { askConfirm } from '../lib/confirm.svelte';
  import { get, post, act, errText } from '../lib/api';
  import { copyText } from '../lib/clipboard';
  import { fmtBytes, fmtTime, fmtAgo } from '../lib/format';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/roles';
  import { session } from '../lib/session.svelte';
  import { t } from '../lib/i18n';
  import type { Agent, PveSource, RescueSession, Snapshot, Source } from '../lib/types';
  import Modal from '../components/Modal.svelte';

  let { agents }: { agents: Agent[] } = $props();

  const LIST_ROLES = ['admin', 'operator', 'viewer', 'security_officer'];
  const mayList = $derived(!!session.user && LIST_ROLES.includes(session.user.role));
  const manage = $derived(can.backup(session.user));

  let sessions: RescueSession[] = $state([]);
  let error: string | null = $state(null);
  let now = $state(Date.now() / 1000);

  async function load() {
    if (!mayList) return;
    try {
      sessions = await get<RescueSession[]>('/rescue');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    now = Date.now() / 1000;
  }
  onMount(load);

  const ACTIVE = ['issued', 'waiting', 'running'];
  const anyActive = $derived(sessions.some((s) => ACTIVE.includes(s.state)));
  // poll while something is in flight (or the dialog is open: a console may check in any moment)
  $effect(() => {
    if (!anyActive && !open) return;
    const h = setInterval(load, 5000);
    return () => clearInterval(h);
  });

  const stateCls: Record<string, string> = {
    issued: 'info',
    waiting: 'warn',
    running: 'info',
    done: 'ok',
    failed: 'bad',
    cancelled: 'plain',
    expired: 'plain',
  };
  const agentName = (s: RescueSession) => s.agent_name ?? agents.find((a) => a.id === s.agent_id)?.name ?? s.agent_id;
  const diskList = (s: RescueSession) => s.disks.map((d) => d.path).join(', ');

  // ------------------------------------------------------------- dialog
  let open = $state(false);
  let agent = $state<Agent | null>(null);
  let snaps: Snapshot[] = $state([]);
  let pves: PveSource[] = $state([]);
  let pick = $state(0);
  let reboot = $state(true);
  // one-time token: dropped when the dialog closes
  let token = $state<{ token: string; expires: number } | null>(null);
  $effect(() => {
    if (!open) token = null;
  });

  const mine = $derived(agent ? sessions.filter((s) => s.agent_id === agent!.id) : []);
  const hostSource = $derived(agent ? `host-${agent.id}` : '');

  let p2v = $state(blankP2v());
  function blankP2v() {
    return { time: 0, source_id: 0, node: '', storage: '', iso: '', iso_storage: '', bridge: 'vmbr0', memory: 2048, cores: 2, vmid: '' as number | '', name: '' };
  }
  const pveNodes = $derived(Object.keys(pves.find((s) => s.id === Number(p2v.source_id))?.config.nodes ?? {}));

  /** Opens the dialog for an agent (called from the Agents table). */
  export async function openFor(a: Agent) {
    agent = a;
    reboot = true;
    token = null;
    snaps = [];
    pves = [];
    p2v = blankP2v();
    open = true;
    load();
    try {
      const [ss, srcs] = await Promise.all([
        get<Snapshot[]>(`/snapshots?tenant=${encodeURIComponent(a.tenant)}&source=${encodeURIComponent(`host-${a.id}`)}`),
        get<Source[]>('/sources'),
      ]);
      snaps = ss.sort((x, y) => y.time - x.time);
      pves = srcs.filter((s): s is PveSource => s.kind === 'pve' && s.tenant === a.tenant);
      pick = snaps[0]?.time ?? 0;
      p2v.time = pick;
      p2v.source_id = pves[0]?.id ?? 0;
      p2v.node = Object.keys(pves[0]?.config.nodes ?? {})[0] ?? '';
      p2v.storage = pves[0]?.config.fleecing_storage ?? '';
    } catch (e) {
      error = errText(e);
    }
  }

  async function issue() {
    if (!agent) return;
    if (!(await askConfirm(t.bmr.issueConfirm(agent.name)))) return;
    const r = await act(post<RescueSession & { token: string }>(`/agents/${encodeURIComponent(agent.id)}/rescue`, { reboot }), t.bmr.issued);
    if (!r) return;
    if (!r.quorum && r.data.token) token = { token: r.data.token, expires: r.data.token_expires };
    load();
  }

  async function start(s: RescueSession) {
    if (!pick) return;
    if (!(await askConfirm(t.bmr.startConfirm(`${s.host}:${s.port}`, diskList(s) || '—')))) return;
    const r = await act(post<{ id: number }>(`/rescue/${encodeURIComponent(s.id)}/start`, { time: Number(pick), reboot: s.reboot }), (d) =>
      t.bmr.started(d.id),
      jobLink,
    );
    if (r) load();
  }

  async function cancel(s: RescueSession) {
    if (!(await askConfirm(t.bmr.cancelConfirm))) return;
    if (await act(post(`/rescue/${encodeURIComponent(s.id)}/cancel`), t.bmr.cancelled)) load();
  }

  async function submitP2v(e: SubmitEvent) {
    e.preventDefault();
    if (!agent) return;
    if (!(await askConfirm(t.bmr.p2vConfirm(agent.name, p2v.node)))) return;
    const body: Record<string, unknown> = {
      time: Number(p2v.time),
      source_id: Number(p2v.source_id),
      node: p2v.node.trim(),
      storage: p2v.storage.trim(),
      iso: p2v.iso.trim(),
      bridge: p2v.bridge.trim() || 'vmbr0',
      memory: Number(p2v.memory) || 2048,
      cores: Number(p2v.cores) || 2,
    };
    if (p2v.iso_storage.trim()) body.iso_storage = p2v.iso_storage.trim();
    if (p2v.vmid !== '' && Number(p2v.vmid)) body.vmid = Number(p2v.vmid);
    if (p2v.name.trim()) body.name = p2v.name.trim();
    const r = await act(post<RescueSession & { p2v_job: number }>(`/agents/${encodeURIComponent(agent.id)}/p2v`, body), (d) =>
      t.bmr.p2vStarted(d.p2v_job),
    );
    if (r) load();
  }
</script>

{#snippet stateCell(s: RescueSession)}
  <span class="chip {stateCls[s.state] ?? 'plain'}">{t.bmr.states[s.state] ?? s.state}</span>
  {#if s.p2v}<span class="chip accent">{t.bmr.p2vChip}</span>{/if}
  {#if s.state === 'running' && s.step}<div class="muted">{t.bmr.stepNames[s.step]}</div>{/if}
  {#if s.state === 'failed' && s.message}<div class="muted">{s.message}</div>{/if}
{/snippet}

{#snippet target(s: RescueSession)}
  {#if s.host}
    <span class="mono">{s.host}:{s.port}</span>
    {#if s.disks.length}
      <div class="muted mono">{s.disks.map((d) => `${d.path} (${fmtBytes(d.size)})`).join(', ')}</div>
    {/if}
  {:else if s.state === 'issued'}
    <span class="muted">{t.bmr.waitingConsole}</span>
  {:else}—{/if}
  {#if s.p2v?.vm}<div class="muted">{t.bmr.p2vVm(s.p2v.vm.vmid, s.p2v.vm.node)}</div>{/if}
{/snippet}

{#if mayList && sessions.length}
  <section class="card" aria-labelledby="bmr-overview">
    <h2 id="bmr-overview">{t.bmr.sessions}</h2>
    <p class="hint">{t.bmr.sessionsIntro}</p>
    {#if error}<p class="banner error" role="alert">{t.bmr.loadFailed}: {error}</p>{/if}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.bmr.agent}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.state}</th>
            <th scope="col">{t.bmr.address}</th>
            <th scope="col">{t.bmr.snapshot}</th>
            <th scope="col">{t.bmr.created}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each sessions as s (s.id)}
            <tr>
              <td><strong>{agentName(s)}</strong></td>
              <td>{s.tenant}</td>
              <td>{@render stateCell(s)}</td>
              <td>{@render target(s)}</td>
              <td class="nowrap">{s.snapshot_time ? fmtTime(s.snapshot_time) : '—'}</td>
              <td class="nowrap" title={fmtTime(s.created)}>{fmtAgo(s.created, now)} <div class="muted">{s.created_by}</div></td>
              <td class="actions">
                {#if s.job_id}<a class="button small" href={href(`/jobs/${s.job_id}`)}>{t.bmr.job(s.job_id)}</a>{/if}
                {#if manage}
                  {@const a = agents.find((x) => x.id === s.agent_id)}
                  {#if a && ACTIVE.includes(s.state) && s.state !== 'running'}
                    <button type="button" class="small" onclick={() => openFor(a)}>{t.bmr.action}</button>
                  {/if}
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{/if}

<Modal bind:open title={t.bmr.title(agent?.name ?? '')} wide>
  {#if agent}
    <p class="hint">{t.bmr.intro}</p>
    {#if error}<p class="banner error" role="alert">{error}</p>{/if}

    <h3>{t.bmr.issueTitle}</h3>
    {#if token}
      <p class="banner warn" role="alert">{t.bmr.tokenOnce}</p>
      <div class="field">
        <span class="muted">{t.bmr.token}</span>
        <code class="secret">{token.token}</code>
        <button type="button" class="small" onclick={() => copyText(token!.token)}>{t.users.copy}</button>
      </div>
      <p class="muted">{t.bmr.expires}: {fmtTime(token.expires)}</p>
    {:else if manage}
      <div class="form-actions">
        <label class="inline-check"><input type="checkbox" bind:checked={reboot} /> {t.bmr.reboot}</label>
        <button type="button" class="primary" onclick={issue}>{t.bmr.issue}</button>
      </div>
    {/if}
    <ol class="bmr-steps">
      {#each t.bmr.steps as step, i (i)}<li>{step}</li>{/each}
    </ol>

    <h3>{t.bmr.sessionsTitle}</h3>
    {#if mine.length === 0}
      <p class="empty">{t.bmr.none}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.state}</th>
              <th scope="col">{t.bmr.address} / {t.bmr.disks}</th>
              <th scope="col">{t.bmr.created}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each mine as s (s.id)}
              <tr>
                <td>
                  {@render stateCell(s)}
                  {#if s.state === 'issued' || s.state === 'waiting'}
                    <div class="muted">{t.bmr.expires}: {fmtTime(s.token_expires)}</div>
                  {/if}
                </td>
                <td>
                  {@render target(s)}
                  {#if s.checked_in}<div class="muted">{t.bmr.checkedIn(fmtAgo(s.checked_in, now))}</div>{/if}
                  {#if s.snapshot_time && s.state !== 'waiting'}<div class="muted">{t.bmr.snapshot}: {fmtTime(s.snapshot_time)}</div>{/if}
                </td>
                <td class="nowrap">
                  {fmtTime(s.created)}
                  <div class="muted">{s.created_by}{s.reboot ? ` · ${t.bmr.rebootAfter}` : ''}</div>
                </td>
                <td class="actions">
                  {#if s.job_id}<a class="button small" href={href(`/jobs/${s.job_id}`)} onclick={() => (open = false)}>{t.bmr.job(s.job_id)}</a>{/if}
                  {#if manage && (s.state === 'issued' || s.state === 'waiting')}
                    <button type="button" class="small danger" onclick={() => cancel(s)}>{t.bmr.cancel}</button>
                  {/if}
                </td>
              </tr>
              {#if manage && s.state === 'waiting'}
                <tr>
                  <td colspan="4">
                    {#if snaps.length === 0}
                      <p class="empty">{t.bmr.noSnapshots}</p>
                    {:else}
                      <div class="form-grid">
                        <div class="field">
                          <label for="bmr-snap-{s.id}">{t.bmr.snapshot}</label>
                          <select id="bmr-snap-{s.id}" bind:value={pick}>
                            {#each snaps as x (x.time)}<option value={x.time}>{fmtTime(x.time)} · {fmtBytes(x.size)}</option>{/each}
                          </select>
                          {#if can.restore(session.user) && pick}
                            <a
                              class="hint"
                              href={href(
                                `/files?tenant=${encodeURIComponent(agent.tenant)}&source=${encodeURIComponent(hostSource)}&time=${pick}&path=${encodeURIComponent('/.nexus-system')}`,
                              )}
                              onclick={() => (open = false)}>{t.bmr.layout}</a
                            >
                          {/if}
                        </div>
                      </div>
                      <p class="banner warn" role="note">{t.bmr.eraseWarn}</p>
                      <div class="form-actions">
                        <button type="button" class="primary" disabled={!pick} onclick={() => start(s)}>{t.bmr.start}</button>
                      </div>
                    {/if}
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    {#if manage}
      <h3>{t.bmr.p2vTitle}</h3>
      <p class="hint">{t.bmr.p2vIntro}</p>
      {#if pves.length === 0}
        <p class="empty">{t.bmr.noPve}</p>
      {:else if snaps.length === 0}
        <p class="empty">{t.bmr.noSnapshots}</p>
      {:else}
        <form onsubmit={submitP2v}>
          <div class="form-grid">
            <div class="field">
              <label for="p2v-snap">{t.bmr.snapshot}</label>
              <select id="p2v-snap" bind:value={p2v.time} required>
                {#each snaps as x (x.time)}<option value={x.time}>{fmtTime(x.time)} · {fmtBytes(x.size)}</option>{/each}
              </select>
            </div>
            <div class="field">
              <label for="p2v-src">{t.bmr.source}</label>
              <select id="p2v-src" bind:value={p2v.source_id} required>
                {#each pves as x (x.id)}<option value={x.id}>{x.name}</option>{/each}
              </select>
            </div>
            <div class="field">
              <label for="p2v-node">{t.bmr.node}</label>
              <input id="p2v-node" class="mono" list="p2v-nodes" bind:value={p2v.node} required maxlength="128" autocomplete="off" spellcheck="false" />
              <datalist id="p2v-nodes">{#each pveNodes as n (n)}<option value={n}></option>{/each}</datalist>
            </div>
            <div class="field">
              <label for="p2v-storage">{t.bmr.storage}</label>
              <input id="p2v-storage" class="mono" bind:value={p2v.storage} required maxlength="128" autocomplete="off" spellcheck="false" />
            </div>
            <div class="field">
              <label for="p2v-iso">{t.bmr.iso}</label>
              <input
                id="p2v-iso"
                class="mono"
                bind:value={p2v.iso}
                required
                pattern={'[A-Za-z0-9._\\-]+:iso/[A-Za-z0-9._\\-]+'}
                placeholder="local:iso/nexus-rescue-0.2.0.iso"
                aria-describedby="p2v-iso-hint"
                autocomplete="off"
                spellcheck="false"
              />
              <div class="hint" id="p2v-iso-hint">{t.bmr.isoHint}</div>
            </div>
            <div class="field">
              <label for="p2v-isos">{t.bmr.isoStorage}</label>
              <input id="p2v-isos" class="mono" bind:value={p2v.iso_storage} maxlength="128" aria-describedby="p2v-isos-hint" autocomplete="off" spellcheck="false" />
              <div class="hint" id="p2v-isos-hint">{t.bmr.isoStorageHint}</div>
            </div>
            <div class="field">
              <label for="p2v-bridge">{t.bmr.bridge}</label>
              <input id="p2v-bridge" class="mono" bind:value={p2v.bridge} maxlength="128" autocomplete="off" spellcheck="false" />
            </div>
            <div class="field">
              <label for="p2v-mem">{t.bmr.memory}</label>
              <input id="p2v-mem" type="number" min="512" max="1048576" bind:value={p2v.memory} required />
            </div>
            <div class="field">
              <label for="p2v-cores">{t.bmr.cores}</label>
              <input id="p2v-cores" type="number" min="1" max="256" bind:value={p2v.cores} required />
            </div>
            <div class="field">
              <label for="p2v-vmid">{t.bmr.vmid}</label>
              <input id="p2v-vmid" type="number" min="100" max="999999999" bind:value={p2v.vmid} aria-describedby="p2v-vmid-hint" />
              <div class="hint" id="p2v-vmid-hint">{t.bmr.vmidHint}</div>
            </div>
            <div class="field">
              <label for="p2v-name">{t.bmr.vmName}</label>
              <input id="p2v-name" bind:value={p2v.name} maxlength="128" autocomplete="off" spellcheck="false" />
            </div>
          </div>
          <div class="form-actions">
            <button type="submit" class="primary">{t.bmr.p2vSubmit}</button>
          </div>
        </form>
      {/if}
    {/if}

    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<style>
  .bmr-steps {
    margin: 0.75rem 0 1rem;
    padding-left: 1.4rem;
    line-height: 1.55;
  }
  h3 {
    margin: 1.25rem 0 0.5rem;
  }
</style>
