<script lang="ts">
  import { jobLink } from '../lib/jobs';
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { fmtAgo, fmtDuration, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { can } from '../lib/roles';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { checkSummary, checksForm, stateChip, toChecks, type ChecksForm } from '../lib/rtest';
  import type { RecoveryPlan, RecoveryRun, Snapshot, Source, Tenant } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import Modal from '../components/Modal.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconPlay from '@lucide/svelte/icons/play';
  import IconCheck from '@lucide/svelte/icons/list-checks';
  import IconSiren from '@lucide/svelte/icons/siren';
  import IconDownload from '@lucide/svelte/icons/download';
  import IconUp from '@lucide/svelte/icons/arrow-up';
  import IconDown from '@lucide/svelte/icons/arrow-down';
  import IconX from '@lucide/svelte/icons/x';

  // Phase 25: recovery plans (GET/POST/PUT/DELETE /recovery-plans), readiness, test runs,
  // execution through approval, runs with their DR report.
  let plans: RecoveryPlan[] = $state([]);
  let sources: Source[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let snaps: Snapshot[] = $state([]);
  let loaded = $state(false);
  let error: string | null = $state(null);

  const writer = $derived(can.manageTenant(session.user));
  const runner = $derived(can.backup(session.user));
  const pveSources = $derived(sources.filter((s) => s.kind === 'pve'));

  async function load() {
    try {
      plans = await get<RecoveryPlan[]>('/recovery-plans');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(() => {
    load();
    get<Source[]>('/sources').then((s) => (sources = s)).catch(() => {});
    get<Tenant[]>('/tenants').then((x) => (tenants = x)).catch(() => {});
    get<Snapshot[]>('/snapshots').then((x) => (snaps = x)).catch(() => {});
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  });

  // ---- editor
  interface StepForm {
    source: string;
    wave: number;
    delay: number;
    target: string;
    checks: ChecksForm;
  }
  let open = $state(false);
  let editing: RecoveryPlan | null = $state(null);
  let f = $state({ tenant: '', name: '', source_id: 0, node: '', storage: 'local-lvm', test_bridge: '', rpo_hours: 24, network: '', steps: [] as StepForm[] });
  const guestSources = $derived(
    [...new Set(snaps.filter((s) => s.local && (!f.tenant || s.tenant === f.tenant) && /^(vm|ct)-\d+$/.test(s.source)).map((s) => s.source))].sort(),
  );
  const nodes = $derived(
    Object.keys(((sources.find((s) => s.id === Number(f.source_id))?.config as Record<string, unknown> | undefined)?.nodes as object) ?? {}),
  );
  function edit(p: RecoveryPlan | null) {
    editing = p;
    const tenant = p?.tenant ?? session.user?.tenant ?? tenants[0]?.name ?? '';
    f = {
      tenant,
      name: p?.name ?? '',
      source_id: p?.source_id ?? pveSources.find((s) => s.tenant === tenant)?.id ?? 0,
      node: p?.node ?? '',
      storage: p?.storage ?? 'local-lvm',
      test_bridge: p?.test_bridge ?? '',
      rpo_hours: p?.rpo_hours ?? 24,
      network: Object.entries(p?.network_map ?? {})
        .map(([a, b]) => `${a} = ${b}`)
        .join('\n'),
      steps: (p?.steps ?? []).map((s) => ({ source: s.source, wave: s.wave, delay: s.delay ?? 0, target: s.target ? String(s.target) : '', checks: checksForm(s.checks) })),
    };
    if (!f.steps.length) addStep();
    open = true;
  }
  function addStep() {
    const last = f.steps.at(-1);
    f.steps.push({ source: '', wave: last?.wave ?? 1, delay: 0, target: '', checks: checksForm(null) });
  }
  function move(i: number, d: number) {
    const s = f.steps;
    [s[i], s[i + d]] = [s[i + d], s[i]];
  }
  async function save(e: Event) {
    e.preventDefault();
    const network_map: Record<string, string> = {};
    for (const line of f.network.split('\n')) {
      const [a, b] = line.split('=').map((x) => x.trim());
      if (a && b) network_map[a] = b;
    }
    const body = {
      tenant: f.tenant,
      name: f.name,
      source_id: Number(f.source_id),
      node: f.node,
      storage: f.storage,
      test_bridge: f.test_bridge.trim() || null,
      network_map,
      rpo_hours: Number(f.rpo_hours),
      steps: f.steps.map((s) => ({
        source: s.source.trim(),
        wave: Number(s.wave),
        delay: Number(s.delay) || 0,
        checks: toChecks(s.checks, s.source.startsWith('ct-')),
        ...(String(s.target).trim() ? { target: Number(s.target) } : {}),
      })),
    };
    const o = await act(editing ? put(`/recovery-plans/${editing.id}`, body) : post('/recovery-plans', body), editing ? t.saved : t.created);
    if (o) {
      open = false;
      load();
    }
  }
  async function remove(p: RecoveryPlan) {
    if (!(await askConfirm(t.rplan.deletePlan(p.name)))) return;
    if (await act(del(`/recovery-plans/${p.id}`), t.deleted)) load();
  }

  // ---- actions
  async function checkNow(p: RecoveryPlan) {
    if (await act(post(`/recovery-plans/${p.id}/readiness`), t.rplan.checkQueued, jobLink)) setTimeout(load, 4000);
  }
  async function testRun(p: RecoveryPlan) {
    if (await act(post<{ run_id: number }>(`/recovery-plans/${p.id}/test`), (d) => t.rplan.testStarted(d.run_id))) load();
  }
  let exOpen = $state(false);
  let exPlan: RecoveryPlan | null = $state(null);
  let exConfirm = $state('');
  function openExecute(p: RecoveryPlan) {
    exPlan = p;
    exConfirm = '';
    exOpen = true;
  }
  async function execute(e: Event) {
    e.preventDefault();
    if (!exPlan) return;
    if (await act(post(`/recovery-plans/${exPlan.id}/execute`, { confirm: exConfirm }), t.rplan.executeRequested)) exOpen = false;
  }

  // ---- runs
  let runsOpen = $state(false);
  let runsPlan: RecoveryPlan | null = $state(null);
  let runs: RecoveryRun[] = $state([]);
  async function showRuns(p: RecoveryPlan) {
    runsPlan = p;
    runs = [];
    runsOpen = true;
    try {
      runs = await get<RecoveryRun[]>(`/recovery-plans/${p.id}/runs`);
    } catch (e) {
      error = errText(e);
    }
  }
  const waves = (p: RecoveryPlan) => new Set(p.steps.map((s) => s.wave)).size;
</script>

<div class="page-head">
  <h1>{t.rplan.title}</h1>
  {#if writer}<button type="button" class="primary" onclick={() => edit(null)}><IconPlus aria-hidden="true" />{t.rplan.new}</button>{/if}
  <p class="lede">{t.rplan.lede}</p>
</div>
<ErrorBanner {error} />

{#if !loaded}
  <p class="muted" aria-busy="true">{t.loading}</p>
{:else if plans.length === 0}
  <div class="card"><p class="empty">{t.rplan.noPlans}</p></div>
{:else}
  {#each plans as p (p.id)}
    {@const r = p.readiness}
    <section class="card plan" aria-labelledby="rp-{p.id}">
      <div class="card-head">
        <div>
          <h2 id="rp-{p.id}">{p.name}</h2>
          <div class="sub">
            {#if !session.user?.tenant}{p.tenant}&nbsp;·&nbsp;{/if}{t.rplan.guests(p.steps.length)}, {t.rplan.waves(waves(p))} · {p.node} / {p.storage} · RPO {p.rpo_hours} h
          </div>
        </div>
        <div class="row">
          {#if runner}
            <button type="button" class="small" onclick={() => checkNow(p)}><IconCheck aria-hidden="true" />{t.rplan.checkNow}</button>
            <button type="button" class="small" onclick={() => testRun(p)} disabled={p.last_run?.state === 'running'}><IconPlay aria-hidden="true" />{t.rplan.testRun}</button>
            <button type="button" class="small danger" onclick={() => openExecute(p)}><IconSiren aria-hidden="true" />{t.rplan.execute}</button>
          {/if}
          <button type="button" class="small" onclick={() => showRuns(p)}>{t.rplan.runs}</button>
          {#if writer}
            <button type="button" class="small" onclick={() => edit(p)}>{t.edit}</button>
            <button type="button" class="small danger" onclick={() => remove(p)}>{t.delete}</button>
          {/if}
        </div>
      </div>
      <div class="plan-grid">
        <div>
          <h3>{t.rplan.readiness}</h3>
          {#if !r}
            <span class="chip plain">{t.rplan.unchecked}</span>
          {:else}
            <span class="chip {r.ok ? 'ok' : 'bad'}">{r.ok ? t.rplan.ready : t.rplan.notReady}</span>
            <span class="muted small" title={fmtTime(r.at)}>{t.rplan.checkedAt(fmtAgo(r.at))}</span>
            <ul class="checks">
              {#each r.checks as c (c.name)}<li class:bad-text={!c.ok}>{c.ok ? '✓' : '✗'} <strong>{c.name}</strong>: {c.detail}</li>{/each}
            </ul>
          {/if}
        </div>
        <div>
          <h3>{t.rplan.steps}</h3>
          <ol class="plan-steps">
            {#each p.steps as s (s.source)}
              <li><span class="chip plain">{t.rplan.wave} {s.wave}</span> <span class="mono">{s.source}</span>{#if s.delay}<span class="muted small"> +{s.delay} s</span>{/if}
                {#if s.checks?.ports?.length || s.checks?.command?.length}<span class="muted small mono"> {[...(s.checks?.ports ?? []).map((x) => `tcp/${x}`), ...(s.checks?.command?.length ? ['command'] : [])].join(' ')}</span>{/if}</li>
            {/each}
          </ol>
          <h3>{t.rplan.lastRun}</h3>
          {#if p.last_run}
            <span class="chip {stateChip(p.last_run.state)}">{t.rplan.runStates[p.last_run.state] ?? p.last_run.state}</span>
            {t.rplan.mode[p.last_run.mode]} · <span title={fmtTime(p.last_run.started)}>{fmtAgo(p.last_run.started)}</span>
            {#if p.last_run.finished}<a href="/api/v1/recovery-runs/{p.last_run.id}/report" download><IconDownload aria-hidden="true" class="inline-icon" />{t.rplan.report}</a>{/if}
          {:else}
            <span class="muted">{t.rplan.noRuns}</span>
          {/if}
        </div>
      </div>
    </section>
  {/each}
{/if}

<Modal bind:open wide title={editing ? t.rplan.edit(editing.name) : t.rplan.new}>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="rp-name">{t.name}</label>
        <input id="rp-name" required bind:value={f.name} />
      </div>
      {#if !session.user?.tenant}
        <div class="field">
          <label for="rp-tenant">{t.tenant}</label>
          <select id="rp-tenant" bind:value={f.tenant} disabled={!!editing}>
            {#each tenants as x (x.name)}<option value={x.name}>{x.name}</option>{/each}
          </select>
        </div>
      {/if}
      <div class="field">
        <label for="rp-source">{t.rplan.source}</label>
        <select id="rp-source" required bind:value={f.source_id}>
          {#each pveSources.filter((s) => !f.tenant || s.tenant === f.tenant) as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="rp-node">{t.rplan.node}</label>
        <input id="rp-node" required bind:value={f.node} list="rp-nodes" />
        <datalist id="rp-nodes">{#each nodes as n (n)}<option value={n}></option>{/each}</datalist>
      </div>
      <div class="field">
        <label for="rp-storage">{t.rplan.storage}</label>
        <input id="rp-storage" required bind:value={f.storage} />
      </div>
      <div class="field">
        <label for="rp-rpo">{t.rplan.rpo}</label>
        <input id="rp-rpo" type="number" min="1" max="8760" required bind:value={f.rpo_hours} aria-describedby="rp-rpo-hint" />
        <div class="hint" id="rp-rpo-hint">{t.rplan.rpoHint}</div>
      </div>
      <div class="field">
        <label for="rp-bridge">{t.rplan.testBridge}</label>
        <input id="rp-bridge" bind:value={f.test_bridge} placeholder={t.rtest.linksDown} aria-describedby="rp-bridge-hint" />
        <div class="hint" id="rp-bridge-hint">{t.rplan.testBridgeHint}</div>
      </div>
    </div>
    <div class="field">
        <label for="rp-net">{t.rplan.networkMap}</label>
        <textarea id="rp-net" class="mono" rows="3" bind:value={f.network} spellcheck="false" placeholder="vmbr0 = vmbr20" aria-describedby="rp-net-hint"></textarea>
        <div class="hint" id="rp-net-hint">{t.rplan.networkMapHint}</div>
      </div>
    <fieldset>
      <legend>{t.rplan.steps}</legend>
      <p class="hint">{t.rplan.stepsHint}</p>
      <datalist id="rp-guests">{#each guestSources as g (g)}<option value={g}></option>{/each}</datalist>
      <div class="table-wrap">
        <table class="steps-edit">
          <thead>
            <tr>
              <th scope="col">{t.rtest.guest}</th>
              <th scope="col">{t.rplan.wave}</th>
              <th scope="col">{t.rplan.delay}</th>
              <th scope="col">{t.rtest.ports}</th>
              <th scope="col">{t.rtest.command}</th>
              <th scope="col" title={t.rplan.targetHint}>{t.rplan.target}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each f.steps as s, i (i)}
              {@const ct = s.source.startsWith('ct-')}
              <tr>
                <td><input aria-label={t.rtest.guest} required list="rp-guests" class="mono" bind:value={s.source} placeholder="vm-100" /></td>
                <td><input aria-label={t.rplan.wave} type="number" min="1" max="20" required bind:value={s.wave} /></td>
                <td><input aria-label={t.rplan.delay} type="number" min="0" max="3600" bind:value={s.delay} /></td>
                <td><input aria-label={t.rtest.ports} bind:value={s.checks.ports} disabled={ct} placeholder="443" /></td>
                <td><input aria-label={t.rtest.command} class="mono" bind:value={s.checks.command} disabled={ct} spellcheck="false" /></td>
                <td><input aria-label={t.rplan.target} type="number" min="100" bind:value={s.target} placeholder={s.source.slice(3)} /></td>
                <td class="actions nowrap">
                  <button type="button" class="icon" aria-label={t.rplan.up} disabled={i === 0} onclick={() => move(i, -1)}><IconUp aria-hidden="true" /></button>
                  <button type="button" class="icon" aria-label={t.rplan.down} disabled={i === f.steps.length - 1} onclick={() => move(i, 1)}><IconDown aria-hidden="true" /></button>
                  <button type="button" class="icon" aria-label={t.rplan.remove} onclick={() => f.steps.splice(i, 1)}><IconX aria-hidden="true" /></button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <button type="button" class="small" onclick={addStep}><IconPlus aria-hidden="true" />{t.rplan.addStep}</button>
      <p class="hint">{t.rtest.ctHint} {t.rplan.targetHint}</p>
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={exOpen} title={exPlan ? t.rplan.executeTitle(exPlan.name) : ''}>
  {#if exPlan}
    <form onsubmit={execute}>
      <p class="banner warn">{t.rplan.executeWarn}</p>
      <div class="field">
        <label for="rp-confirm">{t.rplan.executeConfirm(exPlan.name)}</label>
        <input id="rp-confirm" required bind:value={exConfirm} autocomplete="off" />
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (exOpen = false)}>{t.cancel}</button>
        <button type="submit" class="danger" disabled={exConfirm !== exPlan.name}><IconSiren aria-hidden="true" />{t.rplan.executeRequest}</button>
      </div>
    </form>
  {/if}
</Modal>

<Modal bind:open={runsOpen} wide title={runsPlan ? `${t.rplan.runs}: ${runsPlan.name}` : t.rplan.runs}>
  {#if runs.length === 0}
    <p class="empty">{t.rplan.noRuns}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">#</th>
            <th scope="col">{t.kind}</th>
            <th scope="col">{t.state}</th>
            <th scope="col">{t.rplan.requestedBy}</th>
            <th scope="col">{t.time}</th>
            <th scope="col">{t.rtest.results}</th>
            <th scope="col"><span class="visually-hidden">{t.rplan.report}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each runs as x (x.id)}
            <tr>
              <td>{#if x.job_id}<a href={href(`/jobs/${x.job_id}`)}>{x.id}</a>{:else}{x.id}{/if}</td>
              <td>{t.rplan.mode[x.mode]}</td>
              <td><span class="chip {stateChip(x.state)}">{t.rplan.runStates[x.state] ?? x.state}</span></td>
              <td>{x.requested_by}</td>
              <td class="nowrap">{fmtTime(x.started)}{#if x.finished}<span class="muted small"> ({fmtDuration(x.finished - x.started)})</span>{/if}</td>
              <td>
                {#each x.results as g, gi (gi)}
                  <div class="small">
                    {#if g.state}<span class="chip {stateChip(g.state)}">{t.rtest.states[g.state] ?? g.state}</span>{/if}
                    <span class="mono">{g.source ?? ''}</span> <span class="muted mono">{checkSummary(g.checks)}</span>
                    {#if g.error}<span class="bad-text">{g.error}</span>{/if}
                  </div>
                {/each}
              </td>
              <td>{#if x.finished}<a class="button small" href="/api/v1/recovery-runs/{x.id}/report" download><IconDownload aria-hidden="true" />{t.rplan.report}</a>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</Modal>

<style>
  .plan-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(22rem, 1fr));
    gap: 1rem 2rem;
  }
  h3 {
    font-size: 0.9rem;
    margin: 0.5rem 0 0.35rem;
  }
  .checks,
  .plan-steps {
    margin: 0.4rem 0 0.6rem;
    padding-left: 1.2rem;
    font-size: 0.88rem;
  }
  .checks {
    list-style: none;
    padding-left: 0;
  }
  .bad-text {
    color: var(--bad);
  }
  .steps-edit input {
    min-width: 4rem;
  }
  .steps-edit input[type='number'] {
    max-width: 5.5rem;
  }
  .steps-edit td:first-child input {
    min-width: 7.5rem;
  }
  :global(.inline-icon) {
    width: 1em;
    height: 1em;
    vertical-align: -0.15em;
  }
</style>
