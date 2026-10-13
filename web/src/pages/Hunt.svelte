<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { get, post, errText, qs } from '../lib/api';
  import { route, href, navigate } from '../lib/router.svelte';
  import { terminal } from '../lib/jobs';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { can } from '../lib/roles';
  import { session } from '../lib/session.svelte';
  import type { Agent, HashList, HuntMatch, HuntResult, Job, Snapshot, Tenant } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import RestoreFiles from '../components/RestoreFiles.svelte';
  import HoldDialog from '../components/HoldDialog.svelte';
  import IconHunt from '@lucide/svelte/icons/fingerprint';

  // Phase 28: POST /hunts queues a `hash_hunt` job; the scheduler compares the SHA-256 in the
  // tenant's sealed file indexes with the IOC lists; the result comes back as `job.result`.
  let tenants: Tenant[] = $state([]);
  let snaps: Snapshot[] = $state([]);
  let agents: Agent[] = $state([]);
  let lists: HashList[] | null = $state(null);
  let hunts: Job[] = $state([]);
  let tenant = $state(session.user?.tenant ?? route.query.get('tenant') ?? '');
  let picked: string[] = $state([]);
  let source = $state('');
  let from = $state('');
  let to = $state('');

  let busy = $state(false);
  let error: string | null = $state(null);
  let failedJob: number | null = $state(null);
  let shownJob = $state<Job | null>(null);
  const result = $derived((shownJob?.result as unknown as HuntResult | null) ?? null);
  let chosen: Record<string, number> = $state({});
  let ctl: AbortController | null = null;
  onDestroy(() => ctl?.abort());

  const sources = $derived([...new Set(snaps.filter((s) => s.tenant === tenant && s.local).map((s) => s.source))].sort());
  const key = (m: HuntMatch) => `${m.source}\0${m.path}\0${m.sha256}`;
  const timeOf = (m: HuntMatch) => chosen[key(m)] ?? m.times[0];
  const parent = (p: string) => '/' + p.split('/').slice(0, -1).join('/');
  const tree = (src: string) => /^(host|share|nas|plugin)-/.test(src);
  const day = (d: string, end: boolean) => (d ? Math.floor(new Date(`${d}T00:00:00`).getTime() / 1000) + (end ? 86399 : 0) : undefined);
  const hits = (j: Job) => ((j.result as unknown as HuntResult | null)?.matches?.length ?? null);

  async function loadHunts() {
    try {
      hunts = await get<Job[]>('/jobs' + qs({ kind: 'hash_hunt', limit: 20 }));
    } catch {
      hunts = [];
    }
  }

  onMount(async () => {
    try {
      tenants = await get<Tenant[]>('/tenants');
      if (!tenant && tenants.length) tenant = tenants[0].name;
    } catch {
      /* tenant-scoped accounts: their own tenant */
    }
    get<Snapshot[]>('/snapshots')
      .then((xs) => (snaps = xs))
      .catch(() => {});
    get<Agent[]>('/agents')
      .then((xs) => (agents = xs))
      .catch(() => {});
    // the lists themselves are for admins and security officers; others hunt with all of them
    if (can.hashLists(session.user))
      get<HashList[]>('/hash-lists')
        .then((xs) => (lists = xs))
        .catch(() => (lists = null));
    await loadHunts();
    const id = Number(route.query.get('job'));
    if (id) show(id);
  });

  async function show(id: number) {
    try {
      shownJob = await get<Job>(`/jobs/${id}`);
      chosen = {};
    } catch (e) {
      error = errText(e);
    }
  }

  async function poll(id: number, signal: AbortSignal): Promise<Job | null> {
    for (;;) {
      await new Promise((r) => setTimeout(r, 700));
      if (signal.aborted) return null;
      const job = await get<Job>(`/jobs/${id}`);
      if (terminal(job.state)) return job;
    }
  }

  async function start(e: SubmitEvent) {
    e.preventDefault();
    if (!tenant) return;
    ctl?.abort();
    const c = (ctl = new AbortController());
    busy = true;
    error = null;
    failedJob = null;
    shownJob = null;
    try {
      const o = await post<{ id: number }>('/hunts', {
        tenant,
        lists: picked.length ? picked : undefined,
        source: source || undefined,
        from: day(from, false),
        to: day(to, true),
      });
      if (o.data.id === undefined) return;
      const job = await poll(o.data.id, c.signal);
      if (!job) return;
      await loadHunts();
      if (job.state !== 'ok') {
        failedJob = job.id;
        error = t.threat.failed;
        return;
      }
      shownJob = job;
      chosen = {};
    } catch (err) {
      error = errText(err);
    } finally {
      if (ctl === c) busy = false;
    }
  }

  let restoreOpen = $state(false);
  let restoreOf: { source: string; time: number; path: string } | null = $state(null);
  function restore(m: HuntMatch) {
    restoreOf = { source: m.source, time: timeOf(m), path: '/' + m.path };
    restoreOpen = true;
  }
  let holdOpen = $state(false);
  let holdOf: { tenant: string; source: string; time: number; path: string } | null = $state(null);
  function hold(m: HuntMatch) {
    holdOf = { tenant: shownJob?.tenant ?? tenant, source: m.source, time: timeOf(m), path: m.path };
    holdOpen = true;
  }
  const openHref = (m: HuntMatch) =>
    href('/files' + qs({ tenant: shownJob?.tenant ?? tenant, source: m.source, time: timeOf(m), path: parent(m.path) }));
</script>

<div class="page-head">
  <h1>{t.threat.huntTitle}</h1>
  <p class="lede">{t.threat.huntLede}</p>
</div>

{#if lists && !lists.length}<p class="banner info">{t.threat.noListsHint}</p>{/if}

<form class="filters" onsubmit={start} aria-label={t.threat.huntTitle}>
  {#if !session.user?.tenant}
    <div class="field">
      <label for="h-tenant">{t.threat.tenant}</label>
      <select id="h-tenant" bind:value={tenant} onchange={() => (source = '')}>
        {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
      </select>
    </div>
  {/if}
  {#if lists?.length}
    <fieldset class="field">
      <legend>{t.threat.lists}</legend>
      {#each lists as l (l.name)}
        <label class="inline-check mono"><input type="checkbox" value={l.name} bind:group={picked} />{l.name}</label>
      {/each}
      <p class="hint">{picked.length ? '' : t.threat.allLists}</p>
    </fieldset>
  {/if}
  <div class="field">
    <label for="h-source">{t.threat.source}</label>
    <select id="h-source" bind:value={source}>
      <option value="">{t.threat.anySource}</option>
      {#each sources as s (s)}<option value={s}>{s}</option>{/each}
    </select>
  </div>
  <div class="field">
    <label for="h-from">{t.threat.from}</label>
    <input id="h-from" type="date" bind:value={from} />
  </div>
  <div class="field">
    <label for="h-to">{t.threat.to}</label>
    <input id="h-to" type="date" bind:value={to} />
  </div>
  <button type="submit" class="primary" disabled={busy || !tenant}><IconHunt aria-hidden="true" />{t.threat.start}</button>
</form>

<ErrorBanner {error} />
{#if failedJob}<p><a href={href(`/jobs/${failedJob}`)}>{t.jobs.detail(failedJob)}</a></p>{/if}

{#if busy}
  <p class="muted" aria-busy="true" role="status">{t.threat.running}</p>
{:else if shownJob && result}
  <h2>{t.threat.showing(shownJob.id)}</h2>
  {#if result.truncated}<p class="banner warn">{t.threat.truncated}</p>{/if}
  {#if result.unhashed > 0}<p class="banner info">{t.threat.unhashed(result.unhashed)}</p>{/if}
  <div class="card">
    <p class="muted" role="status">{t.threat.summary(result.matches.length, result.scanned, result.elapsed_ms)}</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.threat.path}</th>
            <th scope="col" class="num">{t.threat.size}</th>
            <th scope="col">{t.threat.sha256}</th>
            <th scope="col">{t.threat.onLists}</th>
            <th scope="col">{t.snap.source}</th>
            <th scope="col">{t.threat.snapshots}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each result.matches as m (key(m))}
            {@const k = key(m)}
            <tr>
              <td class="mono">{m.path}</td>
              <td class="num">{fmtBytes(m.size)}</td>
              <td class="mono" title={m.sha256}>{m.sha256.slice(0, 16)}…</td>
              <td>{m.lists.join(', ')}</td>
              <td class="mono">{m.source}</td>
              <td>
                {#if m.times.length > 1}
                  <select class="auto" aria-label={t.threat.version(m.path)} value={timeOf(m)} onchange={(ev) => (chosen[k] = Number(ev.currentTarget.value))}>
                    {#each m.times as tm (tm)}<option value={tm}>{fmtTime(tm)}</option>{/each}
                  </select>
                  <span class="muted">{t.threat.inSnapshots(m.times.length)}</span>
                {:else}
                  <span class="nowrap">{fmtTime(m.times[0])}</span>
                {/if}
              </td>
              <td>
                <div class="row">
                  {#if can.restore(session.user)}<a class="button small" href={openHref(m)}>{t.threat.open}</a>{/if}
                  {#if can.restore(session.user) && tree(m.source)}
                    <button type="button" class="small" onclick={() => restore(m)}>{t.threat.restore}</button>
                  {/if}
                  {#if can.hold(session.user)}
                    <button type="button" class="small" onclick={() => hold(m)}>{t.threat.hold}</button>
                  {/if}
                </div>
              </td>
            </tr>
          {:else}
            <tr><td colspan="7" class="empty">{t.threat.none}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/if}

<section class="card" aria-labelledby="h-recent">
  <h2 id="h-recent">{t.threat.recent}</h2>
  {#if !hunts.length}
    <p class="muted">{t.threat.noHunts}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.time}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.state}</th>
            <th scope="col">{t.threat.lists}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each hunts as j (j.id)}
            {@const n = hits(j)}
            <tr>
              <td class="nowrap"><a href={href(`/jobs/${j.id}`)}>{fmtTime(j.created)}</a></td>
              <td>{j.tenant}</td>
              <td>
                {#if j.state === 'ok' && n !== null}<span class="chip {n ? 'bad' : 'ok'}">{n ? t.threat.hits(n) : t.threat.clean}</span>
                {:else}<span class="chip plain">{t.jobs.states?.[j.state] ?? j.state}</span>{/if}
              </td>
              <td>{Array.isArray(j.params.lists) ? (j.params.lists as string[]).join(', ') : t.threat.allLists}</td>
              <td>
                {#if j.state === 'ok'}
                  <button type="button" class="small" onclick={() => navigate('/hunt' + qs({ job: j.id }))}>{t.threat.show}</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

{#if restoreOf}
  <RestoreFiles bind:open={restoreOpen} tenant={shownJob?.tenant ?? tenant} source={restoreOf.source} time={restoreOf.time} paths={[restoreOf.path]} {agents} />
{/if}
{#if holdOf}
  <HoldDialog bind:open={holdOpen} target={holdOf} reason={t.threat.holdReason(holdOf.path)} ondone={() => (holdOpen = false)} />
{/if}
