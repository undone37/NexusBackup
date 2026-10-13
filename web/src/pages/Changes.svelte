<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { get, post, errText } from '../lib/api';
  import { route, href } from '../lib/router.svelte';
  import { terminal } from '../lib/jobs';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { session } from '../lib/session.svelte';
  import type { DiffResult, Job, Snapshot, Tenant } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  // Phase 21a: POST /snapshots/diff queues a read-only `snapshot_diff` job (the scheduler
  // compares the two sealed name indexes); one page of paths per job.
  const PAGE = 200;
  let tenants: Tenant[] = $state([]);
  let snaps: Snapshot[] = $state([]);
  let tenant = $state(session.user?.tenant ?? route.query.get('tenant') ?? '');
  let source = $state(route.query.get('source') ?? '');
  let time = $state(route.query.get('time') ?? '');
  let base = $state(route.query.get('base') ?? '');
  let change = $state('');
  let offset = $state(0);

  let busy = $state(false);
  let error: string | null = $state(null);
  let failedJob: number | null = $state(null);
  let result: DiffResult | null = $state(null);
  let ctl: AbortController | null = null;
  onDestroy(() => ctl?.abort());

  const local = $derived(snaps.filter((s) => s.tenant === tenant && s.local));
  const sources = $derived([...new Set(local.map((s) => s.source))].sort());
  const versions = $derived(local.filter((s) => s.source === source).sort((a, b) => b.time - a.time));
  const bases = $derived(versions.filter((s) => s.time < Number(time)));
  const label = (s: Snapshot) => `${fmtTime(s.time)}${s.anomalous ? ` · ${t.changes.flagged}` : ''}`;

  onMount(async () => {
    try {
      tenants = await get<Tenant[]>('/tenants');
      if (!tenant && tenants.length) tenant = tenants[0].name;
    } catch {
      /* tenant-scoped users see their own tenant only */
    }
    try {
      snaps = await get<Snapshot[]>('/snapshots');
    } catch (e) {
      error = errText(e);
    }
    if (!time && versions.length) time = String(versions[0].time);
    if (source && time) compare();
  });

  function pickSource() {
    time = versions.length ? String(versions[0].time) : '';
    base = '';
    result = null;
  }

  async function poll(id: number, signal: AbortSignal): Promise<Job | null> {
    for (;;) {
      await new Promise((r) => setTimeout(r, 700));
      if (signal.aborted) return null;
      const job = await get<Job>(`/jobs/${id}`);
      if (terminal(job.state)) return job;
    }
  }

  async function compare(e?: Event, at = 0) {
    e?.preventDefault();
    if (!tenant || !source || !time) return;
    ctl?.abort();
    const c = (ctl = new AbortController());
    busy = true;
    error = null;
    failedJob = null;
    offset = at;
    try {
      const o = await post<{ id: number }>('/snapshots/diff', {
        tenant,
        source,
        time: Number(time),
        base: base ? Number(base) : undefined,
        change: change || undefined,
        offset: at,
        limit: PAGE,
      });
      if (o.data.id === undefined) return;
      const job = await poll(o.data.id, c.signal);
      if (!job) return;
      if (job.state !== 'ok') {
        failedJob = job.id;
        error = t.changes.failed;
        result = null;
        return;
      }
      result = job.result as unknown as DiffResult;
    } catch (err) {
      error = errText(err);
    } finally {
      if (ctl === c) busy = false;
    }
  }
  const chip = (c: string) => (c === 'added' ? 'ok' : c === 'deleted' ? 'bad' : 'warn');
  const parent = (p: string) => '/' + p.split('/').slice(0, -1).join('/');
  const openHref = (p: string, at: number) =>
    href(`/files?${new URLSearchParams({ tenant, source, time: String(at), path: parent(p) })}`);
</script>

<div class="page-head">
  <h1>{t.changes.title}</h1>
  <p class="lede">{t.changes.lede}</p>
</div>

<form class="filters" onsubmit={compare}>
  {#if !session.user?.tenant}
    <div class="field">
      <label for="c-tenant">{t.changes.tenant}</label>
      <select id="c-tenant" bind:value={tenant} onchange={() => ((source = ''), pickSource())}>
        {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
      </select>
    </div>
  {/if}
  <div class="field">
    <label for="c-source">{t.changes.source}</label>
    <select id="c-source" bind:value={source} onchange={pickSource} required>
      <option value="" disabled>—</option>
      {#each sources as s (s)}<option value={s}>{s}</option>{/each}
    </select>
  </div>
  <div class="field">
    <label for="c-time">{t.changes.time}</label>
    <select id="c-time" bind:value={time} onchange={() => (base = '')} required>
      {#each versions as s (s.time)}<option value={String(s.time)}>{label(s)}</option>{/each}
    </select>
  </div>
  <div class="field">
    <label for="c-base">{t.changes.base}</label>
    <select id="c-base" bind:value={base}>
      <option value="">{t.changes.previous}</option>
      {#each bases as s (s.time)}<option value={String(s.time)}>{label(s)}</option>{/each}
    </select>
  </div>
  <div class="field">
    <label for="c-change">{t.changes.filter}</label>
    <select id="c-change" bind:value={change}>
      <option value="">{t.changes.all}</option>
      <option value="added">{t.changes.added}</option>
      <option value="changed">{t.changes.changed}</option>
      <option value="deleted">{t.changes.deleted}</option>
    </select>
  </div>
  <button type="submit" class="primary" disabled={busy || !source || !time}>{t.changes.submit}</button>
</form>

<ErrorBanner {error} />
{#if failedJob}<p><a href={href(`/jobs/${failedJob}`)}>{t.jobs.detail(failedJob)}</a></p>{/if}

{#if busy}
  <p class="muted" aria-busy="true" role="status">{t.changes.working}</p>
{:else if result && result.base === null}
  <p class="banner info">{t.changes.noBase}</p>
{:else if result && !result.indexed}
  <p class="banner info">{t.changes.unindexed}</p>
{:else if result}
  <div class="card">
    <p role="status">
      <strong>{t.changes.summary(result.added ?? 0, result.changed ?? 0, result.deleted ?? 0)}</strong>
      <span class="muted">· {fmtTime(result.base ?? 0)} → {fmtTime(result.time)}</span>
    </p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.changes.change}</th>
            <th scope="col">{t.changes.path}</th>
            <th scope="col" class="num">{t.changes.size}</th>
            <th scope="col">{t.changes.modified}</th>
          </tr>
        </thead>
        <tbody>
          {#each result.entries ?? [] as x (x.path)}
            <tr>
              <td><span class="chip {chip(x.change)}">{t.changes[x.change]}</span></td>
              <td class="mono">
                <a href={openHref(x.path, x.change === 'deleted' ? (result.base ?? 0) : result.time)}>{x.path}</a>
              </td>
              <td class="num nowrap">
                {#if x.change === 'changed' && x.old_size !== x.size}{fmtBytes(x.old_size ?? 0)} → {/if}{fmtBytes(x.size)}
              </td>
              <td class="nowrap">
                {#if x.change === 'changed' && x.old_mtime !== x.mtime}{fmtTime(x.old_mtime ?? 0)} → {/if}{fmtTime(x.mtime)}
              </td>
            </tr>
          {:else}
            <tr><td colspan="4" class="empty">{t.changes.none}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if (result.total ?? 0) > PAGE}
      <div class="form-actions">
        <span class="muted">{t.changes.range(offset + 1, Math.min(offset + PAGE, result.total ?? 0), result.total ?? 0)}</span>
        <button type="button" disabled={offset === 0} onclick={() => compare(undefined, Math.max(0, offset - PAGE))}>{t.changes.prev}</button>
        <button type="button" disabled={offset + PAGE >= (result.total ?? 0)} onclick={() => compare(undefined, offset + PAGE)}>{t.changes.next}</button>
      </div>
    {/if}
  </div>
{:else if source && !versions.length}
  <p class="empty">{t.changes.pickSource}</p>
{/if}
<p class="muted">{t.changes.privacy}</p>
