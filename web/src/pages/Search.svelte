<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { get, post, errText } from '../lib/api';
  import { route, href } from '../lib/router.svelte';
  import { runJob, downloadUrl, hostAgentId, terminal } from '../lib/jobs';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { can } from '../lib/roles';
  import { session } from '../lib/session.svelte';
  import type { Agent, Job, SearchMatch, SearchResult, Snapshot, Tenant } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import RestoreFiles from '../components/RestoreFiles.svelte';

  // Phase 15g: POST /search queues a `file_search` job (the scheduler opens the tenant's
  // sealed file indexes with the tenant key); the result comes back as `job.result`.
  let tenants: Tenant[] = $state([]);
  let snaps: Snapshot[] = $state([]);
  let agents: Agent[] = $state([]);
  let tenant = $state(session.user?.tenant ?? route.query.get('tenant') ?? '');
  let query = $state(route.query.get('q') ?? '');
  let source = $state(route.query.get('source') ?? '');
  let from = $state('');
  let to = $state('');
  let caseSensitive = $state(false);

  let busy = $state(false);
  let error: string | null = $state(null);
  let failedJob: number | null = $state(null);
  let result: SearchResult | null = $state(null);
  // chosen snapshot time per match (default: the newest one holding that version)
  let chosen: Record<string, number> = $state({});
  let ctl: AbortController | null = null;
  const page = new AbortController();
  onDestroy(() => {
    ctl?.abort();
    page.abort();
  });

  const sources = $derived([...new Set(snaps.filter((s) => s.tenant === tenant && s.local).map((s) => s.source))].sort());
  const key = (m: SearchMatch) => `${m.source}\0${m.path}\0${m.size}\0${m.mtime}`;
  const timeOf = (m: SearchMatch) => chosen[key(m)] ?? m.times[0];
  const parent = (p: string) => '/' + p.split('/').slice(0, -1).join('/');
  const openHref = (m: SearchMatch) => {
    const path = m.kind === 'dir' ? '/' + m.path : parent(m.path);
    const q = new URLSearchParams({ tenant, source: m.source, time: String(timeOf(m)), path });
    return href(`/files?${q}`);
  };
  // unix seconds of a date input (start of the day, or the end of it for "until")
  const day = (d: string, end: boolean) => (d ? Math.floor(new Date(`${d}T00:00:00`).getTime() / 1000) + (end ? 86399 : 0) : undefined);

  onMount(async () => {
    try {
      tenants = await get<Tenant[]>('/tenants');
      if (!tenant && tenants.length) tenant = tenants[0].name;
    } catch {
      /* tenant-scoped users see their own tenant only */
    }
    get<Snapshot[]>('/snapshots')
      .then((xs) => (snaps = xs))
      .catch(() => {
        /* the guest filter then stays empty */
      });
    get<Agent[]>('/agents')
      .then((xs) => (agents = xs))
      .catch(() => {
        /* restores to a host then have no agents to offer */
      });
    if (query && tenant) search();
  });

  async function poll(id: number, signal: AbortSignal): Promise<Job | null> {
    for (;;) {
      await new Promise((r) => setTimeout(r, 700));
      if (signal.aborted) return null;
      const job = await get<Job>(`/jobs/${id}`);
      if (terminal(job.state)) return job;
    }
  }

  async function search(e?: Event) {
    e?.preventDefault();
    if (!query.trim() || !tenant) return;
    ctl?.abort();
    const c = (ctl = new AbortController());
    busy = true;
    error = null;
    failedJob = null;
    result = null;
    chosen = {};
    ready = null;
    try {
      const o = await post<{ id: number }>('/search', {
        tenant,
        query: query.trim(),
        source: source || undefined,
        from: day(from, false),
        to: day(to, true),
        case_sensitive: caseSensitive,
      });
      if (o.data.id === undefined) return;
      const job = await poll(o.data.id, c.signal);
      if (!job) return;
      if (job.state !== 'ok') {
        failedJob = job.id;
        error = t.search.failed;
        return;
      }
      result = job.result as unknown as SearchResult;
    } catch (err) {
      error = errText(err);
    } finally {
      if (ctl === c) busy = false;
    }
  }

  function stop() {
    ctl?.abort();
    busy = false;
  }

  // Download of one file (files_get, tar), like the Files page.
  let preparing: string | null = $state(null);
  let ready: { key: string; token: string; filename: string } | null = $state(null);
  async function download(m: SearchMatch) {
    const k = key(m);
    preparing = k;
    ready = null;
    error = null;
    try {
      const time = timeOf(m);
      const r = await runJob('files_get', tenant, { source: m.source, time, paths: ['/' + m.path], format: 'tar' }, page.signal);
      if (!r) return;
      if (r.job.state !== 'ok') {
        failedJob = r.job.id;
        error = t.files.failed;
        return;
      }
      if (r.token) ready = { key: k, token: r.token, filename: `${m.source}-${time}.tar` };
    } catch (err) {
      error = errText(err);
    } finally {
      preparing = null;
    }
  }

  let restoreOpen = $state(false);
  let restoreOf: { source: string; time: number; path: string } | null = $state(null);
  function restore(m: SearchMatch) {
    restoreOf = { source: m.source, time: timeOf(m), path: '/' + m.path };
    restoreOpen = true;
  }
</script>

<div class="page-head">
  <h1>{t.search.title}</h1>
  <a class="button" href={href('/snapshots')}>{t.snap.title}</a>
  <p class="lede">{t.search.lede}</p>
</div>

<form class="filters" onsubmit={search} role="search">
  {#if !session.user?.tenant}
    <div class="field">
      <label for="s-tenant">{t.search.tenant}</label>
      <select id="s-tenant" bind:value={tenant} onchange={() => (source = '')}>
        {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
      </select>
    </div>
  {/if}
  <div class="field">
    <label for="s-query">{t.search.query}</label>
    <input id="s-query" class="mono" bind:value={query} maxlength="256" autocomplete="off" aria-describedby="s-hint" required />
  </div>
  <div class="field">
    <label for="s-source">{t.search.source}</label>
    <select id="s-source" bind:value={source}>
      <option value="">{t.search.anySource}</option>
      {#each sources as s (s)}<option value={s}>{s}</option>{/each}
    </select>
  </div>
  <div class="field">
    <label for="s-from">{t.search.from}</label>
    <input id="s-from" type="date" bind:value={from} />
  </div>
  <div class="field">
    <label for="s-to">{t.search.to}</label>
    <input id="s-to" type="date" bind:value={to} />
  </div>
  <label class="inline-check"><input type="checkbox" bind:checked={caseSensitive} />{t.search.caseSensitive}</label>
  {#if busy}
    <button type="button" onclick={stop}>{t.search.cancel}</button>
  {:else}
    <button type="submit" class="primary" disabled={!query.trim() || !tenant}>{t.search.submit}</button>
  {/if}
</form>
<p class="muted" id="s-hint">{t.search.queryHint}</p>

<ErrorBanner {error} />
{#if failedJob}<p><a href={href(`/jobs/${failedJob}`)}>{t.jobs.detail(failedJob)}</a></p>{/if}

{#if busy}
  <p class="muted" aria-busy="true" role="status">{t.search.searching}</p>
{:else if result}
  {#if result.truncated}<p class="banner warn">{t.search.truncated}</p>{/if}
  {#if result.unindexed > 0}<p class="banner info">{t.search.unindexed(result.unindexed)}</p>{/if}
  <div class="card">
    <p class="muted" role="status">{t.search.summary(result.matches.length, result.scanned, result.elapsed_ms)}</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.search.path}</th>
            <th scope="col" class="num">{t.search.size}</th>
            <th scope="col">{t.search.modified}</th>
            <th scope="col">{t.snap.source}</th>
            <th scope="col">{t.search.snapshots}</th>
            <th scope="col"><span class="visually-hidden">{t.search.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each result.matches as m (key(m))}
            {@const k = key(m)}
            <tr>
              <td class="mono">{m.path}{m.kind === 'dir' ? '/' : ''}</td>
              <td class="num">{m.kind === 'file' ? fmtBytes(m.size) : ''}</td>
              <td class="nowrap">{fmtTime(m.mtime)}</td>
              <td class="mono">{m.source}</td>
              <td>
                {#if m.times.length > 1}
                  <select
                    class="auto"
                    aria-label={t.search.version(m.path)}
                    value={timeOf(m)}
                    onchange={(ev) => (chosen[k] = Number(ev.currentTarget.value))}
                  >
                    {#each m.times as tm (tm)}<option value={tm}>{fmtTime(tm)}</option>{/each}
                  </select>
                  <span class="muted">{t.search.inSnapshots(m.times.length)}</span>
                {:else}
                  <span class="nowrap">{fmtTime(m.times[0])}</span>
                {/if}
              </td>
              <td>
                <div class="row">
                  <a class="button" href={openHref(m)}>{t.search.open}</a>
                  {#if m.kind === 'file' && can.download(session.user)}
                    {#if ready?.key === k}
                      <a class="button" href={downloadUrl(ready.token)} download={ready.filename}>{t.files.get} {ready.filename}</a>
                    {:else}
                      <button type="button" disabled={preparing !== null} onclick={() => download(m)}>
                        {preparing === k ? t.search.preparing : t.search.download}
                      </button>
                    {/if}
                  {/if}
                  {#if hostAgentId(m.source)}
                    <button type="button" onclick={() => restore(m)}>{t.search.restore}</button>
                  {/if}
                </div>
              </td>
            </tr>
          {:else}
            <tr><td colspan="6" class="empty">{t.search.none}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/if}
<p class="muted">{t.search.privacy}</p>

{#if restoreOf}
  <RestoreFiles
    bind:open={restoreOpen}
    {tenant}
    source={restoreOf.source}
    time={restoreOf.time}
    paths={[restoreOf.path]}
    {agents}
  />
{/if}
