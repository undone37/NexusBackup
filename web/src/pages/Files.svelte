<script lang="ts">
  import { onDestroy } from 'svelte';
  import { get, errText } from '../lib/api';
  import { route, href } from '../lib/router.svelte';
  import { runJob, downloadUrl, fileEntries, hostAgentId } from '../lib/jobs';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Agent, FileEntry, Job } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import RestoreFiles from '../components/RestoreFiles.svelte';

  // Snapshot coordinates come from the URL (#/files?tenant=&source=&time=).
  const tenant = route.query.get('tenant') ?? '';
  const source = route.query.get('source') ?? '';
  const time = Number(route.query.get('time') ?? 0);

  const ctl = new AbortController();
  onDestroy(() => ctl.abort());

  let path = $state(route.query.get('path') || '/');
  let entries: FileEntry[] = $state([]);
  let listing = $state(false);
  let error: string | null = $state(null);
  let failedJob: number | null = $state(null);
  const cache = new Map<string, FileEntry[]>();

  let selected: string[] = $state([]);
  let format: 'tar' | 'zip' = $state('tar');
  let preparing = $state(false);
  let ready: { token: string; filename: string } | null = $state(null);

  const join = (dir: string, name: string) => (dir.endsWith('/') ? dir + name : `${dir}/${name}`);
  const crumbs = $derived(path.split('/').filter(Boolean));

  function failed(j: Job | null) {
    if (j && j.state !== 'ok') {
      failedJob = j.id;
      error = t.files.failed;
      return true;
    }
    return false;
  }

  async function open(p: string) {
    path = p;
    error = null;
    failedJob = null;
    const hit = cache.get(p);
    if (hit) {
      entries = hit;
      return;
    }
    listing = true;
    entries = [];
    try {
      const r = await runJob('files_list', tenant, { source, time, path: p }, ctl.signal);
      if (!r || failed(r.job)) return;
      const list = fileEntries(r.job).sort(
        (a, b) => Number(b.kind === 'dir') - Number(a.kind === 'dir') || a.name.localeCompare(b.name),
      );
      cache.set(p, list);
      if (path === p) entries = list;
    } catch (e) {
      error = errText(e);
    } finally {
      listing = false;
    }
  }

  function up() {
    const parts = path.split('/').filter(Boolean);
    parts.pop();
    open('/' + parts.join('/'));
  }

  function toggle(full: string, on: boolean) {
    selected = on ? [...selected, full] : selected.filter((x) => x !== full);
    ready = null;
  }

  async function prepare() {
    preparing = true;
    ready = null;
    error = null;
    try {
      const r = await runJob('files_get', tenant, { source, time, paths: selected, format }, ctl.signal);
      if (!r || failed(r.job)) return;
      if (r.token) ready = { token: r.token, filename: `${source}-${time}.${format}` };
    } catch (e) {
      error = errText(e);
    } finally {
      preparing = false;
    }
  }

  // Host snapshots (`host-<agent id>`) can also be restored onto a path of an agent.
  const agentId = hostAgentId(source);
  let agents: Agent[] = $state([]);
  let restoreOpen = $state(false);
  const hostName = $derived(agents.find((a) => a.id === agentId)?.name);
  if (agentId)
    get<Agent[]>('/agents')
      .then((xs) => (agents = xs))
      .catch(() => {
        /* the restore dialog then has no agents to offer */
      });

  open(route.query.get('path') || '/');
</script>

<div class="page-head">
  <h1>{t.files.title(source, fmtTime(time))}</h1>
  <a class="button" href={href(`/snapshots?source=${encodeURIComponent(source)}`)}>{t.snap.title}</a>
</div>
<p class="muted">{tenant}{hostName ? ` · ${t.snap.agent(hostName)}` : ''}</p>

<ErrorBanner {error} />
{#if failedJob}<p><a href={href(`/jobs/${failedJob}`)}>{t.jobs.detail(failedJob)}</a></p>{/if}

<div class="card">
  <nav class="breadcrumb" aria-label={t.files.path}>
    <button type="button" class="link" onclick={() => open('/')}>/</button>
    {#each crumbs as c, i (i)}
      <span aria-hidden="true">›</span>
      <button type="button" class="link" onclick={() => open('/' + crumbs.slice(0, i + 1).join('/'))}>{c}</button>
    {/each}
  </nav>

  {#if listing}
    <p class="muted" aria-busy="true" role="status">{t.files.listing}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col"><span class="visually-hidden">{t.files.select}</span></th>
            <th scope="col">{t.name}</th>
            <th scope="col" class="num">{t.files.size}</th>
            <th scope="col">{t.files.modified}</th>
          </tr>
        </thead>
        <tbody>
          {#if path !== '/'}
            <tr>
              <td></td>
              <td colspan="3"><button type="button" class="link" onclick={up}>.. ({t.files.up})</button></td>
            </tr>
          {/if}
          {#each entries as e (e.name)}
            {@const full = join(path, e.name)}
            <tr>
              <td>
                <input
                  type="checkbox"
                  aria-label="{t.files.select} {e.name}"
                  checked={selected.includes(full)}
                  onchange={(ev) => toggle(full, ev.currentTarget.checked)}
                />
              </td>
              <td>
                {#if e.kind === 'dir'}
                  <button type="button" class="link" onclick={() => open(full)}>{e.name}/</button>
                {:else}
                  <span class="mono">{e.name}{e.kind === 'symlink' ? ` → ${e.link ?? ''}` : ''}</span>
                {/if}
              </td>
              <td class="num">{e.kind === 'file' ? fmtBytes(e.size) : ''}</td>
              <td class="nowrap">{fmtTime(e.mtime)}</td>
            </tr>
          {:else}
            <tr><td colspan="4" class="empty">{t.none}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<div class="card">
  <div class="row">
    <strong>{t.files.selected(selected.length)}</strong>
    <label class="visually-hidden" for="fmt">{t.files.format}</label>
    <select id="fmt" bind:value={format} class="auto">
      <option value="tar">tar</option>
      <option value="zip">zip</option>
    </select>
    <button type="button" class="primary" disabled={!selected.length || preparing} onclick={prepare}>
      {preparing ? t.files.preparing : t.files.download}
    </button>
    {#if ready}
      <a class="button" href={downloadUrl(ready.token)} download={ready.filename}>{t.files.get} {ready.filename}</a>
    {/if}
    {#if agentId}
      <button type="button" onclick={() => (restoreOpen = true)} aria-describedby="restore-hint">
        {selected.length ? t.snap.restorePath : t.files.restoreAll}
      </button>
    {/if}
  </div>
  {#if agentId}<p class="muted" id="restore-hint">{t.files.restoreHint}</p>{/if}
  {#if selected.length}
    <ul class="mono">
      {#each selected as s (s)}<li>{s}</li>{/each}
    </ul>
  {/if}
</div>

{#if agentId}
  <RestoreFiles
    bind:open={restoreOpen}
    {tenant}
    {source}
    {time}
    paths={selected.length ? selected : ['/']}
    {agents}
  />
{/if}
