<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import SourceName from '../components/SourceName.svelte';
  import { ApiError, get, post, errText, qs } from '../lib/api';
  import { route, href } from '../lib/router.svelte';
  import { runJob, downloadUrl, hostAgentId, terminal } from '../lib/jobs';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { can } from '../lib/roles';
  import { session } from '../lib/session.svelte';
  import type {
    Agent,
    FileHit,
    FileSearchResult,
    FileVersion,
    Group,
    IndexSnap,
    IndexStatus,
    Job,
    SearchMatch,
    SearchResult,
    Snapshot,
    Tenant,
  } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import RestoreFiles from '../components/RestoreFiles.svelte';
  import IconChevron from '@lucide/svelte/icons/chevron-right';

  // Phase 31b: GET /files/search answers from the tenant's search index (nexus-index) while the
  // user types. When that service is down (503) the page falls back to the Phase 15g search job
  // (POST /search, the result comes back as `job.result`).
  let tenants: Tenant[] = $state([]);
  let snaps: Snapshot[] = $state([]);
  let agents: Agent[] = $state([]);
  let groups: Group[] = $state([]);
  const qp = (k: string) => route.query.get(k) ?? '';
  let tenant = $state(session.user?.tenant ?? qp('tenant'));
  let query = $state(qp('q'));
  let mode = $state(qp('mode') || 'auto');
  let source = $state(qp('source'));
  let group = $state(qp('group'));
  // "More filters"
  const KINDS = ['vm', 'ct', 'host', 'nas', 'share', 'plugin'];
  const UNITS: [string, number][] = [
    ['KiB', 2 ** 10],
    ['MiB', 2 ** 20],
    ['GiB', 2 ** 30],
  ];
  const kinds0 = qp('kind')
    .split(',')
    .filter((k) => KINDS.includes(k));
  let kinds: string[] = $state(kinds0);
  let ext = $state(qp('ext'));
  let sizeMin = $state('');
  let sizeMax = $state('');
  let unit = $state('MiB');
  let modFrom = $state('');
  let modTo = $state('');
  let entry = $state(qp('entry'));
  // C2: owners (SID, uid:gid, uid, or a well-known Windows group name the server turns into its SID)
  let owner = $state(qp('owner'));
  // #54: mails by sender / recipient (item metadata of Microsoft 365 backups)
  let sender = $state(qp('sender'));
  let recipient = $state(qp('recipient'));
  let more = $state(
    !!(kinds0.length || qp('ext') || qp('entry') || qp('deleted') || qp('owner') || qp('sender') || qp('recipient')),
  );
  let deleted = $state(qp('deleted') || 'any');

  let busy = $state(false);
  let error: string | null = $state(null);
  let failedJob: number | null = $state(null);
  let result = $state<FileSearchResult | null>(null);
  let status = $state<IndexStatus | null>(null);
  let fallback = $state(false);
  let jobResult: SearchResult | null = $state(null);
  // expanded rows and the chosen snapshot per version (default: the newest one holding it)
  let expanded: Record<string, boolean> = $state({});
  let chosen: Record<string, number> = $state({});
  let ctl: AbortController | null = null;
  const page = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  onDestroy(() => {
    clearTimeout(timer);
    ctl?.abort();
    page.abort();
  });

  const sources = $derived(
    [...new Set(snaps.filter((s) => s.tenant === tenant && s.local).map((s) => s.source))].sort(),
  );
  // the guest's or agent's name next to the source (snapshot labels)
  const sourceLabel = $derived(new Map(snaps.filter((s) => s.label).map((s) => [s.source, s.label!])));
  const tenantGroups = $derived(groups.filter((g) => g.tenant === tenant));
  const hitKey = (h: FileHit) => `${h.source}\0${h.path}`;
  const verKey = (h: FileHit, i: number) => `${hitKey(h)}\0${i}`;
  const timeOf = (h: FileHit, i: number) => chosen[verKey(h, i)] ?? h.versions[i].times[0];
  const parent = (p: string) => '/' + p.split('/').slice(0, -1).join('/');
  /** Files page at the folder holding `browse` (a folder itself is opened). */
  const openHref = (src: string, browse: string, kind: string, time: number) => {
    const path = kind === 'dir' ? '/' + browse : parent(browse);
    return href(`/files?${new URLSearchParams({ tenant, source: src, time: String(time), path })}`);
  };
  // unix seconds of a date input (start of the day, or the end of it for "until")
  const day = (d: string, end: boolean) =>
    d ? Math.floor(new Date(`${d}T00:00:00`).getTime() / 1000) + (end ? 86399 : 0) : undefined;
  const unitSize = $derived(UNITS.find(([u]) => u === unit)?.[1] ?? 1);
  const bytes = (v: string) => (v.trim() !== '' && Number(v) >= 0 ? Math.round(Number(v) * unitSize) : undefined);
  const exts = $derived(
    ext
      .split(/[\s,;]+/)
      .map((x) => x.replace(/^\.+/, '').toLowerCase())
      .filter(Boolean),
  );
  const params = $derived({
    tenant,
    q: query.trim(),
    mode: mode === 'auto' ? undefined : mode,
    source,
    group,
    kind: kinds.join(','),
    ext: exts.join(','),
    size_min: bytes(sizeMin),
    size_max: bytes(sizeMax),
    mtime_from: day(modFrom, false),
    mtime_to: day(modTo, true),
    entry,
    owner: owner
      .split(/[,;]+/)
      .map((x) => x.trim())
      .filter(Boolean)
      .join(','),
    sender: sender.trim() || undefined,
    recipient: recipient.trim() || undefined,
    deleted: deleted === 'any' ? undefined : deleted,
  });
  // an empty query is fine when a filter narrows the search
  const ready = $derived(
    !!tenant &&
      (!!params.q ||
        !!params.ext ||
        params.size_min !== undefined ||
        params.size_max !== undefined ||
        params.mtime_from !== undefined ||
        params.mtime_to !== undefined ||
        !!params.owner ||
        !!params.sender ||
        !!params.recipient ||
        params.deleted === 'only'),
  );
  const paramQs = $derived(qs(params));
  const tenantStatus = $derived(status?.tenants?.find((x) => x.tenant === tenant) ?? null);
  const pending = $derived(result ? result.pending : (tenantStatus?.snapshots_pending ?? 0));

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
        /* the source filter then stays empty */
      });
    get<Group[]>('/groups')
      .then((xs) => (groups = xs))
      .catch(() => {
        /* the group filter then stays empty */
      });
    get<Agent[]>('/agents')
      .then((xs) => (agents = xs))
      .catch(() => {
        /* restores to a host then have no agents to offer */
      });
  });

  // index status of the tenant (pending snapshots, paused for space)
  $effect(() => {
    const tn = tenant;
    if (!tn || !can.search(session.user)) return;
    get<IndexStatus>(`/files/index-status${qs({ tenant: tn })}`, page.signal)
      .then((s) => {
        if (tn === tenant) status = s;
      })
      .catch(() => {
        status = null;
      });
  });

  // search as you type: 300 ms after the last change (Enter searches at once)
  $effect(() => {
    const p = paramQs;
    const ok = ready;
    if (fallback) return;
    clearTimeout(timer);
    if (!ok) {
      ctl?.abort();
      busy = false;
      result = null;
      return;
    }
    timer = setTimeout(() => instant(p), 300);
    return () => clearTimeout(timer);
  });

  let loadingMore = $state(false);
  async function instant(p: string, cursor?: string) {
    ctl?.abort();
    const c = (ctl = new AbortController());
    if (cursor) loadingMore = true;
    else busy = true;
    error = null;
    failedJob = null;
    try {
      const r = await get<FileSearchResult>(
        `/files/search${p}${cursor ? `&${new URLSearchParams({ cursor })}` : ''}`,
        c.signal,
      );
      if (ctl !== c) return;
      if (cursor && result) {
        result = {
          ...r,
          hits: [...result.hits, ...r.hits],
          snapshots: { ...result.snapshots, ...r.snapshots },
          elapsed_ms: result.elapsed_ms + r.elapsed_ms,
        };
      } else {
        result = r;
        expanded = r.hits.length === 1 ? { [hitKey(r.hits[0])]: true } : {};
        chosen = {};
        ready_ = null;
      }
    } catch (err) {
      if (c.signal.aborted) return;
      if (err instanceof ApiError && err.status === 503) {
        fallback = true;
        result = null;
      } else error = errText(err);
    } finally {
      if (ctl === c) {
        busy = false;
        loadingMore = false;
      }
    }
  }

  function submit(e: Event) {
    e.preventDefault();
    if (fallback) {
      jobSearch();
      return;
    }
    clearTimeout(timer);
    if (ready) instant(paramQs);
  }

  function resetFilters() {
    kinds = [];
    ext = '';
    sizeMin = '';
    sizeMax = '';
    modFrom = '';
    modTo = '';
    entry = '';
    owner = '';
    sender = '';
    recipient = '';
    deleted = 'any';
  }

  // ---- fallback: the search job (Phase 15g)
  async function poll(id: number, signal: AbortSignal): Promise<Job | null> {
    for (;;) {
      await new Promise((r) => setTimeout(r, 700));
      if (signal.aborted) return null;
      const job = await get<Job>(`/jobs/${id}`);
      if (terminal(job.state)) return job;
    }
  }
  async function jobSearch() {
    if (!query.trim() || !tenant) return;
    ctl?.abort();
    const c = (ctl = new AbortController());
    busy = true;
    error = null;
    failedJob = null;
    jobResult = null;
    chosenJob = {};
    ready_ = null;
    try {
      const o = await post<{ id: number }>('/search', { tenant, query: query.trim(), source: source || undefined });
      if (o.data.id === undefined) return;
      const job = await poll(o.data.id, c.signal);
      if (!job) return;
      if (job.state !== 'ok') {
        failedJob = job.id;
        error = t.search.failed;
        return;
      }
      jobResult = job.result as unknown as SearchResult;
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
  let chosenJob: Record<string, number> = $state({});
  const mKey = (m: SearchMatch) => `${m.source}\0${m.path}\0${m.size}\0${m.mtime}`;
  const mTime = (m: SearchMatch) => chosenJob[mKey(m)] ?? m.times[0];

  // ---- actions on one version: download (files_get, tar) and restore to a host
  let preparing: string | null = $state(null);
  let ready_: { key: string; token: string; filename: string } | null = $state(null);
  async function download(k: string, src: string, browse: string, time: number) {
    preparing = k;
    ready_ = null;
    error = null;
    try {
      const r = await runJob(
        'files_get',
        tenant,
        { source: src, time, paths: ['/' + browse], format: 'tar' },
        page.signal,
      );
      if (!r) return;
      if (r.job.state !== 'ok') {
        failedJob = r.job.id;
        error = t.files.failed;
        return;
      }
      if (r.token) ready_ = { key: k, token: r.token, filename: `${src}-${time}.tar` };
    } catch (err) {
      error = errText(err);
    } finally {
      preparing = null;
    }
  }
  let restoreOpen = $state(false);
  let restoreOf: { source: string; time: number; path: string } | null = $state(null);
  function restore(src: string, browse: string, time: number) {
    restoreOf = { source: src, time, path: '/' + browse };
    restoreOpen = true;
  }

  const notIndexed = (xs: IndexSnap[]) => xs.filter((x) => x.state !== 'indexed');
  const stateCls = (s: string) =>
    s === 'indexed' ? 'ok' : s === 'partial' || s === 'pending' ? 'warn' : s === 'failed' ? 'bad' : 'off';
  const stateText = (x: IndexSnap) =>
    t.search.stateAt(fmtTime(x.time), t.search.states[x.state] ?? x.state, x.reason ?? '');
  const newest = (h: FileHit): FileVersion => h.versions[0];
</script>

<div class="page-head">
  <h1>{t.search.title}</h1>
  <a class="button" href={href('/snapshots')}>{t.snap.title}</a>
  <p class="lede">{t.search.lede}</p>
</div>

{#if fallback}
  <div class="banner warn" role="status">
    <span>{t.search.fallback}</span>
    <button type="button" class="small" onclick={() => (fallback = false)}>{t.search.retryInstant}</button>
  </div>
{/if}
{#if status?.paused}<p class="banner warn">{t.search.paused}</p>{/if}

<form class="filters" onsubmit={submit} role="search">
  {#if !session.user?.tenant}
    <div class="field">
      <label for="s-tenant">{t.search.tenant}</label>
      <select id="s-tenant" bind:value={tenant} onchange={() => ((source = ''), (group = ''))}>
        {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
      </select>
    </div>
  {/if}
  <div class="field grow">
    <label for="s-query">{t.search.query}</label>
    <input
      id="s-query"
      type="search"
      class="mono"
      bind:value={query}
      maxlength="256"
      autocomplete="off"
      aria-describedby="s-hint"
    />
  </div>
  {#if !fallback}
    <div class="field narrow">
      <label for="s-mode">{t.search.mode}</label>
      <select id="s-mode" bind:value={mode}>
        {#each ['auto', 'name', 'path', 'words'] as m (m)}<option value={m}>{t.search.modes[m]}</option>{/each}
      </select>
    </div>
  {/if}
  <div class="field">
    <label for="s-source">{t.search.source}</label>
    <select id="s-source" bind:value={source}>
      <option value="">{t.search.anySource}</option>
      {#each sources as s (s)}<option value={s}>{sourceLabel.get(s) ? `${sourceLabel.get(s)} · ${s}` : s}</option
        >{/each}
    </select>
  </div>
  {#if !fallback}
    <div class="field">
      <label for="s-group">{t.search.group}</label>
      <select id="s-group" bind:value={group}>
        <option value="">{t.search.anyGroup}</option>
        {#each tenantGroups as g (g.id)}<option value={String(g.id)}>{g.name}</option>{/each}
      </select>
    </div>
    <button type="button" aria-expanded={more} aria-controls="s-more" onclick={() => (more = !more)}
      ><IconChevron class="chev{more ? ' open' : ''}" aria-hidden="true" />{t.search.moreFilters}</button
    >
  {/if}
  {#if busy && fallback}
    <button type="button" onclick={stop}>{t.search.cancel}</button>
  {:else}
    <button type="submit" class="primary" disabled={fallback ? !query.trim() || !tenant : !ready}
      >{t.search.submit}</button
    >
  {/if}
  {#if more && !fallback}
    <div class="more" id="s-more">
      <fieldset class="field kinds">
        <legend>{t.search.kinds}</legend>
        <div class="row">
          {#each KINDS as k (k)}
            <label class="inline-check"
              ><input type="checkbox" value={k} bind:group={kinds} />{t.search.kindNames[k]}</label
            >
          {/each}
        </div>
      </fieldset>
      <div class="field">
        <label for="s-ext">{t.search.ext}</label>
        <input
          id="s-ext"
          class="mono"
          bind:value={ext}
          placeholder="pdf, docx"
          autocomplete="off"
          aria-describedby="s-ext-hint"
        />
        <div class="hint" id="s-ext-hint">{t.search.extHint}</div>
      </div>
      <div class="field size">
        <label for="s-smin">{t.search.sizeMin}</label>
        <input id="s-smin" type="number" min="0" step="any" bind:value={sizeMin} />
      </div>
      <div class="field size">
        <label for="s-smax">{t.search.sizeMax}</label>
        <input id="s-smax" type="number" min="0" step="any" bind:value={sizeMax} />
      </div>
      <div class="field unit">
        <label for="s-unit">{t.search.sizeUnit}</label>
        <select id="s-unit" bind:value={unit}>
          {#each UNITS as [u] (u)}<option value={u}>{u}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="s-from">{t.search.modFrom}</label>
        <input id="s-from" type="date" bind:value={modFrom} />
      </div>
      <div class="field">
        <label for="s-to">{t.search.modTo}</label>
        <input id="s-to" type="date" bind:value={modTo} />
      </div>
      <div class="field">
        <label for="s-entry">{t.search.entry}</label>
        <select id="s-entry" bind:value={entry}>
          {#each ['', 'file', 'dir'] as x (x)}<option value={x}>{t.search.entries[x]}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="s-owner">{t.search.ownerFilter}</label>
        <input
          id="s-owner"
          bind:value={owner}
          spellcheck="false"
          autocapitalize="none"
          placeholder="1000, S-1-5-21-…, Administrators"
          aria-describedby="s-owner-hint"
        />
        <div class="hint" id="s-owner-hint">{t.search.ownerHint}</div>
      </div>
      <div class="field">
        <label for="s-sender">{t.search.sender}</label>
        <input
          id="s-sender"
          bind:value={sender}
          spellcheck="false"
          autocapitalize="none"
          placeholder="cfo@contoso.com, contoso.com"
          aria-describedby="s-mail-hint"
        />
      </div>
      <div class="field">
        <label for="s-recipient">{t.search.recipient}</label>
        <input
          id="s-recipient"
          bind:value={recipient}
          spellcheck="false"
          autocapitalize="none"
          aria-describedby="s-mail-hint"
        />
        <div class="hint" id="s-mail-hint">{t.search.mailHint}</div>
      </div>
      <div class="field">
        <label for="s-deleted">{t.search.deleted}</label>
        <select id="s-deleted" bind:value={deleted}>
          {#each ['any', 'only', 'exclude'] as x (x)}<option value={x}>{t.search.deletedModes[x]}</option>{/each}
        </select>
      </div>
      <button type="button" onclick={resetFilters}>{t.search.reset}</button>
    </div>
  {/if}
</form>
<p class="muted" id="s-hint">{t.search.queryHint}</p>
{#if pending > 0 && !fallback}<p class="banner info">{t.search.pending(pending)}</p>{/if}

<ErrorBanner {error} />
{#if failedJob}<p><a href={href(`/jobs/${failedJob}`)}>{t.jobs.detail(failedJob)}</a></p>{/if}

{#if fallback}
  {#if busy}
    <p class="muted" aria-busy="true" role="status">{t.search.searching}</p>
  {:else if jobResult}
    {#if jobResult.truncated}<p class="banner warn">{t.search.truncated}</p>{/if}
    {#if jobResult.unindexed > 0}<p class="banner info">{t.search.unindexed(jobResult.unindexed)}</p>{/if}
    <div class="card">
      <p class="muted" role="status">
        {t.search.summary(jobResult.matches.length, jobResult.scanned, jobResult.elapsed_ms)}
      </p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.search.path}</th>
              <th scope="col" class="num">{t.search.size}</th>
              <th scope="col">{t.search.modified}</th>
              <th scope="col">{t.search.source}</th>
              <th scope="col">{t.search.snapshots}</th>
              <th scope="col"><span class="visually-hidden">{t.search.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each jobResult.matches as m (mKey(m))}
              {@const k = mKey(m)}
              <tr>
                <td class="mono">{m.path}{m.kind === 'dir' ? '/' : ''}</td>
                <td class="num">{m.kind === 'file' ? fmtBytes(m.size) : ''}</td>
                <td class="nowrap">{fmtTime(m.mtime)}</td>
                <td><SourceName source={m.source} {tenant} /></td>
                <td>
                  {#if m.times.length > 1}
                    <select
                      class="auto"
                      aria-label={t.search.version(m.path)}
                      value={mTime(m)}
                      onchange={(ev) => (chosenJob[k] = Number(ev.currentTarget.value))}
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
                    <a class="button" href={openHref(m.source, m.path, m.kind, mTime(m))}>{t.search.open}</a>
                    {#if m.kind === 'file' && can.download(session.user)}
                      {#if ready_?.key === k}
                        <a class="button" href={downloadUrl(ready_.token)} download={ready_.filename}
                          >{t.files.get} {ready_.filename}</a
                        >
                      {:else}
                        <button
                          type="button"
                          disabled={preparing !== null}
                          onclick={() => download(k, m.source, m.path, mTime(m))}
                        >
                          {preparing === k ? t.search.preparing : t.search.download}
                        </button>
                      {/if}
                    {/if}
                    {#if hostAgentId(m.source)}
                      <button type="button" onclick={() => restore(m.source, m.path, mTime(m))}
                        >{t.search.restore}</button
                      >
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
{:else if !ready}
  <p class="muted">{t.search.needQuery}</p>
{:else if result}
  <div class="card" aria-busy={busy}>
    <p class="muted" role="status">{t.search.hits(result.hits.length, !!result.next, result.elapsed_ms)}</p>
    <div class="table-wrap">
      <table class="hits">
        <thead>
          <tr>
            <th scope="col"><span class="visually-hidden">{t.search.timeline}</span></th>
            <th scope="col">{t.search.path}</th>
            <th scope="col">{t.search.source}</th>
            <th scope="col" class="num">{t.search.size}</th>
            <th scope="col">{t.search.modified}</th>
            <th scope="col" class="num">{t.search.versions}</th>
            <th scope="col">{t.search.status}</th>
          </tr>
        </thead>
        <tbody>
          {#each result.hits as h, hi (hitKey(h))}
            {@const hk = hitKey(h)}
            {@const v0 = newest(h)}
            {@const marks = result.snapshots[h.source] ?? []}
            {@const missing = notIndexed(marks)}
            <tr class:open={expanded[hk]}>
              <td class="exp">
                <button
                  type="button"
                  class="small icon"
                  aria-expanded={!!expanded[hk]}
                  aria-controls="s-v-{hi}"
                  aria-label={t.search.expand(h.path)}
                  onclick={() => (expanded[hk] = !expanded[hk])}
                  ><IconChevron class="chev{expanded[hk] ? ' open' : ''}" aria-hidden="true" /></button
                >
              </td>
              <td>
                <span class="mono">{h.path}{h.kind === 'dir' ? '/' : ''}</span>
                {#if h.kind !== 'file'}<span class="muted small"> ({t.search.kind[h.kind] ?? h.kind})</span>{/if}
              </td>
              <td><SourceName source={h.source} {tenant} /></td>
              <td class="num">{h.kind === 'file' && v0 ? fmtBytes(v0.size) : ''}</td>
              <td class="nowrap">{v0 ? fmtTime(v0.mtime) : '—'}</td>
              <td class="num">{h.versions.length}</td>
              <td>
                {#if v0?.gone}<span class="chip warn">{t.search.deletedOn(fmtTime(v0.gone))}</span>{/if}
                {#if v0 && !v0.times.length}<span class="chip plain" title={t.search.snapshotDeletedHint}
                    >{t.search.snapshotDeleted}</span
                  >{/if}
              </td>
            </tr>
            {#if expanded[hk]}
              <tr class="detail" id="s-v-{hi}">
                <td></td>
                <td colspan="6">
                  <table class="versions">
                    <caption class="visually-hidden">{t.search.timeline}: {h.path}</caption>
                    <thead>
                      <tr>
                        <th scope="col" class="num">{t.search.size}</th>
                        <th scope="col">{t.search.modified}</th>
                        <th scope="col">{t.search.firstSeen}</th>
                        <th scope="col">{t.search.until}</th>
                        {#if h.versions.some((v) => v.owner)}<th scope="col">{t.search.owner}</th>{/if}
                        <th scope="col">{t.search.inSnapshot}</th>
                        <th scope="col"><span class="visually-hidden">{t.search.actions}</span></th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each h.versions as v, vi (vi)}
                        {@const vk = verKey(h, vi)}
                        <tr>
                          <td class="num">{h.kind === 'file' ? fmtBytes(v.size) : ''}</td>
                          <td class="nowrap">{fmtTime(v.mtime)}</td>
                          <td class="nowrap">{fmtTime(v.first)}</td>
                          <td class="nowrap">
                            {#if v.gone && vi === 0}<span class="chip warn plain"
                                >{t.search.deletedOn(fmtTime(v.gone))}</span
                              >
                            {:else if v.gone}{fmtTime(v.gone)}
                            {:else}<span class="chip ok plain">{t.search.current}</span>{/if}
                          </td>
                          {#if h.versions.some((x) => x.owner)}
                            <td class="mono small" title={v.owner ?? ''}>{v.owner_name ?? v.owner ?? ''}</td>
                          {/if}
                          <td>
                            {#if v.times.length > 1}
                              <select
                                class="auto"
                                aria-label={t.search.pickSnapshot(h.path, fmtTime(v.mtime))}
                                value={timeOf(h, vi)}
                                onchange={(ev) => (chosen[vk] = Number(ev.currentTarget.value))}
                              >
                                {#each v.times as tm (tm)}<option value={tm}>{fmtTime(tm)}</option>{/each}
                              </select>
                              <span class="muted">{t.search.inSnapshots(v.times.length)}</span>
                            {:else if v.times.length === 1}
                              <span class="nowrap">{fmtTime(v.times[0])}</span>
                            {:else}
                              <span class="muted" title={t.search.snapshotDeletedHint}>{t.search.snapshotDeleted}</span>
                            {/if}
                          </td>
                          <td>
                            {#if v.times.length}
                              <div class="row">
                                <a class="button small" href={openHref(h.source, h.browse, h.kind, timeOf(h, vi))}
                                  >{t.search.open}</a
                                >
                                {#if h.kind === 'file' && can.download(session.user)}
                                  {#if ready_?.key === vk}
                                    <a class="button small" href={downloadUrl(ready_.token)} download={ready_.filename}
                                      >{t.files.get} {ready_.filename}</a
                                    >
                                  {:else}
                                    <button
                                      type="button"
                                      class="small"
                                      disabled={preparing !== null}
                                      onclick={() => download(vk, h.source, h.browse, timeOf(h, vi))}
                                    >
                                      {preparing === vk ? t.search.preparing : t.search.download}
                                    </button>
                                  {/if}
                                {/if}
                                {#if hostAgentId(h.source)}
                                  <button
                                    type="button"
                                    class="small"
                                    onclick={() => restore(h.source, h.browse, timeOf(h, vi))}
                                    >{t.search.restore}</button
                                  >
                                {/if}
                              </div>
                            {/if}
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                  {#if marks.length}
                    <div class="strip-wrap">
                      <span class="muted small"
                        >{t.search.strip(h.source)}: {t.search.stripSummary(marks.length, missing.length)}</span
                      >
                      <div class="strip" aria-hidden="true">
                        {#each [...marks].reverse() as x (x.time)}<span
                            class="mark {stateCls(x.state)}"
                            title={stateText(x)}
                          ></span>{/each}
                      </div>
                      {#if missing.length}
                        <ul class="missing small">
                          {#each missing.slice(0, 6) as x (x.time)}<li>
                              <span class="chip plain {stateCls(x.state)}">{t.search.states[x.state] ?? x.state}</span>
                              {fmtTime(x.time)}{x.reason ? `: ${x.reason}` : ''}
                            </li>{/each}
                          {#if missing.length > 6}<li class="muted">…</li>{/if}
                        </ul>
                      {/if}
                    </div>
                  {/if}
                </td>
              </tr>
            {/if}
          {:else}
            <tr><td colspan="7" class="empty">{t.search.none}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if result.next}
      <div class="row more-row">
        <button type="button" disabled={loadingMore} onclick={() => result?.next && instant(paramQs, result.next)}
          >{loadingMore ? t.search.loadingMore : t.search.loadMore}</button
        >
      </div>
    {/if}
  </div>
{:else if busy}
  <p class="muted" aria-busy="true" role="status">{t.search.searching}</p>
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

<style>
  .filters .grow {
    flex: 1 1 260px;
  }
  .filters .narrow {
    min-width: 110px;
  }
  .more {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    align-items: flex-end;
    flex-basis: 100%;
    padding-top: 0.75rem;
    border-top: 1px solid var(--border);
  }
  .more .kinds {
    flex-basis: 100%;
    margin: 0;
  }
  .more .size {
    min-width: 120px;
    max-width: 150px;
  }
  .more .unit {
    min-width: 90px;
  }
  :global(.chev) {
    transition: rotate 120ms var(--ease);
  }
  :global(.chev.open) {
    rotate: 90deg;
  }
  .exp {
    width: 2.5rem;
  }
  .exp button {
    padding: 0.2rem 0.35rem;
    min-height: 28px;
  }
  tr.open > td {
    background: var(--surface-2);
  }
  tr.detail > td {
    background: var(--surface-2);
    padding-top: 0;
  }
  table.versions {
    margin: 0.25rem 0 0.5rem;
  }
  .strip-wrap {
    display: grid;
    gap: 0.35rem;
    padding-bottom: 0.5rem;
  }
  .strip {
    display: flex;
    gap: 2px;
    flex-wrap: wrap;
  }
  .mark {
    width: 10px;
    height: 14px;
    border-radius: 2px;
    background: var(--c-ok);
  }
  .mark.warn {
    background: var(--c-warn);
  }
  .mark.bad {
    background: var(--c-bad);
  }
  .mark.off {
    background: var(--c-neutral);
  }
  .missing {
    margin: 0;
    padding-left: 0;
    list-style: none;
    display: grid;
    gap: 0.2rem;
  }
  .chip.off {
    color: var(--muted);
  }
  .more-row {
    justify-content: center;
    padding-top: 0.5rem;
  }
</style>
