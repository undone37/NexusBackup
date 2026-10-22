<script lang="ts">
  // Phase 33: compliance search and cases (web-api cases.rs). A case keeps search criteria; its search
  // is a file_search job over the tenant's name indexes; the matched snapshots can be held and exported.
  import { onDestroy, onMount } from 'svelte';
  import SourceName from '../components/SourceName.svelte';
  import { get, post, act, errText, qs } from '../lib/api';
  import { route, href, navigate } from '../lib/router.svelte';
  import { askConfirm } from '../lib/confirm.svelte';
  import { fmtAgo, fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { can } from '../lib/roles';
  import { session } from '../lib/session.svelte';
  import type { CaseInfo, Tenant } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import Modal from '../components/Modal.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconGavel from '@lucide/svelte/icons/gavel';
  import IconDownload from '@lucide/svelte/icons/download';

  const id = $props.id();
  const PREFIXES = ['plugin-m365-', ''];
  let cases: CaseInfo[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let one: CaseInfo | null = $state(null);
  const caseId = $derived(Number(route.query.get('id') ?? 0) || null);
  const officer = $derived(session.user?.role === 'security_officer');
  const mayExport = $derived(can.download(session.user));

  async function load() {
    try {
      if (caseId) one = await get<CaseInfo>(`/cases/${caseId}`);
      else cases = await get<CaseInfo[]>('/cases');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  let timer: ReturnType<typeof setInterval> | null = null;
  onMount(async () => {
    tenants = await get<Tenant[]>('/tenants').catch(() => []);
    timer = setInterval(() => {
      // follow a running search
      const busy = caseId
        ? one?.job_state === 'queued' || one?.job_state === 'running'
        : cases.some((c) => c.job_state === 'queued' || c.job_state === 'running');
      if (busy) load();
    }, 3000);
  });
  onDestroy(() => timer && clearInterval(timer));
  $effect(() => {
    void caseId;
    load();
  });

  const searchState = (c: CaseInfo) =>
    c.job_state === 'queued' || c.job_state === 'running'
      ? t.cases.searching
      : c.searched_at
        ? fmtAgo(c.searched_at)
        : t.cases.neverSearched;

  // ---- new case
  let newOpen = $state(false);
  let busy = $state(false);
  let f = $state({
    tenant: '',
    name: '',
    description: '',
    query: '',
    prefix: 'plugin-m365-',
    from: '',
    to: '',
    cs: false,
    sender: '',
    recipient: '',
  });
  function openNew() {
    f = {
      tenant: tenants[0]?.name ?? '',
      name: '',
      description: '',
      query: '',
      prefix: 'plugin-m365-',
      from: '',
      to: '',
      cs: false,
      sender: '',
      recipient: '',
    };
    newOpen = true;
  }
  const day = (d: string, end: boolean) =>
    d ? Math.floor(new Date(`${d}T00:00:00Z`).getTime() / 1000) + (end ? 86399 : 0) : undefined;
  async function create(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    const criteria = {
      query: f.query.trim(),
      source_prefix: f.prefix,
      from: day(f.from, false),
      to: day(f.to, true),
      case_sensitive: f.cs,
      sender: f.sender.trim() || undefined,
      recipient: f.recipient.trim() || undefined,
    };
    const r = await act(
      post<CaseInfo>('/cases', { tenant: f.tenant, name: f.name.trim(), description: f.description, criteria }),
      () => t.cases.created(f.name.trim()),
    );
    busy = false;
    if (r && !r.quorum) {
      newOpen = false;
      navigate('/cases' + qs({ id: r.data.id }));
    }
  }

  // ---- actions on one case
  async function searchAgain() {
    if (one && (await act(post(`/cases/${one.id}/search`), t.cases.searchQueued))) load();
  }
  let holdOpen = $state(false);
  let holdReason = $state('');
  async function hold(e: SubmitEvent) {
    e.preventDefault();
    if (!one) return;
    const r = await act(post<{ held: number }>(`/cases/${one.id}/hold`, { reason: holdReason.trim() }), (d) =>
      t.cases.holdDone(d.held),
    );
    if (r) {
      holdOpen = false;
      load();
    }
  }
  let expOpen = $state(false);
  let format = $state<'tar' | 'zip'>('tar');
  let mailFormat = $state<'' | 'eml' | 'mbox' | 'pst'>('');
  let exportJobs: { id: number; source: string; time: number }[] = $state([]);
  async function exportItems(e: SubmitEvent) {
    e.preventDefault();
    if (!one) return;
    const body = { format, ...(mailFormat ? { mail_format: mailFormat } : {}) };
    const r = await act(
      post<{ jobs: { id: number; source: string; time: number }[] }>(`/cases/${one.id}/export`, body),
      (d) => t.cases.exportDone(d.jobs.length),
    );
    if (r && !r.quorum) {
      exportJobs = r.data.jobs;
      expOpen = false;
    }
  }
  async function close() {
    if (!one || !(await askConfirm(t.cases.closeConfirm(one.name)))) return;
    if (await act(post(`/cases/${one.id}/close`), t.cases.closed)) load();
  }
</script>

<div class="page-head">
  <h1>{one && caseId ? `${t.cases.title}: ${one.name}` : t.cases.title}</h1>
  <div class="tools">
    {#if caseId}
      <a class="button" href={href('/cases')}>{t.cases.back}</a>
    {:else}
      <button type="button" class="primary" onclick={openNew}><IconPlus aria-hidden="true" />{t.cases.newCase}</button>
    {/if}
  </div>
  <p class="lede">{t.cases.lede}</p>
</div>

<ErrorBanner {error} />

{#if !loaded}
  <p class="muted" aria-busy="true">{t.loading}</p>
{:else if caseId && one}
  <section class="card" aria-labelledby="{id}-c">
    <div class="card-head">
      <h2 id="{id}-c">{t.cases.criteria}</h2>
      <span class="chip {one.state === 'open' ? 'ok' : ''}">{t.cases.state[one.state]}</span>
    </div>
    {#if one.description}<p>{one.description}</p>{/if}
    <dl class="kv">
      <dt>{t.tenant}</dt>
      <dd>{one.tenant}</dd>
      <dt>{t.cases.query}</dt>
      <dd class="mono">{one.criteria.query}</dd>
      <dt>{t.cases.prefix}</dt>
      <dd>{t.cases.prefixes[one.criteria.source_prefix ?? ''] ?? one.criteria.source_prefix}</dd>
      {#if one.criteria.sender}<dt>{t.cases.sender}</dt>
        <dd class="mono">{one.criteria.sender}</dd>{/if}
      {#if one.criteria.recipient}<dt>{t.cases.recipient}</dt>
        <dd class="mono">{one.criteria.recipient}</dd>{/if}
      {#if one.criteria.from || one.criteria.to}
        <dt>{t.cases.from} / {t.cases.to}</dt>
        <dd>
          {one.criteria.from ? fmtTime(one.criteria.from) : '—'} / {one.criteria.to ? fmtTime(one.criteria.to) : '—'}
        </dd>
      {/if}
      <dt>{t.cases.searched}</dt>
      <dd>
        {searchState(one)}{#if one.last_job}
          · <a href={href(`/jobs/${one.last_job}`)}>#{one.last_job}</a>{/if}
      </dd>
      <dt>{t.cases.snapshots}</dt>
      <dd>{one.snapshots} · {t.cases.items}: {one.items} · {t.cases.held}: {one.held}</dd>
    </dl>
    {#if one.truncated}<p class="banner warn">{t.cases.truncated}</p>{/if}
    <p class="muted small">{t.cases.privacy}</p>
    {#if one.state === 'open'}
      <div class="form-actions">
        <button type="button" onclick={searchAgain} disabled={one.job_state === 'queued' || one.job_state === 'running'}
          >{t.cases.searchAgain}</button
        >
        {#if officer}<button
            type="button"
            onclick={() => ((holdReason = ''), (holdOpen = true))}
            disabled={!one.snapshots}><IconGavel aria-hidden="true" />{t.cases.hold}</button
          >{/if}
        {#if mayExport}<button type="button" onclick={() => (expOpen = true)} disabled={!one.snapshots}
            ><IconDownload aria-hidden="true" />{t.cases.export}</button
          >{/if}
        <button type="button" class="danger" onclick={close}>{t.cases.close}</button>
      </div>
    {/if}
    {#if exportJobs.length}
      <h3>{t.cases.exportJobs}</h3>
      <ul>
        {#each exportJobs as j (j.id)}<li>
            <a href={href(`/jobs/${j.id}`)}>#{j.id}</a>
            <SourceName source={j.source} tenant={one.tenant} /> · {fmtTime(j.time)}
          </li>{/each}
      </ul>
    {/if}
  </section>

  <section class="card" aria-labelledby="{id}-s">
    <h2 id="{id}-s">{t.cases.snapshotList}</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.snap.source}</th>
            <th scope="col">{t.time}</th>
            <th scope="col" class="num">{t.cases.items}</th>
            <th scope="col">{t.cases.hold_}</th>
          </tr>
        </thead>
        <tbody>
          {#each one.snapshot_list ?? [] as s (s.source + s.time)}
            <tr>
              <td
                ><a href={href('/snapshots' + qs({ tenant: one.tenant, source: s.source }))}
                  ><SourceName source={s.source} tenant={one.tenant} /></a
                ></td
              >
              <td>{fmtTime(s.time)}</td>
              <td class="num">{s.items}</td>
              <td
                >{#if s.hold}<span class="chip {s.hold.state === 'active' ? 'accent' : ''}" title={s.hold.reason}
                    >{s.hold.state}</span
                  >{:else}<span class="muted">{t.cases.noHold}</span>{/if}</td
              >
            </tr>
          {:else}
            <tr><td colspan="4" class="empty">{t.none}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  {#if one.matches?.length}
    <section class="card" aria-labelledby="{id}-m">
      <h2 id="{id}-m">{t.cases.matches}</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.snap.source}</th>
              <th scope="col">{t.files.path}</th>
              <th scope="col" class="num">{t.files.size}</th>
              <th scope="col">{t.cases.snapshots}</th>
            </tr>
          </thead>
          <tbody>
            {#each one.matches.slice(0, 300) as m (m.source + m.path + m.mtime)}
              <tr>
                <td><SourceName source={m.source} tenant={one.tenant} /></td>
                <td class="mono">{m.path}</td>
                <td class="num">{fmtBytes(m.size)}</td>
                <td>{m.times.length}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}
{:else if !caseId}
  <section class="card">
    {#if cases.length === 0}
      <p class="empty">{t.cases.none}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.cases.name}</th>
              <th scope="col">{t.tenant}</th>
              <th scope="col">{t.state}</th>
              <th scope="col" class="num">{t.cases.snapshots}</th>
              <th scope="col" class="num">{t.cases.items}</th>
              <th scope="col" class="num">{t.cases.held}</th>
              <th scope="col">{t.cases.searched}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each cases as c (c.id)}
              <tr>
                <td
                  ><strong>{c.name}</strong>{#if c.description}<div class="muted small">{c.description}</div>{/if}</td
                >
                <td>{c.tenant}</td>
                <td><span class="chip {c.state === 'open' ? 'ok' : ''}">{t.cases.state[c.state]}</span></td>
                <td class="num">{c.snapshots}</td>
                <td class="num">{c.items}</td>
                <td class="num">{c.held}</td>
                <td>{searchState(c)}</td>
                <td class="actions"
                  ><a class="button small" href={href('/cases' + qs({ id: c.id }))}>{t.cases.open}</a></td
                >
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{/if}

<Modal bind:open={newOpen} wide title={t.cases.newCase}>
  <form onsubmit={create}>
    <div class="form-grid">
      <div class="field">
        <label for="{id}-t">{t.tenant}</label>
        <select id="{id}-t" bind:value={f.tenant} required>
          {#each tenants as x (x.name)}<option value={x.name}>{x.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="{id}-n">{t.cases.name}</label>
        <input
          id="{id}-n"
          bind:value={f.name}
          required
          maxlength="64"
          pattern={'[A-Za-z0-9_\\-][A-Za-z0-9._\\-]*'}
          aria-describedby="{id}-n-hint"
        />
        <div class="hint" id="{id}-n-hint">{t.cases.nameHint}</div>
      </div>
    </div>
    <div class="field">
      <label for="{id}-d">{t.cases.description}</label>
      <textarea id="{id}-d" bind:value={f.description} rows="2" maxlength="2000"></textarea>
    </div>
    <div class="field">
      <label for="{id}-q">{t.cases.query}</label>
      <input
        id="{id}-q"
        class="mono"
        bind:value={f.query}
        required={!f.sender.trim() && !f.recipient.trim()}
        maxlength="256"
        autocomplete="off"
        spellcheck="false"
        aria-describedby="{id}-q-hint"
      />
      <div class="hint" id="{id}-q-hint">{t.cases.queryHint}</div>
    </div>
    <div class="form-grid">
      <div class="field">
        <label for="{id}-s">{t.cases.sender}</label>
        <input
          id="{id}-s"
          class="mono"
          bind:value={f.sender}
          maxlength="254"
          autocomplete="off"
          spellcheck="false"
          aria-describedby="{id}-a-hint"
        />
      </div>
      <div class="field">
        <label for="{id}-r">{t.cases.recipient}</label>
        <input
          id="{id}-r"
          class="mono"
          bind:value={f.recipient}
          maxlength="254"
          autocomplete="off"
          spellcheck="false"
          aria-describedby="{id}-a-hint"
        />
      </div>
    </div>
    <div class="field"><div class="hint" id="{id}-a-hint">{t.cases.addrHint}</div></div>
    <div class="form-grid">
      <div class="field">
        <label for="{id}-p">{t.cases.prefix}</label>
        <select id="{id}-p" bind:value={f.prefix}>
          {#each PREFIXES as p (p)}<option value={p}>{t.cases.prefixes[p]}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="{id}-f">{t.cases.from}</label>
        <input id="{id}-f" type="date" bind:value={f.from} />
      </div>
      <div class="field">
        <label for="{id}-u">{t.cases.to}</label>
        <input id="{id}-u" type="date" bind:value={f.to} />
      </div>
    </div>
    <label class="inline-check"><input type="checkbox" bind:checked={f.cs} />{t.cases.caseSensitive}</label>
    <div class="form-actions">
      <button type="button" onclick={() => (newOpen = false)}>{t.cancel}</button>
      <button
        type="submit"
        class="primary"
        disabled={busy || !f.tenant || !f.name.trim() || !(f.query.trim() || f.sender.trim() || f.recipient.trim())}
        >{t.cases.create}</button
      >
    </div>
  </form>
</Modal>

<Modal bind:open={holdOpen} title={t.cases.hold}>
  <form onsubmit={hold}>
    <p class="muted">{t.cases.holdHint}</p>
    <div class="field">
      <label for="{id}-hr">{t.cases.holdReason}</label>
      <input id="{id}-hr" bind:value={holdReason} required maxlength="400" />
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (holdOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={!holdReason.trim()}>{t.cases.hold}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={expOpen} title={t.cases.export}>
  <form onsubmit={exportItems}>
    <p class="muted">{t.cases.exportHint(50)}</p>
    <div class="form-grid">
      <div class="field">
        <label for="{id}-ef">{t.cases.format}</label>
        <select id="{id}-ef" bind:value={format}>
          <option value="tar">tar</option>
          <option value="zip">zip</option>
        </select>
      </div>
      <div class="field">
        <label for="{id}-em">{t.cases.mailFormat}</label>
        <select id="{id}-em" bind:value={mailFormat}>
          <option value="">eml</option>
          <option value="mbox">mbox</option>
          <option value="pst">PST</option>
        </select>
      </div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (expOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.cases.export}</button>
    </div>
  </form>
</Modal>
