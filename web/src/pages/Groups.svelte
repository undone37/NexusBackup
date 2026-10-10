<script lang="ts">
  import { askConfirm } from '../lib/confirm.svelte';
  import { onMount, onDestroy } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { href } from '../lib/router.svelte';
  import { fmtBytes } from '../lib/format';
  import { t } from '../lib/i18n';
  import { runJob } from '../lib/jobs';
  import { isPluginKind, pluginKinds } from '../lib/plugins';
  import type { Agent, Group, Plugin, PluginGuest, Policy, Source, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let items: Group[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let sources: Source[] = $state([]);
  let policies: Policy[] = $state([]);
  let agents: Agent[] = $state([]);
  let plugins: Plugin[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      [items, tenants, sources, policies, agents] = await Promise.all([
        get<Group[]>('/groups'),
        get<Tenant[]>('/tenants'),
        get<Source[]>('/sources'),
        get<Policy[]>('/policies'),
        get<Agent[]>('/agents'),
      ]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    try {
      plugins = await get<Plugin[]>('/plugins');
    } catch {
      /* plugin sources then offer no guest list */
    }
    loaded = true;
  }
  onMount(load);
  const kinds = $derived(pluginKinds(plugins));
  const kindTitle = (k: string) => t.sources.kinds[k] ?? kinds.get(k)?.kind.title ?? '—';

  const sourceName = (id: number) => sources.find((s) => s.id === id)?.name ?? `#${id}`;
  const policyName = (id: number) => policies.find((p) => p.id === id)?.name ?? `#${id}`;
  const agentName = (id: string) => agents.find((a) => a.id === id)?.name ?? id;
  const guestText = (g: number | string) => (typeof g === 'string' ? agentName(g) : String(g));

  let open = $state(false);
  let editing: Group | null = $state(null);
  let f = $state({ tenant: '', name: '', source_id: 0, policy_id: 0, guests: '', datasets: [] as string[] });
  const tenantSources = $derived(sources.filter((s) => s.tenant === f.tenant));
  // A linux source backs up exactly one host: guests = [its agent id], no VM/CT IDs.
  const linuxSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s?.kind === 'linux' ? s : null;
  });
  // A truenas source: guests = a subset of its datasets (none = all).
  const nasSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s?.kind === 'truenas' ? s : null;
  });
  // An nfs/smb source is one share: the group has no guests.
  const shareSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s?.kind === 'nfs' || s?.kind === 'smb' ? s : null;
  });
  // A plugin source: guests are ids from the plugin's guest list (if its kind has one), else none.
  const pluginSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s && isPluginKind(s.kind) ? s : null;
  });
  const pluginGuests = $derived(pluginSource ? (kinds.get(pluginSource.kind)?.kind.guests ?? null) : null);
  const GUEST_RE = /^[A-Za-z0-9._-]{1,64}$/;

  // "Load <guests.title>": plugin_guests job against the source.
  const ctl = new AbortController();
  onDestroy(() => ctl.abort());
  let guestList: { source: number; guests: PluginGuest[] } | null = $state(null);
  let guestsBusy = $state(false);
  let guestsJob: number | null = $state(null);
  async function loadGuests() {
    const s = pluginSource;
    if (!s) return;
    guestsBusy = true;
    guestsJob = null;
    try {
      const r = await runJob('plugin_guests', s.tenant, { source_id: s.id }, ctl.signal);
      if (r && r.job.state === 'ok') guestList = { source: s.id, guests: r.job.result?.guests ?? [] };
      else if (r) {
        guestsJob = r.job.id;
        notify('error', t.groups.guestsFailed);
      }
    } catch (e) {
      notify('error', errText(e));
    } finally {
      guestsBusy = false;
    }
  }
  /** Loaded guests of the selected source plus already selected ids that were not listed. */
  const guestChoices = $derived.by(() => {
    const listed = guestList && guestList.source === Number(f.source_id) ? guestList.guests : [];
    const extra = f.datasets.filter((g) => !listed.some((x) => x.id === g)).map((id) => ({ id, title: id }) as PluginGuest);
    return [...listed, ...extra];
  });

  // Keep the source selection valid when the tenant changes.
  $effect(() => {
    if (open && !tenantSources.some((s) => s.id === f.source_id)) f.source_id = tenantSources[0]?.id ?? 0;
  });

  function edit(x: Group | null) {
    editing = x;
    const tenant = x?.tenant ?? tenants[0]?.name ?? '';
    f = {
      tenant,
      name: x?.name ?? '',
      source_id: x?.source_id ?? sources.find((s) => s.tenant === tenant)?.id ?? 0,
      policy_id: x?.policy_id ?? policies[0]?.id ?? 0,
      guests: (x?.guests ?? []).filter((g) => typeof g === 'number').join(', '),
      datasets: (x?.guests ?? []).filter((g): g is string => typeof g === 'string'),
    };
    lastSource = f.source_id;
    guestList = null;
    open = true;
  }
  // Another source: the selected guests/datasets belonged to the old one.
  let lastSource = 0;
  $effect(() => {
    if (!open || Number(f.source_id) === lastSource) return;
    lastSource = Number(f.source_id);
    f.datasets = [];
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    let guests: (number | string)[];
    if (linuxSource) {
      guests = [linuxSource.config.agent_id];
    } else if (pluginSource) {
      // (f.datasets holds the selected guest ids of a plugin source too)
      guests = pluginGuests?.list ? f.datasets : [];
      const bad = (guests as string[]).find((g) => !GUEST_RE.test(g));
      if (bad) {
        notify('error', t.groups.guestInvalid(bad));
        return;
      }
    } else if (shareSource) {
      guests = [];
    } else if (nasSource) {
      guests = f.datasets.filter((d) => nasSource.config.datasets.includes(d));
    } else {
      guests = f.guests.split(/[\s,]+/).filter(Boolean).map(Number);
      if (guests.some((g) => !Number.isInteger(g) || Number(g) < 100)) {
        notify('error', t.groups.guests);
        return;
      }
    }
    // The tenant is fixed after creation (PUT rejects unknown fields, incl. tenant).
    const body = { name: f.name, source_id: Number(f.source_id), policy_id: Number(f.policy_id), guests };
    const r = editing
      ? await act(put(`/groups/${editing.id}`, body), t.saved)
      : await act(post('/groups', { tenant: f.tenant, ...body }), t.created);
    if (r) {
      open = false;
      load();
    }
  }

  async function remove(x: Group) {
    if (!(await askConfirm(t.confirmDelete(`${t.dash.group} "${x.name}"`)))) return;
    if (await act(del(`/groups/${x.id}`), t.deleted)) load();
  }
</script>

<div class="page-head">
  <h1>{t.groups.title}</h1>
  <button type="button" class="primary" onclick={() => edit(null)}>{t.groups.new}</button>
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
            <th scope="col">{t.groups.source}</th>
            <th scope="col">{t.groups.policy}</th>
            <th scope="col">{t.groups.guestsShort}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            <tr>
              <td><strong>{x.name}</strong></td>
              <td>{x.tenant}</td>
              <td>{sourceName(x.source_id)}</td>
              <td>{policyName(x.policy_id)}</td>
              <td class="mono"
                >{x.guests.length
                  ? x.guests.map(guestText).join(', ')
                  : kindTitle(sources.find((s) => s.id === x.source_id)?.kind ?? '')}</td
              >
              <td class="actions">
                <button type="button" class="small" onclick={() => edit(x)}>{t.edit}</button>
                <button type="button" class="small danger" onclick={() => remove(x)}>{t.delete}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal bind:open title={editing ? `${t.dash.group}: ${editing.name}` : t.groups.new}>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="g-tenant">{t.tenant}</label>
        <select id="g-tenant" bind:value={f.tenant} disabled={!!editing} required>
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="g-name">{t.name}</label>
        <input id="g-name" bind:value={f.name} required />
      </div>
      <div class="field">
        <label for="g-src">{t.groups.source}</label>
        <select id="g-src" bind:value={f.source_id} required>
          {#each tenantSources as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="g-pol">{t.groups.policy}</label>
        <select id="g-pol" bind:value={f.policy_id} required>
          {#each policies as p (p.id)}<option value={p.id}>{p.name} ({p.schedule})</option>{/each}
        </select>
      </div>
    </div>
    {#if linuxSource}
      <p class="muted">{t.groups.linuxGuest(agentName(linuxSource.config.agent_id))}</p>
    {:else if pluginSource}
      {#if pluginGuests?.list}
        <fieldset class="field">
          <legend>{t.groups.pluginGuests(pluginGuests.title)}</legend>
          <div class="row">
            <button type="button" class="small" disabled={guestsBusy} onclick={loadGuests}
              >{guestsBusy ? t.groups.loadingGuests : t.groups.loadGuests(pluginGuests.title)}</button
            >
            {#if guestsJob}<a href={href(`/jobs/${guestsJob}`)}>{t.jobs.detail(guestsJob)}</a>{/if}
          </div>
          {#each guestChoices as g (g.id)}
            <label class="inline-check"
              ><input type="checkbox" value={g.id} bind:group={f.datasets} /><span class="mono">{g.id}</span
              >{#if g.title !== g.id}<span>{g.title}</span>{/if}{#if g.size !== undefined}<span class="muted"
                  >{fmtBytes(g.size)}</span
                >{/if}</label
            >
          {:else}
            <p class="hint">{t.groups.guestsLoadHint(pluginGuests.title)}</p>
          {/each}
        </fieldset>
      {:else}
        <p class="muted">{t.groups.wholeSource}</p>
      {/if}
    {:else if shareSource}
      <p class="muted">{t.groups.wholeShare}</p>
    {:else if nasSource}
      <fieldset class="field">
        <legend>{t.groups.datasets}</legend>
        {#each nasSource.config.datasets as d (d)}
          <label class="inline-check mono"><input type="checkbox" value={d} bind:group={f.datasets} />{d}</label>
        {/each}
      </fieldset>
    {:else}
      <div class="field">
        <label for="g-guests">{t.groups.guests}</label>
        <input id="g-guests" class="mono" bind:value={f.guests} placeholder="100, 101, 200" />
      </div>
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>
