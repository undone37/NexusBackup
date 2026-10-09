<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { t } from '../lib/i18n';
  import type { Agent, Group, Policy, Source, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let items: Group[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let sources: Source[] = $state([]);
  let policies: Policy[] = $state([]);
  let agents: Agent[] = $state([]);
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
    loaded = true;
  }
  onMount(load);

  const sourceName = (id: number) => sources.find((s) => s.id === id)?.name ?? `#${id}`;
  const policyName = (id: number) => policies.find((p) => p.id === id)?.name ?? `#${id}`;
  const agentName = (id: string) => agents.find((a) => a.id === id)?.name ?? id;
  const guestText = (g: number | string) => (typeof g === 'string' ? agentName(g) : String(g));

  let open = $state(false);
  let editing: Group | null = $state(null);
  let f = $state({ tenant: '', name: '', source_id: 0, policy_id: 0, guests: '' });
  const tenantSources = $derived(sources.filter((s) => s.tenant === f.tenant));
  // A linux source backs up exactly one host: guests = [its agent id], no VM/CT IDs.
  const linuxSource = $derived.by(() => {
    const s = sources.find((x) => x.id === Number(f.source_id));
    return s?.kind === 'linux' ? s : null;
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
    };
    open = true;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    let guests: (number | string)[];
    if (linuxSource) {
      guests = [linuxSource.config.agent_id];
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
    if (!confirm(t.confirmDelete(`${t.dash.group} "${x.name}"`))) return;
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
              <td class="mono">{x.guests.map(guestText).join(', ')}</td>
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
