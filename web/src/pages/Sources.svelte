<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { t } from '../lib/i18n';
  import type { Agent, Source, SourceKind, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let items: Source[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let agents: Agent[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      [items, tenants, agents] = await Promise.all([
        get<Source[]>('/sources'),
        get<Tenant[]>('/tenants'),
        get<Agent[]>('/agents'),
      ]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  let open = $state(false);
  let editing: Source | null = $state(null);
  let f = $state({
    kind: 'pve' as SourceKind,
    tenant: '',
    name: '',
    host: '',
    port: 8006,
    ca_pem: '',
    token_id: '',
    token_secret: '',
    nodes: '{}',
    storage: '',
    fleecing_storage: '',
    // linux
    agent_id: '',
    paths: '',
    excludes: '',
    hooks: false,
  });
  const tenantAgents = $derived(agents.filter((a) => a.tenant === f.tenant));
  // Keep the agent selection valid when the tenant changes.
  $effect(() => {
    if (open && f.kind === 'linux' && !tenantAgents.some((a) => a.id === f.agent_id)) f.agent_id = tenantAgents[0]?.id ?? '';
  });
  const agentName = (id: string) => agents.find((a) => a.id === id)?.name ?? id;
  const lines = (s: string) =>
    s
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);

  function edit(x: Source | null) {
    editing = x;
    const c = x?.kind === 'pve' ? x.config : undefined;
    const l = x?.kind === 'linux' ? x.config : undefined;
    f = {
      kind: x?.kind ?? 'pve',
      tenant: x?.tenant ?? tenants[0]?.name ?? '',
      name: x?.name ?? '',
      host: c?.host ?? '',
      port: c?.port ?? 8006,
      ca_pem: c?.ca_pem ?? '',
      token_id: c?.token_id ?? '',
      token_secret: '',
      nodes: JSON.stringify(c?.nodes ?? {}, null, 2),
      storage: c?.storage ?? '',
      fleecing_storage: c?.fleecing_storage ?? '',
      agent_id: l?.agent_id ?? '',
      paths: (l?.paths ?? []).join('\n'),
      excludes: (l?.excludes ?? []).join('\n'),
      hooks: l?.hooks ?? false,
    };
    open = true;
  }

  /** Config of a linux source, or null (after telling the user) when invalid. */
  function linuxConfig(): Record<string, unknown> | null {
    const paths = lines(f.paths);
    const excludes = lines(f.excludes);
    if (!paths.length || paths.length > 64 || paths.some((p) => !p.startsWith('/'))) {
      notify('error', t.sources.pathsInvalid);
      return null;
    }
    if (excludes.length > 256) {
      notify('error', t.sources.excludesInvalid);
      return null;
    }
    return { agent_id: f.agent_id, paths, excludes, hooks: f.hooks };
  }

  function pveConfig(): Record<string, unknown> | null {
    let nodes: Record<string, unknown>;
    try {
      nodes = JSON.parse(f.nodes || '{}');
    } catch {
      notify('error', `${t.err.invalidJson}: ${t.sources.nodes}`);
      return null;
    }
    const config: Record<string, unknown> = {
      host: f.host,
      port: Number(f.port),
      ca_pem: f.ca_pem,
      token_id: f.token_id,
      nodes,
      storage: f.storage,
      fleecing_storage: f.fleecing_storage,
    };
    // Write-only secret: only sent when entered.
    if (f.token_secret) config.token_secret = f.token_secret;
    return config;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const config = f.kind === 'linux' ? linuxConfig() : pveConfig();
    if (!config) return;
    const r = editing
      ? await act(put(`/sources/${editing.id}`, { name: f.name, config }), t.saved)
      : await act(post('/sources', { tenant: f.tenant, kind: f.kind, name: f.name, config }), t.created);
    if (r) {
      open = false;
      load();
    }
  }

  async function remove(x: Source) {
    if (!confirm(t.confirmDelete(`${t.groups.source} "${x.name}"`))) return;
    if (await act(del(`/sources/${x.id}`), t.deleted)) load();
  }
</script>

<div class="page-head">
  <h1>{t.sources.title}</h1>
  <button type="button" class="primary" onclick={() => edit(null)}>{t.sources.new}</button>
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
            <th scope="col">{t.kind}</th>
            <th scope="col">{t.sources.target}</th>
            <th scope="col">{t.sources.details}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            <tr>
              <td><strong>{x.name}</strong></td>
              <td>{x.tenant}</td>
              <td>{t.sources.kinds[x.kind] ?? x.kind}</td>
              {#if x.kind === 'linux'}
                <td>{t.sources.agent} <strong>{agentName(x.config?.agent_id)}</strong></td>
                <td class="mono" title={x.config?.excludes?.length ? `${t.sources.excludes}: ${x.config.excludes.join(' ')}` : undefined}
                  >{(x.config?.paths ?? []).join(' ')}</td
                >
              {:else}
                <td class="mono">{x.config?.host}:{x.config?.port}</td>
                <td class="mono">{x.config?.token_id}</td>
              {/if}
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

<Modal bind:open title={editing ? `${t.groups.source}: ${editing.name}` : t.sources.new} wide>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="s-kind">{t.sources.kind}</label>
        <select id="s-kind" bind:value={f.kind} disabled={!!editing} required>
          <option value="pve">{t.sources.kinds.pve}</option>
          <option value="linux">{t.sources.kinds.linux}</option>
        </select>
      </div>
      <div class="field">
        <label for="s-tenant">{t.tenant}</label>
        <select id="s-tenant" bind:value={f.tenant} disabled={!!editing} required>
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="s-name">{t.name}</label>
        <input id="s-name" bind:value={f.name} required />
      </div>
      {#if f.kind === 'linux'}
        <div class="field">
          <label for="s-agent">{t.sources.agent}</label>
          <select id="s-agent" bind:value={f.agent_id} 
            required
            aria-describedby={tenantAgents.length ? undefined : 's-agent-hint'}
          >
            {#each tenantAgents as a (a.id)}<option value={a.id}>{a.name} ({a.host})</option>{/each}
          </select>
          {#if !tenantAgents.length}<div class="hint" id="s-agent-hint">{t.sources.noAgents}</div>{/if}
        </div>
      {:else}
        <div class="field">
          <label for="s-host">{t.sources.host}</label>
          <input id="s-host" bind:value={f.host} required />
        </div>
        <div class="field">
          <label for="s-port">{t.sources.port}</label>
          <input id="s-port" type="number" min="1" max="65535" bind:value={f.port} required />
        </div>
        <div class="field">
          <label for="s-tid">{t.sources.tokenId}</label>
          <input id="s-tid" class="mono" bind:value={f.token_id} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="s-sec">{t.sources.tokenSecret}</label>
          <input
            id="s-sec"
            type="password"
            bind:value={f.token_secret}
            autocomplete="new-password"
            required={!editing}
            aria-describedby="s-sec-hint"
          />
          <div class="hint" id="s-sec-hint">
            {editing?.kind === 'pve' && editing.config?.token_secret_set ? t.writeOnlyKeep : t.writeOnlyHint}
          </div>
        </div>
        <div class="field">
          <label for="s-st">{t.sources.storage}</label>
          <input id="s-st" bind:value={f.storage} />
        </div>
        <div class="field">
          <label for="s-fl">{t.sources.fleecing}</label>
          <input id="s-fl" bind:value={f.fleecing_storage} />
        </div>
      {/if}
    </div>
    {#if f.kind === 'linux'}
      <div class="field">
        <label for="s-paths">{t.sources.paths}</label>
        <textarea
          id="s-paths"
          bind:value={f.paths}
          required
          spellcheck="false"
          placeholder={'/etc\n/home'}
          aria-describedby="s-paths-hint"
        ></textarea>
        <div class="hint" id="s-paths-hint">{t.sources.pathsHint}</div>
      </div>
      <div class="field">
        <label for="s-excl">{t.sources.excludes}</label>
        <textarea
          id="s-excl"
          bind:value={f.excludes}
          spellcheck="false"
          placeholder={'*.tmp\n/var/cache/**'}
          aria-describedby="s-excl-hint"
        ></textarea>
        <div class="hint" id="s-excl-hint">{t.sources.excludesHint}</div>
      </div>
      <div class="field">
        <label class="inline-check"
          ><input type="checkbox" bind:checked={f.hooks} aria-describedby="s-hooks-hint" />{t.sources.hooks}</label
        >
        <div class="hint" id="s-hooks-hint">{t.sources.hooksHint}</div>
      </div>
    {:else}
      <div class="field">
        <label for="s-ca">{t.sources.caPem}</label>
        <textarea id="s-ca" bind:value={f.ca_pem} spellcheck="false"></textarea>
      </div>
      <div class="field">
        <label for="s-nodes">{t.sources.nodes}</label>
        <textarea id="s-nodes" bind:value={f.nodes} spellcheck="false"></textarea>
      </div>
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={f.kind === 'linux' && !f.agent_id}>{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>
