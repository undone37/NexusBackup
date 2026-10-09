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
    // truenas
    connect_addr: '',
    tn_user: 'nexusbackup',
    ssh_host: '',
    ssh_port: 22,
    ssh_user: 'nexusbackup',
    host_key: '',
    key_pem: '',
    public_key: '',
    from: '',
    datasets: '',
    recursive: false,
    sudo: true,
    zfs_sudo: true,
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
    const n = x?.kind === 'truenas' ? x.config : undefined;
    f = {
      kind: x?.kind ?? 'pve',
      tenant: x?.tenant ?? tenants[0]?.name ?? '',
      name: x?.name ?? '',
      host: c?.host ?? n?.host ?? '',
      port: c?.port ?? n?.port ?? 8006,
      ca_pem: c?.ca_pem ?? n?.ca_pem ?? '',
      token_id: c?.token_id ?? '',
      token_secret: '',
      nodes: JSON.stringify(c?.nodes ?? {}, null, 2),
      storage: c?.storage ?? '',
      fleecing_storage: c?.fleecing_storage ?? '',
      agent_id: l?.agent_id ?? '',
      paths: (l?.paths ?? []).join('\n'),
      excludes: (l?.excludes ?? []).join('\n'),
      hooks: l?.hooks ?? false,
      connect_addr: n?.connect_addr ?? '',
      tn_user: n?.user ?? 'nexusbackup',
      ssh_host: n?.ssh.host ?? '',
      ssh_port: n?.ssh.port ?? 22,
      ssh_user: n?.ssh.user ?? 'nexusbackup',
      host_key: n?.ssh.host_key ?? '',
      key_pem: '',
      public_key: n?.ssh.public_key ?? '',
      from: n?.ssh.from ?? '',
      datasets: (n?.datasets ?? []).join('\n'),
      recursive: n?.recursive ?? false,
      sudo: n?.sudo ?? true,
      zfs_sudo: n?.zfs_sudo ?? true,
    };
    open = true;
  }

  // New TrueNAS sources default to the HTTPS port.
  $effect(() => {
    if (open && !editing && f.kind === 'truenas' && f.port === 8006) f.port = 443;
  });

  /** Config of a truenas source, or null (after telling the user) when invalid. */
  function truenasConfig(): Record<string, unknown> | null {
    const datasets = lines(f.datasets);
    if (!datasets.length || datasets.length > 64) {
      notify('error', t.sources.tn.datasetsInvalid);
      return null;
    }
    const ssh: Record<string, unknown> = {
      host: f.ssh_host || f.host,
      port: Number(f.ssh_port),
      user: f.ssh_user,
      host_key: f.host_key.trim(),
    };
    if (f.public_key.trim()) ssh.public_key = f.public_key.trim();
    if (f.from.trim()) ssh.from = f.from.trim();
    // Write-only secrets: only sent when entered.
    if (f.key_pem.trim()) ssh.key_pem = f.key_pem.trim() + '\n';
    const config: Record<string, unknown> = {
      host: f.host,
      port: Number(f.port),
      ca_pem: f.ca_pem,
      user: f.tn_user,
      ssh,
      datasets,
      recursive: f.recursive,
      sudo: f.sudo,
      zfs_sudo: f.zfs_sudo,
    };
    if (f.connect_addr.trim()) config.connect_addr = f.connect_addr.trim();
    if (f.token_secret) config.token_secret = f.token_secret;
    return config;
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
    const config = f.kind === 'linux' ? linuxConfig() : f.kind === 'truenas' ? truenasConfig() : pveConfig();
    if (!config) return;
    const r = editing
      ? await act(put<Source>(`/sources/${editing.id}`, { name: f.name, config }), t.saved)
      : await act(post<Source>('/sources', { tenant: f.tenant, kind: f.kind, name: f.name, config }), t.created);
    if (r) {
      load();
      // TrueNAS: keep the dialog open with the authorized_keys line to paste on TrueNAS
      const s = r.data as Source;
      if (!r.quorum && s?.kind === 'truenas' && s.config?.authorized_keys) {
        edit(s);
        return;
      }
      open = false;
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
              {:else if x.kind === 'truenas'}
                <td class="mono">{x.config?.host}:{x.config?.port}</td>
                <td class="mono">{(x.config?.datasets ?? []).join(' ')}{x.config?.recursive ? ' (+)' : ''}</td>
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
          <option value="truenas">{t.sources.kinds.truenas}</option>
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
      {:else if f.kind === 'truenas'}
        <div class="field">
          <label for="t-host">{t.sources.tn.host}</label>
          <input id="t-host" bind:value={f.host} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-port">{t.sources.tn.port}</label>
          <input id="t-port" type="number" min="1" max="65535" bind:value={f.port} required />
        </div>
        <div class="field">
          <label for="t-ca">{t.sources.tn.connectAddr}</label>
          <input id="t-ca" class="mono" bind:value={f.connect_addr} spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-user">{t.sources.tn.user}</label>
          <input id="t-user" class="mono" bind:value={f.tn_user} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-key">{t.sources.tn.apiKey}</label>
          <input
            id="t-key"
            type="password"
            bind:value={f.token_secret}
            autocomplete="new-password"
            required={!editing}
            aria-describedby="t-key-hint"
          />
          <div class="hint" id="t-key-hint">
            {editing?.kind === 'truenas' && editing.config?.token_secret_set ? t.writeOnlyKeep : t.writeOnlyHint}
          </div>
        </div>
        <div class="field">
          <label for="t-sh">{t.sources.tn.sshHost}</label>
          <input id="t-sh" bind:value={f.ssh_host} placeholder={f.host} spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-sp">{t.sources.tn.sshPort}</label>
          <input id="t-sp" type="number" min="1" max="65535" bind:value={f.ssh_port} required />
        </div>
        <div class="field">
          <label for="t-su">{t.sources.tn.sshUser}</label>
          <input id="t-su" class="mono" bind:value={f.ssh_user} required spellcheck="false" />
        </div>
        <div class="field">
          <label for="t-from">{t.sources.tn.from}</label>
          <input id="t-from" class="mono" bind:value={f.from} spellcheck="false" />
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
    {:else if f.kind === 'truenas'}
      <div class="field">
        <label for="t-ds">{t.sources.tn.datasets}</label>
        <textarea
          id="t-ds"
          class="mono"
          bind:value={f.datasets}
          required
          spellcheck="false"
          placeholder={'tank/data\ntank/smb'}
          aria-describedby="t-ds-hint"
        ></textarea>
        <div class="hint" id="t-ds-hint">{t.sources.tn.datasetsHint}</div>
      </div>
      <div class="field">
        <label class="inline-check"><input type="checkbox" bind:checked={f.recursive} />{t.sources.tn.recursive}</label>
        <label class="inline-check"><input type="checkbox" bind:checked={f.sudo} />{t.sources.tn.sudo}</label>
        <label class="inline-check"><input type="checkbox" bind:checked={f.zfs_sudo} />{t.sources.tn.zfsSudo}</label>
      </div>
      <div class="field">
        <label for="t-cert">{t.sources.tn.cert}</label>
        <textarea id="t-cert" class="mono" bind:value={f.ca_pem} required spellcheck="false" aria-describedby="t-cert-hint"
        ></textarea>
        <div class="hint" id="t-cert-hint">{t.sources.tn.certHint}</div>
      </div>
      <div class="field">
        <label for="t-hk">{t.sources.tn.hostKey}</label>
        <input id="t-hk" class="mono" bind:value={f.host_key} required spellcheck="false" aria-describedby="t-hk-hint" />
        <div class="hint" id="t-hk-hint">{t.sources.tn.hostKeyHint}</div>
      </div>
      <div class="field">
        <label for="t-pem">{t.sources.tn.keyPem}</label>
        <textarea
          id="t-pem"
          class="mono"
          bind:value={f.key_pem}
          required={!editing}
          spellcheck="false"
          autocomplete="off"
          aria-describedby="t-pem-hint"
        ></textarea>
        <div class="hint" id="t-pem-hint">
          {editing?.kind === 'truenas' && editing.config?.ssh?.key_pem_set ? t.writeOnlyKeep : t.writeOnlyHint}
        </div>
      </div>
      <div class="field">
        <label for="t-pub">{t.sources.tn.publicKey}</label>
        <input id="t-pub" class="mono" bind:value={f.public_key} spellcheck="false" />
      </div>
      {#if editing?.kind === 'truenas' && editing.config?.authorized_keys}
        <div class="field">
          <label for="t-ak">{t.sources.tn.authorizedKeys}</label>
          <textarea id="t-ak" class="mono" readonly value={editing.config.authorized_keys} aria-describedby="t-ak-hint"
          ></textarea>
          <div class="hint" id="t-ak-hint">{t.sources.tn.authorizedKeysHint}</div>
        </div>
      {/if}
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
