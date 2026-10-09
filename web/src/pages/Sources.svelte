<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { t } from '../lib/i18n';
  import type { Source, Tenant } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let items: Source[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      [items, tenants] = await Promise.all([get<Source[]>('/sources'), get<Tenant[]>('/tenants')]);
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
  });

  function edit(x: Source | null) {
    editing = x;
    const c = x?.config;
    f = {
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
    };
    open = true;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    let nodes: Record<string, unknown>;
    try {
      nodes = JSON.parse(f.nodes || '{}');
    } catch {
      notify('error', `${t.err.invalidJson}: ${t.sources.nodes}`);
      return;
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
    const r = editing
      ? await act(put(`/sources/${editing.id}`, { name: f.name, config }), t.saved)
      : await act(post('/sources', { tenant: f.tenant, kind: 'pve', name: f.name, config }), t.created);
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
            <th scope="col">{t.sources.host}</th>
            <th scope="col">{t.sources.tokenId}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            <tr>
              <td><strong>{x.name}</strong></td>
              <td>{x.tenant}</td>
              <td>{x.kind}</td>
              <td class="mono">{x.config?.host}:{x.config?.port}</td>
              <td class="mono">{x.config?.token_id}</td>
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
        <label for="s-tenant">{t.tenant}</label>
        <select id="s-tenant" bind:value={f.tenant} disabled={!!editing} required>
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="s-name">{t.name}</label>
        <input id="s-name" bind:value={f.name} required />
      </div>
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
        <div class="hint" id="s-sec-hint">{editing?.config?.token_secret_set ? t.writeOnlyKeep : t.writeOnlyHint}</div>
      </div>
      <div class="field">
        <label for="s-st">{t.sources.storage}</label>
        <input id="s-st" bind:value={f.storage} />
      </div>
      <div class="field">
        <label for="s-fl">{t.sources.fleecing}</label>
        <input id="s-fl" bind:value={f.fleecing_storage} />
      </div>
    </div>
    <div class="field">
      <label for="s-ca">{t.sources.caPem}</label>
      <textarea id="s-ca" bind:value={f.ca_pem} spellcheck="false"></textarea>
    </div>
    <div class="field">
      <label for="s-nodes">{t.sources.nodes}</label>
      <textarea id="s-nodes" bind:value={f.nodes} spellcheck="false"></textarea>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>
