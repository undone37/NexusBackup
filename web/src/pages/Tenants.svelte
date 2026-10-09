<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { t } from '../lib/i18n';
  import type { Tenant, TenantOffsite } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let items: Tenant[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      items = await get<Tenant[]>('/tenants');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  let open = $state(false);
  let editing: Tenant | null = $state(null);
  let name = $state('');
  let off: TenantOffsite = $state({});
  let bwlimit = $state('');

  function edit(x: Tenant | null) {
    editing = x;
    name = x?.name ?? '';
    off = { host: '', port: 23, user: '', key_file: '', host_key: '', base_dir: '', uploaders: 4, ...(x?.offsite ?? {}) };
    bwlimit = x?.offsite?.bwlimit ? String(x.offsite.bwlimit) : '';
    open = true;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    // The SSH key itself never goes through the API: the offsite config references a
    // key file on the appliance (the web-api refuses inline secrets in this blob).
    const offsite: TenantOffsite = {
      ...off,
      port: Number(off.port) || 23,
      uploaders: Number(off.uploaders) || 1,
      bwlimit: bwlimit ? Number(bwlimit) : null,
    };
    const r = editing
      ? await act(put(`/tenants/${encodeURIComponent(editing.name)}`, { offsite }), t.saved)
      : await act(post('/tenants', { name, offsite }), t.created);
    if (r) {
      open = false;
      load();
    }
  }

  async function remove(x: Tenant) {
    if (!confirm(t.confirmDelete(`${t.tenant} "${x.name}"`))) return;
    if (await act(del(`/tenants/${encodeURIComponent(x.name)}`), t.deleted)) load();
  }
</script>

<div class="page-head">
  <h1>{t.tenants.title}</h1>
  <button type="button" class="primary" onclick={() => edit(null)}>{t.tenants.new}</button>
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
            <th scope="col">{t.tenants.offsite}</th>
            <th scope="col">{t.tenants.uploaders}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.name)}
            <tr>
              <td><strong>{x.name}</strong></td>
              <td class="mono">
                {#if x.offsite?.host}{x.offsite.user}@{x.offsite.host}:{x.offsite.port ?? 23}{:else}—{/if}
              </td>
              <td>{x.offsite?.uploaders ?? '—'}</td>
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

<Modal bind:open title={editing ? `${t.tenant}: ${editing.name}` : t.tenants.new} wide>
  <form onsubmit={save}>
    {#if !editing}
      <div class="field">
        <label for="t-name">{t.name}</label>
        <input id="t-name" bind:value={name} required pattern="[a-z0-9][a-z0-9\-]*" maxlength="32" />
      </div>
    {/if}
    <fieldset>
      <legend>{t.tenants.offsite}</legend>
      <div class="form-grid">
        <div class="field">
          <label for="t-host">{t.tenants.host}</label>
          <input id="t-host" bind:value={off.host} />
        </div>
        <div class="field">
          <label for="t-port">{t.tenants.port}</label>
          <input id="t-port" type="number" min="1" max="65535" bind:value={off.port} />
        </div>
        <div class="field">
          <label for="t-user">{t.tenants.user}</label>
          <input id="t-user" bind:value={off.user} />
        </div>
        <div class="field">
          <label for="t-dir">{t.tenants.baseDir}</label>
          <input id="t-dir" bind:value={off.base_dir} />
        </div>
      </div>
      <div class="field">
        <label for="t-hk">{t.tenants.hostKey}</label>
        <input id="t-hk" class="mono" bind:value={off.host_key} spellcheck="false" />
      </div>
      <div class="form-grid">
        <div class="field">
          <label for="t-bw">{t.tenants.bwlimit}</label>
          <input id="t-bw" type="number" min="0" bind:value={bwlimit} />
        </div>
        <div class="field">
          <label for="t-up">{t.tenants.uploaders}</label>
          <input id="t-up" type="number" min="1" max="8" bind:value={off.uploaders} />
        </div>
      </div>
      <div class="field">
        <label for="t-key">{t.tenants.keyFile}</label>
        <input id="t-key" class="mono" bind:value={off.key_file} spellcheck="false" aria-describedby="t-key-hint" />
        <div class="hint" id="t-key-hint">{t.tenants.keyFileHint}</div>
      </div>
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>
