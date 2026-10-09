<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { t } from '../lib/i18n';
  import type { Tenant, TenantOffsite, SftpRemote, S3Remote } from '../lib/types';
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

  /** The remote of a tenant; older UI versions stored the SFTP fields flat. */
  function remoteOf(o: TenantOffsite | undefined): SftpRemote | S3Remote | null {
    if (o?.remote) return o.remote;
    if (o?.host) return { type: 'sftp', host: o.host, port: o.port, user: o.user ?? '', key_file: o.key_file ?? '', host_key: o.host_key ?? '', base_dir: o.base_dir };
    return null;
  }

  function summary(o: TenantOffsite | undefined): string {
    const r = remoteOf(o);
    if (!r) return '—';
    if (r.type === 'sftp') return `${r.user}@${r.host}:${r.port ?? 23}`;
    return `s3://${r.bucket}${r.prefix ? '/' + r.prefix : ''} @ ${r.endpoint.replace(/^https:\/\//, '')}`;
  }

  let open = $state(false);
  let editing: Tenant | null = $state(null);
  let name = $state('');
  let kind: 'none' | 'sftp' | 's3' = $state('none');
  let sftp = $state({ host: '', port: 23, user: '', key_file: '', host_key: '', base_dir: '' });
  let s3 = $state({
    endpoint: '',
    region: '',
    bucket: '',
    prefix: '',
    access_key: '',
    secret_key: '',
    path_style: false,
    ca_pem: '',
    storage_class_packs: '',
    storage_class_meta: '',
    lock: true,
  });
  let secretSet = $state(false);
  let uploaders = $state(4);
  let bwlimit = $state('');

  function edit(x: Tenant | null) {
    editing = x;
    name = x?.name ?? '';
    const r = remoteOf(x?.offsite);
    kind = r?.type ?? 'none';
    sftp = { host: '', port: 23, user: '', key_file: '', host_key: '', base_dir: '' };
    s3 = { endpoint: '', region: '', bucket: '', prefix: '', access_key: '', secret_key: '', path_style: false, ca_pem: '', storage_class_packs: '', storage_class_meta: '', lock: true };
    secretSet = false;
    if (r?.type === 'sftp') sftp = { ...sftp, ...r, port: r.port ?? 23, base_dir: r.base_dir ?? '' };
    if (r?.type === 's3') {
      s3 = {
        ...s3,
        endpoint: r.endpoint,
        region: r.region,
        bucket: r.bucket,
        prefix: r.prefix ?? '',
        access_key: r.access_key,
        path_style: !!r.path_style,
        ca_pem: r.ca_pem ?? '',
        storage_class_packs: r.storage_class_packs ?? '',
        storage_class_meta: r.storage_class_meta ?? '',
        lock: !!r.lock,
      };
      secretSet = !!r.secret_key_set;
    }
    uploaders = x?.offsite?.uploaders ?? 4;
    bwlimit = x?.offsite?.bwlimit ? String(Math.round(x.offsite.bwlimit / 1024)) : '';
    open = true;
  }

  function offsite(): TenantOffsite {
    if (kind === 'none') return {};
    const common = { uploaders: Number(uploaders) || 1, bwlimit: bwlimit ? Number(bwlimit) * 1024 : null };
    if (kind === 'sftp') {
      // The SSH key never goes through the API: the config references a key file on the appliance.
      const r: SftpRemote = { type: 'sftp', host: sftp.host.trim(), port: Number(sftp.port) || 23, user: sftp.user.trim(), key_file: sftp.key_file.trim(), host_key: sftp.host_key.trim() };
      if (sftp.base_dir.trim()) r.base_dir = sftp.base_dir.trim();
      return { remote: r, ...common };
    }
    const r: S3Remote = {
      type: 's3',
      endpoint: s3.endpoint.trim(),
      region: s3.region.trim(),
      bucket: s3.bucket.trim(),
      access_key: s3.access_key.trim(),
      path_style: s3.path_style,
      lock: s3.lock,
    };
    // write-only: omitted = keep the stored key (only for an unchanged endpoint/bucket/key id)
    if (s3.secret_key) r.secret_key = s3.secret_key;
    if (s3.prefix.trim()) r.prefix = s3.prefix.trim().replace(/^\/+|\/+$/g, '');
    if (s3.ca_pem.trim()) r.ca_pem = s3.ca_pem.trim() + '\n';
    if (s3.storage_class_packs.trim()) r.storage_class_packs = s3.storage_class_packs.trim();
    if (s3.storage_class_meta.trim()) r.storage_class_meta = s3.storage_class_meta.trim();
    return { remote: r, ...common };
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const o = offsite();
    const r = editing
      ? await act(put(`/tenants/${encodeURIComponent(editing.name)}`, { offsite: o }), t.saved)
      : await act(post('/tenants', { name, offsite: o }), t.created);
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
            {@const r = remoteOf(x.offsite)}
            <tr>
              <td><strong>{x.name}</strong></td>
              <td class="mono">
                {summary(x.offsite)}
                {#if r?.type === 's3' && r.lock}<span class="chip ok">{t.tenants.locked}</span>{/if}
              </td>
              <td>{r ? (x.offsite?.uploaders ?? 4) : '—'}</td>
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
      <div class="field">
        <label for="t-kind">{t.tenants.target}</label>
        <select id="t-kind" bind:value={kind}>
          {#each ['none', 'sftp', 's3'] as k (k)}<option value={k}>{t.tenants.targets[k]}</option>{/each}
        </select>
      </div>
      {#if kind === 'sftp'}
        <div class="form-grid">
          <div class="field">
            <label for="t-host">{t.tenants.host}</label>
            <input id="t-host" bind:value={sftp.host} required />
          </div>
          <div class="field">
            <label for="t-port">{t.tenants.port}</label>
            <input id="t-port" type="number" min="1" max="65535" bind:value={sftp.port} />
          </div>
          <div class="field">
            <label for="t-user">{t.tenants.user}</label>
            <input id="t-user" bind:value={sftp.user} required />
          </div>
          <div class="field">
            <label for="t-dir">{t.tenants.baseDir}</label>
            <input id="t-dir" bind:value={sftp.base_dir} />
          </div>
        </div>
        <div class="field">
          <label for="t-hk">{t.tenants.hostKey}</label>
          <input id="t-hk" class="mono" bind:value={sftp.host_key} spellcheck="false" required />
        </div>
        <div class="field">
          <label for="t-key">{t.tenants.keyFile}</label>
          <input id="t-key" class="mono" bind:value={sftp.key_file} spellcheck="false" required aria-describedby="t-key-hint" />
          <div class="hint" id="t-key-hint">{t.tenants.keyFileHint}</div>
        </div>
      {:else if kind === 's3'}
        <div class="form-grid">
          <div class="field">
            <label for="t-ep">{t.tenants.endpoint}</label>
            <input id="t-ep" class="mono" bind:value={s3.endpoint} required pattern="https://[^/?#@ ]+/?" spellcheck="false" placeholder="https://fsn1.your-objectstorage.com" />
          </div>
          <div class="field">
            <label for="t-region">{t.tenants.region}</label>
            <input id="t-region" bind:value={s3.region} required pattern="[a-z0-9\-]+" maxlength="32" placeholder="fsn1" />
          </div>
          <div class="field">
            <label for="t-bucket">{t.tenants.bucket}</label>
            <input id="t-bucket" class="mono" bind:value={s3.bucket} required pattern="[a-z0-9][a-z0-9.\-]{'{'}1,61{'}'}[a-z0-9]" />
          </div>
          <div class="field">
            <label for="t-prefix">{t.tenants.prefix}</label>
            <input id="t-prefix" class="mono" bind:value={s3.prefix} spellcheck="false" />
          </div>
          <div class="field">
            <label for="t-ak">{t.tenants.accessKey}</label>
            <input id="t-ak" class="mono" bind:value={s3.access_key} required autocomplete="off" spellcheck="false" />
          </div>
          <div class="field">
            <label for="t-sk">{t.tenants.secretKey}</label>
            <input
              id="t-sk"
              type="password"
              bind:value={s3.secret_key}
              autocomplete="new-password"
              required={!secretSet}
              aria-describedby="t-sk-hint"
            />
            <div class="hint" id="t-sk-hint">{secretSet ? t.writeOnlyKeep : t.writeOnlyHint}</div>
          </div>
          <div class="field">
            <label for="t-scp">{t.tenants.classPacks}</label>
            <input id="t-scp" class="mono" bind:value={s3.storage_class_packs} pattern="[A-Z_]+" placeholder="STANDARD_IA" aria-describedby="t-sc-hint" />
          </div>
          <div class="field">
            <label for="t-scm">{t.tenants.classMeta}</label>
            <input id="t-scm" class="mono" bind:value={s3.storage_class_meta} pattern="[A-Z_]+" placeholder="STANDARD" aria-describedby="t-sc-hint" />
          </div>
        </div>
        <div class="hint" id="t-sc-hint">{t.tenants.classHint}</div>
        <div class="field">
          <label class="inline-check"><input type="checkbox" bind:checked={s3.path_style} />{t.tenants.pathStyle}</label>
        </div>
        <div class="field">
          <label class="inline-check"><input type="checkbox" bind:checked={s3.lock} aria-describedby="t-lock-hint" />{t.tenants.lock}</label>
          <div class="hint" id="t-lock-hint">{t.tenants.lockHint}</div>
        </div>
        <div class="field">
          <label for="t-ca">{t.tenants.caPem}</label>
          <textarea id="t-ca" class="mono" bind:value={s3.ca_pem} spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" aria-describedby="t-ca-hint"></textarea>
          <div class="hint" id="t-ca-hint">{t.tenants.caPemHint}</div>
        </div>
      {/if}
      {#if kind !== 'none'}
        <div class="form-grid">
          <div class="field">
            <label for="t-bw">{t.tenants.bwlimit}</label>
            <input id="t-bw" type="number" min="0" bind:value={bwlimit} />
          </div>
          <div class="field">
            <label for="t-up">{t.tenants.uploaders}</label>
            <input id="t-up" type="number" min="1" max="8" bind:value={uploaders} />
          </div>
        </div>
      {/if}
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>
