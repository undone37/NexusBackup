<script lang="ts">
  // Phase 30: the second offsite target of a tenant (PUT /tenants/{name}/offsite2): a Storage Box or
  // an S3 bucket with its own retention (longer than local only) and its own lock. Setting it up
  // applies at once; changing or removing an existing one needs a second person.
  import { untrack } from 'svelte';
  import Modal from './Modal.svelte';
  import { put, act } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { t } from '../lib/i18n';
  import type { OffsiteGfs, S3Remote, SftpRemote, Tenant, TenantOffsite } from '../lib/types';

  let {
    open = $bindable(false),
    tenant,
    ondone,
  }: { open: boolean; tenant: Tenant | null; ondone: () => void } = $props();

  const CLASSES = ['daily', 'weekly', 'monthly', 'yearly'] as const;
  let kind: 'sftp' | 's3' = $state('s3');
  let sftp = $state({ host: '', port: 23, user: '', key_file: '', host_key: '', base_dir: '' });
  let s3 = $state({
    endpoint: '',
    region: '',
    bucket: '',
    prefix: '',
    access_key: '',
    secret_key: '',
    path_style: false,
    lock: true,
  });
  let secretSet = $state(false);
  let gfs: Record<string, string> = $state({ daily: '', weekly: '', monthly: '', yearly: '' });
  let uploaders = $state(2);
  let bwlimit = $state('');
  const existing = $derived(tenant?.offsite?.second ?? null);

  // fills the form when the dialog opens (reads only `open` and `tenant`)
  $effect(() => {
    if (open && tenant) untrack(() => fill(tenant!));
  });
  function fill(x: Tenant) {
    const o = x.offsite?.second;
    const r = o?.remote;
    kind = r?.type === 'sftp' ? 'sftp' : 's3';
    sftp = { host: '', port: 23, user: '', key_file: '', host_key: '', base_dir: '' };
    s3 = {
      endpoint: '',
      region: '',
      bucket: '',
      prefix: '',
      access_key: '',
      secret_key: '',
      path_style: false,
      lock: true,
    };
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
        lock: !!r.lock,
      };
      secretSet = !!r.secret_key_set;
    }
    gfs = Object.fromEntries(CLASSES.map((c) => [c, o?.gfs?.[c] == null ? '' : String(o.gfs[c])]));
    uploaders = o?.uploaders ?? 2;
    bwlimit = o?.bwlimit ? String(Math.round(o.bwlimit / 1024)) : '';
  }

  function target(): TenantOffsite {
    const own: OffsiteGfs = {};
    for (const c of CLASSES) if (gfs[c] !== '' && gfs[c] != null) own[c] = Number(gfs[c]);
    const common: TenantOffsite = {
      uploaders: Number(uploaders) || 1,
      bwlimit: bwlimit ? Number(bwlimit) * 1024 : null,
    };
    if (Object.keys(own).length) common.gfs = own;
    if (kind === 'sftp') {
      const r: SftpRemote = {
        type: 'sftp',
        host: sftp.host.trim(),
        port: Number(sftp.port) || 23,
        user: sftp.user.trim(),
        key_file: sftp.key_file.trim(),
        host_key: sftp.host_key.trim(),
      };
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
    if (s3.secret_key) r.secret_key = s3.secret_key;
    if (s3.prefix.trim()) r.prefix = s3.prefix.trim().replace(/^\/+|\/+$/g, '');
    return { remote: r, ...common };
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!tenant) return;
    if (await act(put(`/tenants/${encodeURIComponent(tenant.name)}/offsite2`, { target: target() }), t.saved)) {
      open = false;
      ondone();
    }
  }
  async function remove() {
    if (!tenant || !(await askConfirm(t.p30.second.removeConfirm(tenant.name)))) return;
    if (await act(put(`/tenants/${encodeURIComponent(tenant.name)}/offsite2`, { target: null }), t.saved)) {
      open = false;
      ondone();
    }
  }
</script>

<Modal bind:open title={tenant ? t.p30.second.title(tenant.name) : ''} wide>
  <form onsubmit={save}>
    <p class="muted">{t.p30.second.intro}</p>
    {#if existing}<p class="banner info">{t.p30.second.changeHint}</p>{/if}
    <div class="field">
      <label for="o2-kind">{t.tenants.target}</label>
      <select id="o2-kind" bind:value={kind}>
        {#each ['s3', 'sftp'] as k (k)}<option value={k}>{t.tenants.targets[k]}</option>{/each}
      </select>
    </div>
    {#if kind === 'sftp'}
      <div class="form-grid">
        <div class="field">
          <label for="o2-host">{t.tenants.host}</label><input id="o2-host" bind:value={sftp.host} required />
        </div>
        <div class="field">
          <label for="o2-port">{t.tenants.port}</label><input
            id="o2-port"
            type="number"
            min="1"
            max="65535"
            bind:value={sftp.port}
          />
        </div>
        <div class="field">
          <label for="o2-user">{t.tenants.user}</label><input id="o2-user" bind:value={sftp.user} required />
        </div>
        <div class="field">
          <label for="o2-dir">{t.tenants.baseDir}</label><input id="o2-dir" bind:value={sftp.base_dir} />
        </div>
      </div>
      <div class="field">
        <label for="o2-hk">{t.tenants.hostKey}</label><input
          id="o2-hk"
          class="mono"
          bind:value={sftp.host_key}
          spellcheck="false"
          required
        />
      </div>
      <div class="field">
        <label for="o2-key">{t.tenants.keyFile}</label>
        <input
          id="o2-key"
          class="mono"
          bind:value={sftp.key_file}
          spellcheck="false"
          required
          aria-describedby="o2-key-hint"
        />
        <div class="hint" id="o2-key-hint">{t.tenants.keyFileHint}</div>
      </div>
    {:else}
      <div class="form-grid">
        <div class="field">
          <label for="o2-ep">{t.tenants.endpoint}</label>
          <input
            id="o2-ep"
            class="mono"
            bind:value={s3.endpoint}
            required
            pattern="https://[^/?#@ ]+/?"
            spellcheck="false"
          />
        </div>
        <div class="field">
          <label for="o2-region">{t.tenants.region}</label><input
            id="o2-region"
            bind:value={s3.region}
            required
            pattern="[a-z0-9\-]+"
            maxlength="32"
          />
        </div>
        <div class="field">
          <label for="o2-bucket">{t.tenants.bucket}</label>
          <input
            id="o2-bucket"
            class="mono"
            bind:value={s3.bucket}
            required
            pattern="[a-z0-9][a-z0-9.\-]{'{'}1,61{'}'}[a-z0-9]"
          />
        </div>
        <div class="field">
          <label for="o2-prefix">{t.tenants.prefix}</label><input
            id="o2-prefix"
            class="mono"
            bind:value={s3.prefix}
            spellcheck="false"
          />
        </div>
        <div class="field">
          <label for="o2-ak">{t.tenants.accessKey}</label>
          <input id="o2-ak" class="mono" bind:value={s3.access_key} required autocomplete="off" spellcheck="false" />
        </div>
        <div class="field">
          <label for="o2-sk">{t.tenants.secretKey}</label>
          <input
            id="o2-sk"
            type="password"
            bind:value={s3.secret_key}
            autocomplete="new-password"
            required={!secretSet}
            aria-describedby="o2-sk-hint"
          />
          <div class="hint" id="o2-sk-hint">{secretSet ? t.writeOnlyKeep : t.writeOnlyHint}</div>
        </div>
      </div>
      <div class="field">
        <label class="inline-check"><input type="checkbox" bind:checked={s3.path_style} />{t.tenants.pathStyle}</label>
      </div>
      <div class="field">
        <label class="inline-check"
          ><input type="checkbox" bind:checked={s3.lock} aria-describedby="o2-lock-hint" />{t.tenants.lock}</label
        >
        <div class="hint" id="o2-lock-hint">{t.tenants.lockHint}</div>
      </div>
    {/if}
    <fieldset>
      <legend>{t.p30.second.retention}</legend>
      <p class="hint">{t.p30.second.retentionHint}</p>
      <div class="form-grid">
        {#each CLASSES as c (c)}
          <div class="field">
            <label for="o2-gfs-{c}">{t.p30.second.classes[c]}</label>
            <input
              id="o2-gfs-{c}"
              type="number"
              min="0"
              max="10000"
              bind:value={gfs[c]}
              placeholder={t.p30.second.asLocal}
            />
          </div>
        {/each}
      </div>
    </fieldset>
    <div class="form-grid">
      <div class="field">
        <label for="o2-bw">{t.tenants.bwlimit}</label><input id="o2-bw" type="number" min="0" bind:value={bwlimit} />
      </div>
      <div class="field">
        <label for="o2-up">{t.tenants.uploaders}</label><input
          id="o2-up"
          type="number"
          min="1"
          max="8"
          bind:value={uploaders}
        />
      </div>
    </div>
    <div class="form-actions">
      {#if existing}<button type="button" class="danger" onclick={remove}>{t.p30.second.remove}</button>{/if}
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.save}</button>
    </div>
  </form>
</Modal>
