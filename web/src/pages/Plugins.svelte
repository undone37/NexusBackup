<script lang="ts">
  import { rowClick } from '../lib/rowlink';
  // Plugin platform (docs/plugin-system.md): installed plugins per id/version, signed
  // uploads (four-eyes), lifecycle actions and the publisher keys signatures are checked against.
  import { onMount } from 'svelte';
  import { href } from '../lib/router.svelte';
  import { askConfirm } from '../lib/confirm.svelte';
  import { get, post, postRaw, del, act, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { cmpVersion } from '../lib/plugins';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Plugin, PluginKey, PluginUpload } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import Check from '../components/Check.svelte';

  const MAX_BUNDLE = 128 << 20;

  let plugins: Plugin[] = $state([]);
  let keys: PluginKey[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  const admin = $derived(can.configure(session.user));

  async function load() {
    try {
      [plugins, keys] = await Promise.all([get<Plugin[]>('/plugins'), get<PluginKey[]>('/plugin-keys')]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  /** One block per plugin id, newest version first; blocks sorted by name. */
  const byId = $derived.by(() => {
    const m = new Map<string, Plugin[]>();
    for (const p of plugins) m.set(p.id, [...(m.get(p.id) ?? []), p]);
    return [...m.entries()]
      .map(([id, vs]) => {
        const versions = vs.sort((a, b) => cmpVersion(b.version, a.version));
        const current = versions.find((v) => v.current) ?? null;
        return { id, name: (current ?? versions[0]).name, current, versions };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  });

  const stateCls: Record<string, string> = {
    pending: 'warn',
    approved: 'info',
    installed: 'ok',
    failed: 'bad',
    rejected: 'bad',
    removing: 'warn',
    removed: '',
  };
  const short = (h: string) => (h ? `${h.slice(0, 12)}…` : '—');

  // ---- details
  let detail: { p: Plugin; upgradeFrom?: string | null; quorumId?: number } | null = $state(null);
  let detailOpen = $state(false);
  function showDetails(p: Plugin, upgradeFrom?: string | null, quorumId?: number) {
    detail = { p, upgradeFrom, quorumId };
    detailOpen = true;
  }

  // ---- install
  let installOpen = $state(false);
  let bundle: File | null = $state(null);
  let sig = $state('');
  let uploading = $state(false);
  const sigClean = $derived(sig.replace(/\s+/g, ''));
  const sigOk = $derived(/^[A-Za-z0-9+/_-]+=*$/.test(sigClean));

  function newInstall() {
    bundle = null;
    sig = '';
    installOpen = true;
  }
  function pickBundle(e: Event) {
    bundle = (e.currentTarget as HTMLInputElement).files?.[0] ?? null;
  }
  async function pickSig(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    if (f) sig = (await f.text()).trim();
  }

  async function upload(e: SubmitEvent) {
    e.preventDefault();
    if (!bundle) return;
    if (bundle.size > MAX_BUNDLE) {
      notify('error', t.plugins.tooLarge);
      return;
    }
    if (!sigOk) {
      notify('error', t.plugins.signatureInvalid);
      return;
    }
    uploading = true;
    const r = await act(
      postRaw<PluginUpload>('/plugins', bundle, {
        'Content-Type': 'application/octet-stream',
        'X-Plugin-Signature': sigClean,
      }),
      t.plugins.uploaded,
    );
    uploading = false;
    if (!r) return;
    installOpen = false;
    const d = r.data as Partial<PluginUpload>;
    if (d.plugin) showDetails(d.plugin, d.upgrade_from ?? null, r.quorum ? r.quorumId : d.quorum_id);
    load();
  }

  // ---- lifecycle
  async function enable(p: Plugin) {
    if (await act(post<Plugin>(`/plugins/${encodeURIComponent(p.id)}/enable`), t.plugins.enabledOk)) load();
  }
  async function disable(p: Plugin) {
    if (!(await askConfirm(t.plugins.disableConfirm(p.name)))) return;
    if (await act(post(`/plugins/${encodeURIComponent(p.id)}/disable`), t.saved)) load();
  }
  async function activate(p: Plugin) {
    if (!(await askConfirm(t.plugins.activateConfirm(p.name, p.version)))) return;
    if (await act(post(`/plugins/${encodeURIComponent(p.id)}/activate`, { version: p.version }), t.saved)) load();
  }
  async function remove(id: string, name: string) {
    if (!(await askConfirm(t.confirmDelete(t.plugins.removeWhat(name))))) return;
    if (await act(del(`/plugins/${encodeURIComponent(id)}`), t.deleted)) load();
  }

  // ---- publisher keys
  let keyOpen = $state(false);
  let kf = $state({ publisher: '', public_key: '' });
  function newKey() {
    kf = { publisher: '', public_key: '' };
    keyOpen = true;
  }
  async function saveKey(e: SubmitEvent) {
    e.preventDefault();
    const body = { publisher: kf.publisher.trim(), public_key: kf.public_key.trim() + '\n' };
    if (await act(post('/plugin-keys', body), t.created)) {
      keyOpen = false;
      load();
    }
  }
  async function removeKey(k: PluginKey) {
    if (!(await askConfirm(t.confirmDelete(t.plugins.removeKeyWhat(k.publisher, short(k.fingerprint)))))) return;
    if (await act(del(`/plugin-keys/${encodeURIComponent(k.fingerprint)}`), t.deleted)) load();
  }
</script>

{#snippet details(p: Plugin, upgradeFrom: string | null | undefined)}
  <dl class="kv">
    <dt>{t.plugins.publisher}</dt>
    <dd><strong>{p.publisher}</strong></dd>
    <dt>{t.plugins.signer}</dt>
    <dd class="mono">{p.signer || '—'}</dd>
    <dt>{t.plugins.version}</dt>
    <dd>{p.version} <span class="chip {stateCls[p.state] ?? ''}">{t.plugins.states[p.state] ?? p.state}</span></dd>
    {#if upgradeFrom !== undefined}
      <dt>{t.plugins.upgradeFrom}</dt>
      <dd>{upgradeFrom ?? t.plugins.newInstall}</dd>
    {/if}
    <dt>{t.plugins.sha256}</dt>
    <dd class="mono">{p.sha256}</dd>
    <dt>{t.plugins.binSha256}</dt>
    <dd class="mono">{p.bin_sha256}</dd>
    <dt>{t.plugins.size}</dt>
    <dd>{fmtBytes(p.size)}</dd>
    <dt>{t.plugins.api}</dt>
    <dd>{p.manifest?.api ?? '—'}</dd>
    <dt>{t.plugins.sandbox}</dt>
    <dd>{t.plugins.sandboxText(p.manifest?.sandbox ?? {})}</dd>
    <dt>{t.plugins.uploadedBy}</dt>
    <dd>{p.uploaded_by} · {fmtTime(p.uploaded_at)}</dd>
    {#if p.installed_at}
      <dt>{t.plugins.installedAt}</dt>
      <dd>{fmtTime(p.installed_at)}</dd>
    {/if}
    {#if p.error}
      <dt>{t.plugins.error}</dt>
      <dd><span class="chip bad">{p.error}</span></dd>
    {/if}
  </dl>
  <h3>{t.plugins.kinds}</h3>
  {#each p.manifest?.kinds ?? [] as k (k.kind)}
    <section class="card">
      <h4>{k.title} <span class="muted mono">plugin:{k.kind}</span></h4>
      <dl class="kv">
        <dt>{t.plugins.endpoints}</dt>
        <dd class="mono">
          {#each k.endpoints ?? [] as ep, i (i)}
            <div>{ep.proto ?? 'tcp'} {ep.host}{ep.port ? `:${ep.port}` : ''}{ep.default_port ? ` (${ep.default_port})` : ''}{ep.default_host ? ` — ${t.plugins.defaultHost(ep.default_host)}` : ''}</div>
          {:else}{t.plugins.noEndpoints}{/each}
        </dd>
        <dt>{t.plugins.guests}</dt>
        <dd>{k.guests?.list ? k.guests.title : '—'}</dd>
        <dt>{t.plugins.restores}</dt>
        <dd>
          {#each k.restores ?? [] as r (r.id)}
            <div>
              {r.title} <span class="muted mono">{r.id}</span>
              {#if r.app_specific}<span class="chip info">{t.snap.appSpecific}</span>{/if}
            </div>
          {/each}
        </dd>
        {#if k.secret_fields?.length}
          <dt>{t.writeOnlyHint}</dt>
          <dd class="mono">{k.secret_fields.join(', ')}</dd>
        {/if}
      </dl>
    </section>
  {/each}
{/snippet}

<div class="page-head">
  <h1>{t.plugins.title}</h1>
  {#if admin}<button type="button" class="primary" onclick={newInstall}>{t.plugins.install}</button>{/if}
  <p class="lede">{t.plugins.intro}</p>
</div>
{#if !admin}<p class="banner info">{t.plugins.readOnly}</p>{/if}
<ErrorBanner {error} />

{#if !loaded}
  <div class="card"><p class="muted" aria-busy="true">{t.loading}</p></div>
{:else if byId.length === 0}
  <div class="card"><p class="empty">{t.none}</p></div>
{:else}
  {#each byId as g (g.id)}
    <section class="card" aria-labelledby="pl-{g.id}">
      <div class="page-head">
        <h2 id="pl-{g.id}">
          {g.name} <span class="muted mono">{g.id}</span>
          {#if g.current}
            <span class="chip {g.current.enabled ? 'ok' : 'warn'}"
              >{g.current.version} · {g.current.enabled ? t.plugins.enabled : t.plugins.disabled}</span
            >
          {/if}
        </h2>
        {#if admin}
          <div class="row">
            {#if g.current?.state === 'installed'}
              {#if g.current.enabled}
                <button type="button" class="small" onclick={() => disable(g.current!)}>{t.plugins.disable}</button>
              {:else}
                <button type="button" class="small" onclick={() => enable(g.current!)}>{t.plugins.enable}</button>
              {/if}
            {/if}
            {#if g.versions.some((v) => v.state === 'installed')}
              <button type="button" class="small danger" onclick={() => remove(g.id, g.name)}>{t.delete}</button>
            {/if}
          </div>
        {/if}
      </div>
      {#if g.current}
        <p class="muted">
          {t.plugins.kinds}: {(g.current.manifest?.kinds ?? []).map((k) => k.title).join(', ') || '—'}
        </p>
      {/if}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.plugins.version}</th>
              <th scope="col">{t.state}</th>
              <th scope="col">{t.plugins.current}</th>
              <th scope="col">{t.plugins.enabled}</th>
              <th scope="col">{t.plugins.publisher}</th>
              <th scope="col">{t.plugins.signer}</th>
              <th scope="col">{t.plugins.sha256}</th>
              <th scope="col" class="num">{t.plugins.size}</th>
              <th scope="col">{t.plugins.uploadedBy}</th>
              <th scope="col">{t.plugins.installedAt}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each g.versions as v (v.version)}
              <tr use:rowClick={() => showDetails(v)}>
                <td><strong>{v.version}</strong></td>
                <td>
                  <span class="chip {stateCls[v.state] ?? ''}">{t.plugins.states[v.state] ?? v.state}</span>
                  {#if v.quorum_id && (v.state === 'pending' || v.state === 'removing')}
                    <div class="muted"><a href={href(`/quorum?id=${v.quorum_id}`)}>{t.plugins.pendingQuorum(v.quorum_id)}</a></div>
                  {/if}
                  {#if v.error}<div class="chip bad" title={v.error}>{v.error.slice(0, 80)}</div>{/if}
                </td>
                <td><Check on={v.current} /></td>
                <td><Check on={v.current && v.enabled} /></td>
                <td>{v.publisher}</td>
                <td class="mono">{v.signer || '—'}</td>
                <td class="mono" title={v.sha256}>{short(v.sha256)}</td>
                <td class="num">{fmtBytes(v.size)}</td>
                <td class="nowrap">{v.uploaded_by}<div class="muted">{fmtTime(v.uploaded_at)}</div></td>
                <td class="nowrap">{fmtTime(v.installed_at)}</td>
                <td class="actions">
                  <button type="button" class="small" onclick={() => showDetails(v)}>{t.plugins.details}</button>
                  {#if admin && v.state === 'installed' && !v.current}
                    <button type="button" class="small" onclick={() => activate(v)}>{t.plugins.activate}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/each}
{/if}

<section class="card" aria-labelledby="pk-head">
  <div class="page-head">
    <h2 id="pk-head">{t.plugins.keys}</h2>
    {#if admin}<button type="button" class="primary" onclick={newKey}>{t.plugins.addKey}</button>{/if}
  </div>
  <p class="muted">{t.plugins.keysIntro}</p>
  {#if loaded && keys.length === 0}
    <p class="empty">{t.none}</p>
  {:else if loaded}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.plugins.publisher}</th>
            <th scope="col">{t.plugins.fingerprint}</th>
            <th scope="col">{t.plugins.keyName}</th>
            <th scope="col">{t.plugins.addedBy}</th>
            <th scope="col">{t.plugins.approvedBy}</th>
            {#if admin}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each keys as k (k.fingerprint)}
            <tr>
              <td><strong>{k.publisher}</strong></td>
              <td class="mono" title={k.public_key}>{k.fingerprint}</td>
              <td>
                {#if k.builtin}<span class="chip info">{t.plugins.builtin}</span>{/if}
                {#if k.name}<span class="mono">{k.name}</span>{/if}
              </td>
              <td>{#if k.added_by}{k.added_by}<div class="muted">{fmtTime(k.added_at)}</div>{:else}—{/if}</td>
              <td>{k.approved_by ?? '—'}</td>
              {#if admin}
                <td class="actions">
                  {#if !k.builtin}
                    <button type="button" class="small danger" onclick={() => removeKey(k)}>{t.delete}</button>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<Modal bind:open={installOpen} title={t.plugins.install} wide>
  <form onsubmit={upload}>
    <p class="muted">{t.plugins.installIntro}</p>
    <div class="form-grid">
      <div class="field">
        <label for="pi-bundle">{t.plugins.bundle}</label>
        <input id="pi-bundle" type="file" accept=".nxplugin,application/octet-stream" onchange={pickBundle} required />
      </div>
      <div class="field">
        <label for="pi-sigfile">{t.plugins.signature}</label>
        <input id="pi-sigfile" type="file" accept=".sig,.b64,text/plain" onchange={pickSig} />
      </div>
    </div>
    <div class="field">
      <label for="pi-sig">{t.plugins.signatureText}</label>
      <textarea
        id="pi-sig"
        bind:value={sig}
        required
        spellcheck="false"
        autocomplete="off"
        aria-invalid={sig !== '' && !sigOk}
        aria-describedby="pi-sig-hint"
      ></textarea>
      <div class="hint" class:bad={sig !== '' && !sigOk} id="pi-sig-hint">
        {sig !== '' && !sigOk ? t.plugins.signatureInvalid : t.plugins.signatureHint}
      </div>
    </div>
    {#if bundle}<p class="muted mono">{bundle.name} · {fmtBytes(bundle.size)}</p>{/if}
    <div class="form-actions">
      <button type="button" onclick={() => (installOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={!bundle || !sigOk || uploading}
        >{uploading ? t.plugins.uploading : t.plugins.upload}</button
      >
    </div>
  </form>
</Modal>

<Modal bind:open={detailOpen} title={detail ? t.plugins.detailsTitle(detail.p.name, detail.p.version) : ''} wide>
  {#if detail}
    {#if detail.quorumId}
      <p class="banner ok">{t.plugins.uploaded}</p>
      <p class="banner pending" role="status">{t.plugins.waiting(detail.quorumId)}</p>
    {/if}
    {@render details(detail.p, detail.upgradeFrom)}
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (detailOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<Modal bind:open={keyOpen} title={t.plugins.addKey} wide>
  <form onsubmit={saveKey}>
    <div class="field">
      <label for="pk-pub">{t.plugins.publisher}</label>
      <input
        id="pk-pub"
        class="mono"
        bind:value={kf.publisher}
        required
        maxlength="64"
        autocomplete="off"
        spellcheck="false"
        aria-describedby="pk-pub-hint"
      />
      <div class="hint" id="pk-pub-hint">{t.plugins.publisherHint}</div>
    </div>
    <div class="field">
      <label for="pk-key">{t.plugins.publicKey}</label>
      <textarea
        id="pk-key"
        class="mono"
        bind:value={kf.public_key}
        required
        spellcheck="false"
        placeholder={'-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----'}
        aria-describedby="pk-key-hint"
      ></textarea>
      <div class="hint" id="pk-key-hint">{t.plugins.publicKeyHint}</div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (keyOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.create}</button>
    </div>
  </form>
</Modal>
