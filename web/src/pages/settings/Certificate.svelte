<script lang="ts">
  // Settings → Certificate (Phase 14d): the served chain, a CSR whose key never leaves the
  // appliance, importing the CA's answer (validated by nexus-tls) and reverting.
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { notify } from '../../lib/notify.svelte';
  import { session } from '../../lib/session.svelte';
  import { copyText } from '../../lib/clipboard';
  import { fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { CertInfo, CertStatus } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconCopy from '@lucide/svelte/icons/copy';
  import IconFile from '@lucide/svelte/icons/file-key';
  import IconUndo from '@lucide/svelte/icons/undo-2';

  const id = $props.id();
  const admin = $derived(session.user?.role === 'admin');
  let s: CertStatus | null = $state(null);
  let error: string | null = $state(null);
  let busy = $state(false);
  let f = $state({ cn: '', sans: '' });
  let chain = $state('');
  let warnings: string[] = $state([]);

  async function load() {
    try {
      s = await get<CertStatus>('/certificate');
      error = null;
      const base = s.pending ?? { cn: s.identity?.sans[0] ?? '', sans: s.identity?.sans ?? [] };
      if (!f.cn) f = { cn: base.cn, sans: base.sans.filter((x) => x !== base.cn).join('\n') };
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  const left = (c: CertInfo) => Math.floor((c.not_after - Date.now() / 1000) / 86400);
  const expiryCls = (c: CertInfo) => (left(c) < 7 ? 'bad' : left(c) < 30 ? 'warn' : left(c) < 90 ? 'info' : 'ok');

  async function csr(e: SubmitEvent) {
    e.preventDefault();
    if (s?.pending && !(await askConfirm(t.cert.replacePending))) return;
    busy = true;
    const sans = f.sans
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
    if (await act(post('/certificate/csr', { cn: f.cn.trim(), sans }), t.cert.csrDone)) await load();
    busy = false;
  }

  async function install(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    const r = await act(post<{ warnings: string[] }>('/certificate/install', { chain_pem: chain }), t.cert.installed);
    busy = false;
    if (!r || r.quorum) return;
    warnings = r.data.warnings ?? [];
    chain = '';
    await load();
  }

  async function revert() {
    if (!(await askConfirm(s?.previous ? t.cert.revertPrevConfirm : t.cert.revertSelfConfirm))) return;
    if (await act(post('/certificate/revert'), t.cert.reverted)) {
      warnings = [];
      await load();
    }
  }

  async function readFile(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    if (file.size > 65536) notify('error', t.cert.tooLarge);
    else chain = await file.text();
  }
</script>

<ErrorBanner {error} />
{#if !s}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  <div class="settings-section">
    <p class="intro muted">{t.cert.intro}</p>
    {#if !admin}<p class="banner info">{t.settings.readOnly}</p>{/if}

    <section class="card" aria-labelledby="{id}-cur">
      <div class="card-head">
        <h2 id="{id}-cur">{t.cert.current}</h2>
        <div class="row">
          <span class="chip {s.active === 'imported' ? 'ok' : 'warn'}">{t.cert.active[s.active]}</span>
          {#if admin && s.can_revert}
            <button type="button" class="small" onclick={revert}
              ><IconUndo aria-hidden="true" />{s.previous ? t.cert.revertPrev : t.cert.revertSelf}</button
            >
          {/if}
        </div>
      </div>
      {#each s.chain as c, i (c.sha256)}
        <div class="key-card cert">
          <h3>{i === 0 ? t.cert.leaf : c.self_signed ? t.cert.root : t.cert.intermediate}</h3>
          <dl class="kv-list">
            <dt>{t.cert.subject}</dt>
            <dd class="mono">{c.subject}</dd>
            <dt>{t.cert.issuer}</dt>
            <dd class="mono">{c.issuer}</dd>
            {#if i === 0}
              <dt>{t.cert.names}</dt>
              <dd class="mono">{c.sans.join(', ') || '—'}</dd>
            {/if}
            <dt>{t.cert.valid}</dt>
            <dd>
              {fmtTime(c.not_before)} – {fmtTime(c.not_after)}
              <span class="chip {expiryCls(c)}">{t.cert.daysLeft(left(c))}</span>
            </dd>
            <dt>{t.cert.fingerprint}</dt>
            <dd class="mono fp">{c.sha256}</dd>
          </dl>
        </div>
      {/each}
      <p class="banner info">{t.cert.pins(s.pins.replication_peers)}</p>
      {#if s.active === 'imported' && s.identity}
        <p class="muted">{t.cert.identity} <code class="fp">{s.identity.sha256}</code></p>
      {/if}
    </section>

    {#if admin}
      <form class="card" aria-labelledby="{id}-csr" onsubmit={csr}>
        <div class="card-head"><h2 id="{id}-csr">{t.cert.step1}</h2></div>
        <p class="muted">{t.cert.csrIntro}</p>
        <div class="field">
          <label for="{id}-cn">{t.cert.cn}</label>
          <input
            id="{id}-cn"
            class="mono"
            bind:value={f.cn}
            required
            maxlength="253"
            autocomplete="off"
            spellcheck="false"
          />
        </div>
        <div class="field">
          <label for="{id}-sans">{t.cert.sans}</label>
          <textarea
            id="{id}-sans"
            class="mono"
            rows="3"
            bind:value={f.sans}
            spellcheck="false"
            aria-describedby="{id}-sans-hint"></textarea>
          <div class="hint" id="{id}-sans-hint">{t.cert.sansHint}</div>
        </div>
        <div class="form-actions">
          <button type="submit" class="primary" disabled={busy}><IconFile aria-hidden="true" />{t.cert.generate}</button
          >
        </div>
        {#if s.pending}
          <div class="field">
            <span class="field-label" id="{id}-req"
              >{t.cert.pending(fmtTime(s.pending.created), s.pending.sans.join(', '))}</span
            >
            <textarea class="mono pem" rows="8" readonly aria-labelledby="{id}-req" value={s.pending.csr_pem ?? ''}
            ></textarea>
            <div class="row">
              <button type="button" class="small" onclick={() => copyText(s?.pending?.csr_pem ?? '')}
                ><IconCopy aria-hidden="true" />{t.users.copy}</button
              >
            </div>
          </div>
        {/if}
      </form>

      <form class="card" aria-labelledby="{id}-inst" onsubmit={install}>
        <div class="card-head"><h2 id="{id}-inst">{t.cert.step2}</h2></div>
        <p class="muted">{t.cert.installIntro}</p>
        {#if !s.pending}<p class="banner warn">{t.cert.noPending}</p>{/if}
        <div class="field">
          <label for="{id}-chain">{t.cert.chain}</label>
          <textarea
            id="{id}-chain"
            class="mono pem"
            rows="8"
            bind:value={chain}
            required
            disabled={!s.pending}
            placeholder="-----BEGIN CERTIFICATE-----"
            spellcheck="false"></textarea>
        </div>
        {#if s.pending}
          <label class="button small file-btn"
            >{t.cert.fromFile}<input
              type="file"
              accept=".pem,.crt,.cer,text/plain"
              onchange={readFile}
              class="visually-hidden"
            /></label
          >
        {/if}
        {#each warnings as w (w)}<p class="banner warn">{w}</p>{/each}
        <div class="form-actions">
          <button type="submit" class="primary" disabled={busy || !s.pending}>{t.cert.install}</button>
        </div>
      </form>
    {/if}
  </div>
{/if}

<style>
  .cert h3 {
    margin: 0 0 0.4rem;
    font-size: 0.9rem;
  }
  .cert + .cert {
    margin-top: 0.75rem;
  }
  .fp {
    word-break: break-all;
    font-size: 0.82em;
  }
  .file-btn {
    width: fit-content;
  }
  .pem {
    width: 100%;
    font-size: 0.8rem;
  }
</style>
