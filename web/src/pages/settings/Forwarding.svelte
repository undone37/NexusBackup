<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, post, act, errText } from '../../lib/api';
  import { notify } from '../../lib/notify.svelte';
  import { session } from '../../lib/session.svelte';
  import { t } from '../../lib/i18n';
  import type { ForwardingSettings } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import TestResult from './TestResult.svelte';
  import IconSend from '@lucide/svelte/icons/send';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconX from '@lucide/svelte/icons/x';

  // Setting `forwarding` (Phase 14a): syslog over TLS and/or HTTPS JSON. Header values are write-only.
  type Header = { name: string; value: string; stored: boolean };
  const FACILITIES = Object.entries(t.settings.fw.facilities).map(([k, v]) => ({ k: Number(k), v }));
  const admin = $derived(session.user?.role === 'admin');
  let error: string | null = $state(null);
  let cur: ForwardingSettings | null = $state(null);
  let testing = $state(false);
  let result: Record<string, string> | null = $state(null);
  let f = $state({
    sOn: false,
    s: { enabled: true, host: '', port: 6514, ca_pem: '', pin_sha256: '', app_name: 'nexus', facility: 13 },
    hOn: false,
    h: {
      enabled: true,
      url: '',
      batch_max: 100,
      ca_pem: '',
      pin_sha256: '',
      format: 'json_array' as 'json_array' | 'splunk_hec',
      index: '',
    },
    headers: [] as Header[],
  });

  function fill(c: ForwardingSettings) {
    cur = c;
    f = {
      sOn: !!c.syslog,
      s: {
        enabled: c.syslog?.enabled ?? true,
        host: c.syslog?.host ?? '',
        port: c.syslog?.port ?? 6514,
        ca_pem: c.syslog?.ca_pem ?? '',
        pin_sha256: c.syslog?.pin_sha256 ?? '',
        app_name: c.syslog?.app_name ?? 'nexus',
        facility: c.syslog?.facility ?? 13,
      },
      hOn: !!c.https,
      h: {
        enabled: c.https?.enabled ?? true,
        url: c.https?.url ?? '',
        batch_max: c.https?.batch_max ?? 100,
        ca_pem: c.https?.ca_pem ?? '',
        pin_sha256: c.https?.pin_sha256 ?? '',
        format: c.https?.format ?? 'json_array',
        index: c.https?.index ?? '',
      },
      headers: Object.keys(c.https?.headers ?? {}).map((name) => ({ name, value: '', stored: true })),
    };
  }

  async function load() {
    try {
      fill(await get<ForwardingSettings>('/settings/forwarding'));
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  const opt = (s: string) => (s.trim() ? s.trim() : null);
  async function save(e: SubmitEvent) {
    e.preventDefault();
    const body = {
      syslog: f.sOn
        ? {
            ...f.s,
            port: Number(f.s.port),
            facility: Number(f.s.facility),
            ca_pem: opt(f.s.ca_pem),
            pin_sha256: opt(f.s.pin_sha256),
          }
        : null,
      https: f.hOn
        ? {
            ...f.h,
            batch_max: Number(f.h.batch_max),
            ca_pem: opt(f.h.ca_pem),
            pin_sha256: opt(f.h.pin_sha256),
            index: f.h.format === 'splunk_hec' ? opt(f.h.index) : null,
            // empty value of a stored header = keep it (null)
            headers: Object.fromEntries(
              f.headers
                .filter((h) => h.name.trim())
                .map((h) => [h.name.trim(), h.value ? h.value : h.stored ? null : '']),
            ),
          }
        : null,
    };
    const o = await act(put<ForwardingSettings>('/settings/forwarding', body), t.saved);
    if (o && !o.quorum) fill(o.data);
    else if (o) load();
  }

  async function test() {
    testing = true;
    result = null;
    try {
      result = (await post<Record<string, string>>('/settings/forwarding/test', {})).data as Record<string, string>;
    } catch (e) {
      notify('error', errText(e));
    }
    testing = false;
  }
  // Splunk HEC preset: the token goes into `Authorization: Splunk <token>`
  function setFormat() {
    if (f.h.format === 'splunk_hec' && !f.headers.some((h) => h.name.toLowerCase() === 'authorization'))
      f.headers.push({ name: 'Authorization', value: '', stored: false });
  }
  const hec = $derived(f.h.format === 'splunk_hec');
  const label = (k: string) => (k === 'syslog' ? t.settings.fw.syslog : k === 'https' ? t.settings.fw.https : k);
</script>

<ErrorBanner {error} />
{#if !cur}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  <form onsubmit={save}>
    <section class="card settings-section" aria-labelledby="fw-h">
      <div class="card-head">
        <h2 id="fw-h">{t.settings.tabs.forwarding}</h2>
        {#if admin && (cur.syslog || cur.https)}
          <button type="button" class="small" onclick={test} disabled={testing}
            ><IconSend aria-hidden="true" />{testing ? t.settings.testing : t.settings.fw.test}</button
          >
        {/if}
      </div>
      <p>{t.settings.fw.intro}</p>
      {#if result}<TestResult {result} {label} />{/if}
    </section>

    <fieldset disabled={!admin} class="plain-fieldset">
      <section class="card settings-section" aria-labelledby="fw-s">
        <div class="card-head">
          <h2 id="fw-s">{t.settings.fw.syslog}</h2>
          {#if cur.syslog}<span class="chip {cur.syslog.enabled ? 'ok' : 'warn'}"
              >{cur.syslog.enabled ? t.quorum.on : t.quorum.off}</span
            >{/if}
        </div>
        <p class="muted">{t.settings.fw.syslogIntro}</p>
        <div class="field">
          <label class="inline-check"><input type="checkbox" bind:checked={f.sOn} />{t.settings.fw.configure}</label>
        </div>
        {#if f.sOn}
          <div class="field">
            <label class="inline-check"
              ><input type="checkbox" bind:checked={f.s.enabled} />{t.settings.fw.enabled}</label
            >
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="fw-host">{t.settings.fw.host}</label>
              <input
                id="fw-host"
                class="mono"
                bind:value={f.s.host}
                required
                spellcheck="false"
                placeholder="siem.example.com"
              />
            </div>
            <div class="field">
              <label for="fw-port">{t.settings.fw.port}</label>
              <input id="fw-port" type="number" min="1" max="65535" bind:value={f.s.port} required />
            </div>
            <div class="field">
              <label for="fw-app">{t.settings.fw.appName}</label>
              <input id="fw-app" class="mono" bind:value={f.s.app_name} required maxlength="48" spellcheck="false" />
            </div>
            <div class="field">
              <label for="fw-fac">{t.settings.fw.facility}</label>
              <select id="fw-fac" bind:value={f.s.facility}>
                {#each FACILITIES as x (x.k)}<option value={x.k}>{x.v}</option>{/each}
              </select>
            </div>
          </div>
          <p class="hint">{t.settings.fw.trustHint}</p>
          <div class="form-grid">
            <div class="field">
              <label for="fw-spin">{t.settings.fw.pin}</label>
              <input id="fw-spin" class="mono" bind:value={f.s.pin_sha256} spellcheck="false" placeholder="ab:cd:…" />
            </div>
          </div>
          <div class="field">
            <label for="fw-sca">{t.settings.fw.caPem}</label>
            <textarea
              id="fw-sca"
              class="mono"
              rows="4"
              bind:value={f.s.ca_pem}
              spellcheck="false"
              placeholder="-----BEGIN CERTIFICATE-----"></textarea>
          </div>
        {/if}
      </section>

      <section class="card settings-section" aria-labelledby="fw-hh">
        <div class="card-head">
          <h2 id="fw-hh">{t.settings.fw.https}</h2>
          {#if cur.https}<span class="chip {cur.https.enabled ? 'ok' : 'warn'}"
              >{cur.https.enabled ? t.quorum.on : t.quorum.off}</span
            >{/if}
        </div>
        <p class="muted">{t.settings.fw.httpsIntro}</p>
        <div class="field">
          <label class="inline-check"><input type="checkbox" bind:checked={f.hOn} />{t.settings.fw.configure}</label>
        </div>
        {#if f.hOn}
          <div class="field">
            <label class="inline-check"
              ><input type="checkbox" bind:checked={f.h.enabled} />{t.settings.fw.enabled}</label
            >
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="fw-url">{t.settings.fw.url}</label>
              <input
                id="fw-url"
                class="mono"
                type="url"
                bind:value={f.h.url}
                required
                spellcheck="false"
                placeholder="https://siem.example.com/ingest"
              />
            </div>
            <div class="field">
              <label for="fw-batch">{t.settings.fw.batch}</label>
              <input id="fw-batch" type="number" min="1" max="1000" bind:value={f.h.batch_max} required />
            </div>
            <div class="field">
              <label for="fw-format">{t.settings.fw.format}</label>
              <select id="fw-format" bind:value={f.h.format} onchange={setFormat} aria-describedby="fw-format-hint">
                <option value="json_array">{t.settings.fw.formats.json_array}</option>
                <option value="splunk_hec">{t.settings.fw.formats.splunk_hec}</option>
              </select>
            </div>
            {#if hec}
              <div class="field">
                <label for="fw-index">{t.settings.fw.index}</label>
                <input
                  id="fw-index"
                  class="mono"
                  bind:value={f.h.index}
                  maxlength="80"
                  spellcheck="false"
                  placeholder="main"
                />
              </div>
            {/if}
          </div>
          <p class="hint" id="fw-format-hint">{hec ? t.settings.fw.hecHint : t.settings.fw.jsonHint}</p>
          <div class="field">
            <div class="card-head">
              <span class="field-label">{t.settings.al.headers}</span>
              <button type="button" class="small" onclick={() => f.headers.push({ name: '', value: '', stored: false })}
                ><IconPlus aria-hidden="true" />{t.settings.al.addHeader}</button
              >
            </div>
            <p class="hint">{t.settings.al.headersHint}</p>
            {#each f.headers as h, i (i)}
              <div class="header-row">
                <input
                  aria-label={t.settings.al.headerName}
                  class="mono"
                  bind:value={h.name}
                  placeholder="Authorization"
                  spellcheck="false"
                />
                <input
                  aria-label={t.settings.al.headerValue}
                  type="password"
                  bind:value={h.value}
                  placeholder={h.stored
                    ? t.writeOnlyKeep
                    : hec && h.name.toLowerCase() === 'authorization'
                      ? 'Splunk <HEC token>'
                      : ''}
                  autocomplete="new-password"
                />
                <button
                  type="button"
                  class="icon"
                  aria-label={t.settings.al.removeHeader(h.name)}
                  onclick={() => f.headers.splice(i, 1)}><IconX aria-hidden="true" /></button
                >
              </div>
            {/each}
          </div>
          <p class="hint">{t.settings.fw.trustHint}</p>
          <div class="form-grid">
            <div class="field">
              <label for="fw-hpin">{t.settings.fw.pin}</label>
              <input id="fw-hpin" class="mono" bind:value={f.h.pin_sha256} spellcheck="false" placeholder="ab:cd:…" />
            </div>
          </div>
          <div class="field">
            <label for="fw-hca">{t.settings.fw.caPem}</label>
            <textarea
              id="fw-hca"
              class="mono"
              rows="4"
              bind:value={f.h.ca_pem}
              spellcheck="false"
              placeholder="-----BEGIN CERTIFICATE-----"></textarea>
          </div>
        {/if}
      </section>
    </fieldset>
    {#if admin}
      <p class="hint">{t.settings.fw.quorumHint}</p>
      <div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>
    {:else}
      <p class="hint">{t.settings.readOnly}</p>
    {/if}
  </form>
{/if}

<style>
  .plain-fieldset {
    border: 0;
    padding: 0;
    margin: 0;
    min-width: 0;
  }
  .header-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.5fr) auto;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
  }
</style>
