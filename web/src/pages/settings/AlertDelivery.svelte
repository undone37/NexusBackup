<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, post, act, errText } from '../../lib/api';
  import { notify } from '../../lib/notify.svelte';
  import { session } from '../../lib/session.svelte';
  import { t } from '../../lib/i18n';
  import type { AlertSettings } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import TestResult from './TestResult.svelte';
  import IconSend from '@lucide/svelte/icons/send';

  const id = $props.id();
  const admin = $derived(session.user?.role === 'admin');
  let error: string | null = $state(null);
  let loaded = $state(false);
  let busy = $state(false);
  let testing = $state(false);
  let result: Record<string, string> | null = $state(null);
  let passwordSet = $state(false);
  let f = $state({
    webhook: '',
    smtpOn: false,
    host: '',
    port: 587,
    starttls: true,
    from: '',
    to: '',
    user: '',
    password: '',
    min: 'warning' as AlertSettings['min_severity'],
  });

  function fill(a: AlertSettings) {
    f = {
      webhook: a.webhook_url ?? '',
      smtpOn: !!a.smtp,
      host: a.smtp?.host ?? '',
      port: a.smtp?.port ?? 587,
      starttls: a.smtp?.starttls ?? true,
      from: a.smtp?.from ?? '',
      to: (a.smtp?.to ?? []).join('\n'),
      user: a.smtp?.user ?? '',
      password: '',
      min: a.min_severity ?? 'warning',
    };
    passwordSet = !!a.smtp?.password_set;
  }

  async function load() {
    try {
      fill(await get<AlertSettings>('/settings/alerts'));
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  const recipients = $derived(
    f.to
      .split(/[\n,;]/)
      .map((x) => x.trim())
      .filter(Boolean),
  );

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (f.smtpOn && !recipients.length) {
      notify('error', t.settings.al.invalidTo);
      return;
    }
    const body: AlertSettings = {
      webhook_url: f.webhook.trim() || null,
      smtp: f.smtpOn
        ? {
            host: f.host.trim(),
            port: Number(f.port),
            starttls: f.starttls,
            from: f.from.trim(),
            to: recipients,
            user: f.user.trim(),
            ...(f.password ? { password: f.password } : {}),
          }
        : null,
      min_severity: f.min,
    };
    busy = true;
    const r = await act(put<AlertSettings>('/settings/alerts', body), t.saved);
    busy = false;
    if (r && !r.quorum) fill(r.data);
  }

  async function test() {
    testing = true;
    result = null;
    try {
      result = (await post<Record<string, string>>('/settings/alerts/test')).data as Record<string, string>;
    } catch (e) {
      notify('error', errText(e));
    }
    testing = false;
  }
</script>

<ErrorBanner {error} />
{#if !loaded}
  <p class="muted" aria-busy="true">{t.loading}</p>
{:else}
  <form class="settings-section" onsubmit={save}>
    <p class="intro muted">{t.settings.al.intro}</p>
    {#if !admin}<p class="banner info">{t.settings.readOnly}</p>{/if}
    <fieldset disabled={!admin} class="plain">
      <section class="card" aria-labelledby="{id}-wh">
        <h2 id="{id}-wh">{t.settings.al.webhook}</h2>
        <div class="field">
          <label for="{id}-url">{t.settings.al.webhookUrl}</label>
          <input
            id="{id}-url"
            type="url"
            class="mono"
            bind:value={f.webhook}
            pattern="https://.+"
            placeholder="https://hooks.example.com/…"
            autocomplete="off"
            spellcheck="false"
            aria-describedby="{id}-url-hint"
          />
          <div class="hint" id="{id}-url-hint">{t.settings.al.webhookHint}</div>
        </div>
      </section>

      <section class="card" aria-labelledby="{id}-mail">
        <div class="card-head">
          <h2 id="{id}-mail">{t.settings.al.email}</h2>
          <label class="inline-check"><input type="checkbox" bind:checked={f.smtpOn} />{t.settings.al.smtpOn}</label>
        </div>
        {#if f.smtpOn}
          <div class="form-grid">
            <div class="field">
              <label for="{id}-host">{t.settings.al.host}</label>
              <input id="{id}-host" bind:value={f.host} required autocomplete="off" spellcheck="false" />
            </div>
            <div class="field">
              <label for="{id}-port">{t.settings.al.port}</label>
              <input id="{id}-port" type="number" min="1" max="65535" bind:value={f.port} required />
            </div>
            <div class="field">
              <label for="{id}-from">{t.settings.al.from}</label>
              <input id="{id}-from" type="email" bind:value={f.from} required autocomplete="off" />
            </div>
          </div>
          <div class="field">
            <label class="inline-check"><input type="checkbox" bind:checked={f.starttls} />{t.settings.al.starttls}</label>
          </div>
          <div class="field">
            <label for="{id}-to">{t.settings.al.to}</label>
            <textarea id="{id}-to" bind:value={f.to} rows="3" spellcheck="false"></textarea>
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="{id}-user">{t.settings.al.user}</label>
              <input id="{id}-user" bind:value={f.user} autocomplete="off" spellcheck="false" />
            </div>
            <div class="field">
              <label for="{id}-pw">{t.settings.al.password}</label>
              <input id="{id}-pw" type="password" bind:value={f.password} autocomplete="new-password" aria-describedby="{id}-pw-hint" />
              <div class="hint" id="{id}-pw-hint">{passwordSet ? t.writeOnlyKeep : t.writeOnlyHint}</div>
            </div>
          </div>
        {/if}
      </section>

      <section class="card">
        <div class="field">
          <label for="{id}-sev">{t.settings.al.minSeverity}</label>
          <select id="{id}-sev" class="auto" bind:value={f.min}>
            {#each ['info', 'warning', 'critical'] as s (s)}<option value={s}>{t.settings.al.severities[s]}</option>{/each}
          </select>
        </div>
        <div class="form-actions">
          <button type="button" onclick={test} disabled={testing} title={t.settings.al.testIntro}
            ><IconSend aria-hidden="true" />{testing ? t.settings.testing : t.settings.test}</button
          >
          <button type="submit" class="primary" disabled={busy}>{t.save}</button>
        </div>
        {#if result}<TestResult {result} label={t.settings.al.channel} />{/if}
      </section>
    </fieldset>
  </form>
{/if}
