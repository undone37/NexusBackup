<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, post, act, errText } from '../../lib/api';
  import { notify } from '../../lib/notify.svelte';
  import { session } from '../../lib/session.svelte';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { t } from '../../lib/i18n';
  import type { AlertRule, AlertSettings, Severity, Tenant } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import Modal from '../../components/Modal.svelte';
  import TestResult from './TestResult.svelte';
  import IconSend from '@lucide/svelte/icons/send';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconX from '@lucide/svelte/icons/x';

  const id = $props.id();
  const admin = $derived(session.user?.role === 'admin');
  const SEVS: Severity[] = ['info', 'warning', 'critical'];
  const KINDS = Object.keys(t.alerts.hints);
  const FIELDS = 'id, ts, first_ts, last_ts, count, severity, kind, category, message, hint, tenant, host, alert_url';
  // Example bodies (manual chapter 11): Slack incoming webhook, Microsoft Teams workflow (Adaptive Card).
  const EXAMPLES: Record<string, string> = {
    Slack: `{"text": ":rotating_light: [{{severity}}] {{kind}} on {{host}}: {{message}}\\n{{hint}}\\n<{{alert_url}}|Open alert> (seen {{count}}x)"}`,
    Teams: `{"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
  "body": [{"type": "TextBlock", "weight": "Bolder", "wrap": true, "text": "[{{severity}}] {{kind}} on {{host}}"},
           {"type": "TextBlock", "wrap": true, "text": "{{message}}"},
           {"type": "TextBlock", "wrap": true, "isSubtle": true, "text": "{{hint}}"}],
  "actions": [{"type": "Action.OpenUrl", "title": "Open alert", "url": "{{alert_url}}"}]}}]}`,
  };

  let error: string | null = $state(null);
  let loaded = $state(false);
  let busy = $state(false);
  let saved: AlertSettings | null = $state(null);
  let tenants: string[] = $state([]);
  let testing: string | null = $state(null);
  let results: Record<string, Record<string, string>> = $state({});
  let passwordSet = $state(false);
  let f = $state({
    smtpOn: false,
    host: '',
    port: 587,
    starttls: true,
    from: '',
    user: '',
    password: '',
    reminder: 24,
    retention: { info: 14, warning: 180, critical: 180 } as Record<Severity, number>,
  });

  function fill(a: AlertSettings) {
    saved = a;
    f = {
      smtpOn: !!a.smtp,
      host: a.smtp?.host ?? '',
      port: a.smtp?.port ?? 587,
      starttls: a.smtp?.starttls ?? true,
      from: a.smtp?.from ?? '',
      user: a.smtp?.user ?? '',
      password: '',
      reminder: a.reminder_hours,
      retention: { ...a.retention_days },
    };
    passwordSet = !!a.smtp?.password_set;
  }

  async function load() {
    try {
      fill(await get<AlertSettings>('/settings/alerts'));
      tenants = (await get<Tenant[]>('/tenants').catch(() => [])).map((x) => x.name);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  /** The saved SMTP server as a request (password kept by the server). */
  function savedSmtp() {
    const s = saved?.smtp;
    return s ? { host: s.host, port: s.port, starttls: s.starttls, from: s.from, user: s.user || undefined } : null;
  }

  async function store(body: Omit<AlertSettings, 'smtp'> & { smtp: unknown }) {
    busy = true;
    const r = await act(put<AlertSettings>('/settings/alerts', body), t.saved);
    busy = false;
    if (r && !r.quorum) {
      fill(r.data);
      results = {};
      return true;
    }
    return false;
  }

  // SMTP server, reminders and retention (the rules as saved)
  async function saveGeneral(e: SubmitEvent) {
    e.preventDefault();
    if (!saved) return;
    if (!f.smtpOn && saved.rules.some((r) => r.channels.email.length)) {
      notify('error', t.settings.al.smtpNeeded);
      return;
    }
    await store({
      smtp: f.smtpOn
        ? {
            host: f.host.trim(),
            port: Number(f.port),
            starttls: f.starttls,
            from: f.from.trim(),
            user: f.user.trim() || undefined,
            ...(f.password ? { password: f.password } : {}),
          }
        : null,
      rules: saved.rules,
      reminder_hours: Number(f.reminder),
      retention_days: { info: Number(f.retention.info), warning: Number(f.retention.warning), critical: Number(f.retention.critical) },
    });
  }

  // ---- rule editor (saves the rule list right away, with the saved SMTP server)
  type Header = { name: string; value: string; stored: boolean };
  let open = $state(false);
  let editing: number | null = $state(null);
  let r = $state({
    name: '',
    min: 'warning' as Severity,
    kinds: [] as string[],
    tenants: [] as string[],
    email: '',
    url: '',
    headers: [] as Header[],
    template: '',
  });

  function edit(i: number | null) {
    const x = i === null ? null : saved!.rules[i];
    editing = i;
    r = {
      name: x?.name ?? '',
      min: x?.min_severity ?? 'warning',
      kinds: [...(x?.kinds ?? [])],
      tenants: [...(x?.tenants ?? [])],
      email: (x?.channels.email ?? []).join('\n'),
      url: x?.channels.webhook?.url ?? '',
      headers: Object.keys(x?.channels.webhook?.headers ?? {}).map((name) => ({ name, value: '', stored: true })),
      template: x?.channels.webhook?.template ?? '',
    };
    open = true;
  }

  const list = (s: string) =>
    s
      .split(/[\n,;]/)
      .map((x) => x.trim())
      .filter(Boolean);

  async function saveRule(e: SubmitEvent) {
    e.preventDefault();
    if (!saved) return;
    const email = list(r.email);
    const url = r.url.trim();
    const name = r.name.trim();
    const clash = saved.rules.some((x, i) => x.name === name && i !== editing);
    if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$/.test(name) || clash || (!email.length && !url)) {
      notify('error', t.settings.al.invalidRule);
      return;
    }
    if (email.length && !saved.smtp) {
      notify('error', t.settings.al.smtpNeeded);
      return;
    }
    const rule: AlertRule = {
      name,
      min_severity: r.min,
      kinds: r.kinds,
      tenants: r.tenants,
      channels: {
        email,
        webhook: url
          ? {
              url,
              headers: Object.fromEntries(
                r.headers.filter((h) => h.name.trim()).map((h) => [h.name.trim(), h.value ? h.value : h.stored ? null : '']),
              ),
              template: r.template.trim() || null,
            }
          : null,
      },
    };
    const rules = [...saved.rules];
    if (editing === null) rules.push(rule);
    else rules[editing] = rule;
    if (await store({ smtp: savedSmtp(), rules, reminder_hours: saved.reminder_hours, retention_days: saved.retention_days })) open = false;
  }

  async function remove(i: number) {
    if (!saved || !(await askConfirm(t.settings.al.deleteConfirm(saved.rules[i].name)))) return;
    const rules = saved.rules.filter((_, j) => j !== i);
    await store({ smtp: savedSmtp(), rules, reminder_hours: saved.reminder_hours, retention_days: saved.retention_days });
  }

  async function test(name: string) {
    testing = name;
    try {
      results[name] = (await post<Record<string, string>>('/settings/alerts/test', { rule: name })).data as Record<string, string>;
    } catch (e) {
      notify('error', errText(e));
    }
    testing = null;
  }

  const summary = (x: AlertRule) =>
    t.settings.al.summary(
      t.settings.al.severities[x.min_severity],
      x.kinds.length ? x.kinds.join(', ') : t.settings.al.any,
      x.tenants.length ? x.tenants.join(', ') : t.settings.al.any,
    );
  const channels = (x: AlertRule) =>
    [
      x.channels.email.length ? `${t.settings.al.channel('email')} (${x.channels.email.length})` : '',
      x.channels.webhook ? `${t.settings.al.channel('webhook')} ${new URL(x.channels.webhook.url).host}` : '',
    ]
      .filter(Boolean)
      .join(' · ') || t.settings.al.noChannel;
</script>

<ErrorBanner {error} />
{#if !loaded || !saved}
  {#if !loaded}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  <div class="settings-section">
    <p class="intro muted">{t.settings.al.intro}</p>
    {#if !admin}<p class="banner info">{t.settings.readOnly}</p>{/if}

    <section class="card" aria-labelledby="{id}-rules">
      <div class="card-head">
        <h2 id="{id}-rules">{t.settings.al.rules}</h2>
        {#if admin}<button type="button" class="small" onclick={() => edit(null)}><IconPlus aria-hidden="true" />{t.settings.al.addRule}</button>{/if}
      </div>
      {#if saved.rules.length === 0}
        <p class="empty">{t.settings.al.noRules}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.settings.al.ruleName}</th>
                <th scope="col">{t.settings.al.minSeverity}</th>
                <th scope="col">{t.settings.al.channels}</th>
                <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
              </tr>
            </thead>
            <tbody>
              {#each saved.rules as x, i (x.name)}
                <tr>
                  <td class="mono">{x.name}</td>
                  <td>{summary(x)}</td>
                  <td>{channels(x)}</td>
                  <td class="actions">
                    {#if admin}
                      <button type="button" class="small" onclick={() => test(x.name)} disabled={testing !== null} title={t.settings.al.testIntro}
                        aria-label={t.settings.al.testRule(x.name)}><IconSend aria-hidden="true" />{testing === x.name ? t.settings.testing : t.settings.test}</button
                      >
                      <button type="button" class="small" onclick={() => edit(i)} aria-label={t.settings.al.editRule(x.name)}>{t.edit}</button>
                      <button type="button" class="small danger" onclick={() => remove(i)} aria-label={t.settings.al.deleteRule(x.name)}>{t.delete}</button>
                    {/if}
                  </td>
                </tr>
                {#if results[x.name]}
                  <tr><td colspan="4"><TestResult result={results[x.name]} label={t.settings.al.channel} /></td></tr>
                {/if}
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <form onsubmit={saveGeneral}>
      <fieldset disabled={!admin} class="plain">
        <section class="card" aria-labelledby="{id}-mail">
          <div class="card-head">
            <h2 id="{id}-mail">{t.settings.al.smtp}</h2>
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

        <section class="card" aria-labelledby="{id}-life">
          <h2 id="{id}-life">{t.settings.al.lifecycle}</h2>
          <div class="form-grid">
            <div class="field">
              <label for="{id}-rem">{t.settings.al.reminder}</label>
              <input id="{id}-rem" type="number" min="0" max="720" bind:value={f.reminder} required aria-describedby="{id}-rem-hint" />
              <div class="hint" id="{id}-rem-hint">{t.settings.al.reminderHint}</div>
            </div>
            {#each SEVS as s (s)}
              <div class="field">
                <label for="{id}-ret-{s}">{t.settings.al.retention(s)}</label>
                <input id="{id}-ret-{s}" type="number" min="1" max="3650" bind:value={f.retention[s]} required />
              </div>
            {/each}
          </div>
          <div class="form-actions">
            <button type="submit" class="primary" disabled={busy}>{t.save}</button>
          </div>
        </section>
      </fieldset>
    </form>
  </div>
{/if}

<Modal bind:open wide title={editing === null ? t.settings.al.newRule : t.settings.al.editRule(r.name)}>
  <form onsubmit={saveRule}>
    <div class="form-grid">
      <div class="field">
        <label for="{id}-rn">{t.settings.al.ruleName}</label>
        <input id="{id}-rn" bind:value={r.name} required maxlength="64" pattern={'[A-Za-z0-9_\\-][A-Za-z0-9._\\-]*'} aria-describedby="{id}-rn-hint" />
        <div class="hint" id="{id}-rn-hint">{t.settings.al.ruleNameHint}</div>
      </div>
      <div class="field">
        <label for="{id}-rs">{t.settings.al.minSeverity}</label>
        <select id="{id}-rs" bind:value={r.min}>
          {#each SEVS as s (s)}<option value={s}>{t.settings.al.severities[s]}</option>{/each}
        </select>
      </div>
    </div>
    <fieldset>
      <legend>{t.settings.al.kinds}</legend>
      <p class="hint">{t.settings.al.kindsHint}</p>
      <div class="check-cols">
        {#each KINDS as k (k)}
          <label class="inline-check mono"><input type="checkbox" value={k} bind:group={r.kinds} />{k}</label>
        {/each}
      </div>
    </fieldset>
    {#if tenants.length}
      <fieldset>
        <legend>{t.settings.al.tenants}</legend>
        <p class="hint">{t.settings.al.tenantsHint}</p>
        <div class="check-cols">
          {#each tenants as x (x)}
            <label class="inline-check"><input type="checkbox" value={x} bind:group={r.tenants} />{x}</label>
          {/each}
        </div>
      </fieldset>
    {/if}
    <fieldset>
      <legend>{t.settings.al.channels}</legend>
      <div class="field">
        <label for="{id}-re">{t.settings.al.email}</label>
        <textarea id="{id}-re" bind:value={r.email} rows="2" spellcheck="false" aria-describedby="{id}-re-hint"></textarea>
        <div class="hint" id="{id}-re-hint">{t.settings.al.emailHint}</div>
      </div>
      <div class="field">
        <label for="{id}-ru">{t.settings.al.webhookUrl}</label>
        <input id="{id}-ru" type="url" class="mono" bind:value={r.url} placeholder="https://hooks.example.com/…" autocomplete="off" spellcheck="false" aria-describedby="{id}-ru-hint" />
        <div class="hint" id="{id}-ru-hint">{t.settings.al.webhookHint}</div>
      </div>
      {#if r.url.trim()}
        <div class="field">
          <div class="card-head">
            <span class="field-label">{t.settings.al.headers}</span>
            <button type="button" class="small" onclick={() => r.headers.push({ name: '', value: '', stored: false })}><IconPlus aria-hidden="true" />{t.settings.al.addHeader}</button>
          </div>
          <p class="hint">{t.settings.al.headersHint}</p>
          {#each r.headers as h, i (i)}
            <div class="header-row">
              <input aria-label={t.settings.al.headerName} class="mono" bind:value={h.name} placeholder="Authorization" spellcheck="false" />
              <input aria-label={t.settings.al.headerValue} type="password" bind:value={h.value} placeholder={h.stored ? t.writeOnlyKeep : ''} autocomplete="new-password" />
              <button type="button" class="icon" aria-label={t.settings.al.removeHeader(h.name)} onclick={() => r.headers.splice(i, 1)}><IconX aria-hidden="true" /></button>
            </div>
          {/each}
        </div>
        <div class="field">
          <label for="{id}-rt">{t.settings.al.template}</label>
          <textarea id="{id}-rt" class="mono" bind:value={r.template} rows="6" spellcheck="false" aria-describedby="{id}-rt-hint"></textarea>
          <div class="hint" id="{id}-rt-hint">{t.settings.al.templateHint(FIELDS)}</div>
          <div class="row">
            <span class="muted">{t.settings.al.templateExamples}:</span>
            {#each Object.keys(EXAMPLES) as k (k)}
              <button type="button" class="small" onclick={() => (r.template = EXAMPLES[k])}>{k}</button>
            {/each}
          </div>
        </div>
      {/if}
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={busy}>{t.save}</button>
    </div>
  </form>
</Modal>

<style>
  .check-cols {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr));
    gap: 0.25rem 1rem;
  }
  .header-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.5fr) auto;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
  }
  td.actions {
    white-space: nowrap;
  }
</style>
