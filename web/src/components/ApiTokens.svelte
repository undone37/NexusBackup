<script lang="ts">
  // API tokens (Phase 14d): own tokens (My account) or, with `all`, every user's (Users page,
  // admins). The secret is shown once after creation; the server stores only its hash.
  import { onMount } from 'svelte';
  import { get, post, del, act, errText } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { copyText } from '../lib/clipboard';
  import { fmtTime, fmtAgo } from '../lib/format';
  import { t } from '../lib/i18n';
  import { secondFactor } from '../lib/passkey';
  import type { ApiToken } from '../lib/types';
  import Modal from './Modal.svelte';
  import ErrorBanner from './ErrorBanner.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconCopy from '@lucide/svelte/icons/copy';

  let { all = false }: { all?: boolean } = $props();
  const id = $props.id();
  let items: ApiToken[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  const now = () => Date.now() / 1000;
  // security officers' tokens are read-only (the server refuses operator tokens for them)
  const canOperate = $derived(session.user?.role !== 'security_officer' && session.user?.role !== 'viewer');
  const local = $derived(session.user?.auth !== 'oidc');

  async function load() {
    try {
      items = await get<ApiToken[]>(all ? '/auth/tokens?all=true' : '/auth/tokens');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  let open = $state(false);
  let f = $state({ name: '', scope: 'read' as 'read' | 'operator', days: 90, password: '', totp: '' });
  let created: ApiToken | null = $state(null);
  let shownOpen = $state(false);

  function startCreate() {
    f = { name: '', scope: 'read', days: 90, password: '', totp: '' };
    open = true;
  }

  async function create(e: SubmitEvent) {
    e.preventDefault();
    const body: Record<string, unknown> = { name: f.name.trim(), scope: f.scope, days: Number(f.days) };
    const pw = f.password;
    const second = local ? secondFactor(f.totp) : Promise.resolve('');
    const r = await act(
      second.then((totp) =>
        post<ApiToken>('/auth/tokens', local ? { ...body, current_password: pw, current_totp: totp } : body),
      ),
      t.tokens.created,
    );
    f.password = '';
    f.totp = '';
    if (!r || r.quorum) return;
    open = false;
    created = r.data;
    shownOpen = true;
    load();
  }

  async function revoke(x: ApiToken) {
    if (!(await askConfirm(t.tokens.revokeConfirm(x.name, x.user)))) return;
    if (await act(del(`/auth/tokens/${x.id}`), t.tokens.revoked)) load();
  }

  const expiry = (x: ApiToken) =>
    x.expires < now()
      ? { cls: 'bad', text: t.tokens.expired }
      : x.expires - now() < 7 * 86400
        ? { cls: 'warn', text: fmtTime(x.expires) }
        : { cls: '', text: fmtTime(x.expires) };
</script>

<section class="card" aria-labelledby="{id}-h">
  <div class="card-head">
    <h2 id="{id}-h">{all ? t.tokens.allTitle : t.tokens.title}</h2>
    {#if !all}<button type="button" class="small" onclick={startCreate}
        ><IconPlus aria-hidden="true" />{t.tokens.new}</button
      >{/if}
  </div>
  <p class="muted">{all ? t.tokens.allIntro : t.tokens.intro}</p>
  <ErrorBanner {error} />
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if items.length === 0}
    <p class="empty">{t.tokens.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            {#if all}<th scope="col">{t.tokens.user}</th>{/if}
            <th scope="col">{t.name}</th>
            <th scope="col">{t.tokens.scope}</th>
            <th scope="col">{t.tokens.expires}</th>
            <th scope="col">{t.tokens.lastUsed}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            {@const ex = expiry(x)}
            <tr>
              {#if all}<td>{x.user}</td>{/if}
              <td><strong>{x.name}</strong> <code class="muted">nxt_{x.prefix}_…</code></td>
              <td><span class="chip {x.scope === 'operator' ? 'accent' : ''}">{t.tokens.scopes[x.scope]}</span></td>
              <td class="nowrap"><span class={ex.cls ? `chip ${ex.cls}` : ''}>{ex.text}</span></td>
              <td class="nowrap"
                >{fmtAgo(x.last_used)}{#if x.last_ip}<span class="muted">{` · ${x.last_ip}`}</span>{/if}</td
              >
              <td class="actions"
                ><button type="button" class="small danger" onclick={() => revoke(x)}>{t.tokens.revoke}</button></td
              >
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<Modal bind:open title={t.tokens.new}>
  <form onsubmit={create}>
    <div class="field">
      <label for="{id}-name">{t.name}</label>
      <input
        id="{id}-name"
        bind:value={f.name}
        required
        maxlength="64"
        pattern={'[A-Za-z0-9_\\-][A-Za-z0-9._\\-]*'}
        placeholder="monitoring"
        autocomplete="off"
        spellcheck="false"
      />
    </div>
    <div class="form-grid">
      <div class="field">
        <label for="{id}-scope">{t.tokens.scope}</label>
        <select id="{id}-scope" bind:value={f.scope} aria-describedby="{id}-scope-hint">
          <option value="read">{t.tokens.scopes.read}</option>
          {#if canOperate}<option value="operator">{t.tokens.scopes.operator}</option>{/if}
        </select>
      </div>
      <div class="field">
        <label for="{id}-days">{t.tokens.lifetime}</label>
        <select id="{id}-days" bind:value={f.days}>
          {#each [7, 30, 90, 180, 365] as d (d)}<option value={d}>{t.tokens.days(d)}</option>{/each}
        </select>
      </div>
    </div>
    <p class="hint" id="{id}-scope-hint">{f.scope === 'operator' ? t.tokens.operatorHint : t.tokens.readHint}</p>
    <p class="banner info">{t.tokens.never}</p>
    {#if local}
      <fieldset>
        <legend>{t.users.reauth}</legend>
        <div class="form-grid">
          <div class="field">
            <label for="{id}-pw">{t.users.currentPassword}</label>
            <input id="{id}-pw" type="password" bind:value={f.password} required autocomplete="current-password" />
          </div>
          <div class="field">
            <label for="{id}-totp">{t.users.currentTotp}</label>
            <input
              id="{id}-totp"
              bind:value={f.totp}
              inputmode="numeric"
              pattern={'[0-9]{6}'}
              maxlength="6"
              autocomplete="one-time-code"
              aria-describedby="{id}-totp-hint"
            />
            <div class="hint" id="{id}-totp-hint">{t.passkeys.totpOrPasskey}</div>
          </div>
        </div>
      </fieldset>
    {:else}
      <p class="muted">{t.tokens.ssoFresh}</p>
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={shownOpen} title="{t.tokens.shownTitle}: {created?.name ?? ''}">
  {#if created?.token}
    <p class="banner warn">{t.tokens.shownOnce}</p>
    <div class="copyline">
      <code class="secret">{created.token}</code>
      <button
        type="button"
        class="small"
        onclick={() => copyText(created!.token!)}
        aria-label="{t.users.copy}: {created.name}"><IconCopy aria-hidden="true" />{t.users.copy}</button
      >
    </div>
    <p class="muted">{t.tokens.usage}</p>
    <pre class="mono usage">curl -H "Authorization: Bearer {created.token.slice(
        0,
        13,
      )}…" https://{location.host}/api/v1/dashboard</pre>
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (shownOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<style>
  .usage {
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 0.85em;
  }
</style>
