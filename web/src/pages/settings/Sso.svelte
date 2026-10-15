<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, post, act, errText } from '../../lib/api';
  import { notify } from '../../lib/notify.svelte';
  import { session } from '../../lib/session.svelte';
  import { ROLES } from '../../lib/roles';
  import { copyText } from '../../lib/clipboard';
  import { t } from '../../lib/i18n';
  import type { OidcSettings, Role, Tenant } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import TestResult from './TestResult.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconTrash from '@lucide/svelte/icons/trash';
  import IconCopy from '@lucide/svelte/icons/copy';
  import IconSend from '@lucide/svelte/icons/plug-zap';

  // Phase 23a: with `tenant`, the tenant's own IdP (GET/PUT /tenants/{name}/oidc): tenant roles of
  // that tenant only, plus the e-mail domains the login page sends to it
  let { tenant = null }: { tenant?: string | null } = $props();
  const base = $derived(tenant ? `/tenants/${encodeURIComponent(tenant)}/oidc` : '/settings/oidc');
  const roles = $derived(tenant ? (['tenant_admin', 'tenant_user', 'viewer'] as Role[]) : ROLES);
  let domains = $state('');

  const id = $props.id();
  const admin = $derived(session.user?.role === 'admin' && !session.user?.tenant);
  const redirect = `${location.origin}/api/v1/auth/oidc/callback`;
  let error: string | null = $state(null);
  let loaded = $state(false);
  let busy = $state(false);
  let testing = $state(false);
  let result: Record<string, string> | null = $state(null);
  let tenants: Tenant[] = $state([]);
  let secretSet = $state(false);
  type Row = { group: string; role: Role; tenants: string };
  let f = $state({
    enabled: false,
    issuer: '',
    client_id: '',
    client_secret: '',
    scopes: 'openid profile email',
    username_claim: 'preferred_username',
    groups_claim: 'groups',
    label: '',
    mappings: [] as Row[],
    // YYYY-MM-DD or '' (Phase 14d: expiry alerts 90/30/7 days before)
    secret_expires: '',
  });

  function fill(o: OidcSettings) {
    f = {
      enabled: o.enabled,
      issuer: o.issuer ?? '',
      client_id: o.client_id ?? '',
      client_secret: '',
      scopes: (o.scopes ?? []).join(' '),
      username_claim: o.username_claim ?? 'preferred_username',
      groups_claim: o.groups_claim ?? 'groups',
      label: o.label ?? '',
      mappings: (o.mappings ?? []).map((m) => ({ group: m.group, role: m.role, tenants: m.tenants?.[0] ?? '' })),
      secret_expires: o.client_secret_expires
        ? new Date(o.client_secret_expires * 1000).toISOString().slice(0, 10)
        : '',
    };
    secretSet = !!o.client_secret_set;
    domains = (o.domains ?? []).join(' ');
  }

  async function load() {
    try {
      fill(await get<OidcSettings>(base));
      error = null;
    } catch (e) {
      error = errText(e);
    }
    tenants = await get<Tenant[]>('/tenants').catch(() => []);
    loaded = true;
  }
  onMount(load);

  const split = (s: string) =>
    s
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const scopes = split(f.scopes);
    // tenant users and tenant admins (Phase 19b) need exactly one tenant
    const oneTenant = (r: string) => !tenant && (r === 'tenant_user' || r === 'tenant_admin');
    const mappings = f.mappings.map((m) => ({
      group: m.group.trim(),
      role: m.role,
      tenants: tenant ? [tenant] : oneTenant(m.role) && m.tenants ? [m.tenants] : [],
    }));
    if (
      !/^https:\/\/\S+$/.test(f.issuer.trim()) ||
      !f.client_id.trim() ||
      !f.label.trim() ||
      !scopes.includes('openid') ||
      mappings.some((m) => !m.group || (oneTenant(m.role) && !m.tenants.length))
    ) {
      notify('error', t.settings.oidc.invalid);
      return;
    }
    const body: OidcSettings = {
      enabled: f.enabled,
      issuer: f.issuer.trim().replace(/\/+$/, ''),
      client_id: f.client_id.trim(),
      scopes,
      username_claim: f.username_claim.trim(),
      groups_claim: f.groups_claim.trim(),
      label: f.label.trim(),
      mappings,
      client_secret_expires: f.secret_expires ? Date.parse(`${f.secret_expires}T00:00:00Z`) / 1000 : null,
      ...(f.client_secret ? { client_secret: f.client_secret } : {}),
      ...(tenant ? { domains: split(domains).map((d) => d.replace(/^@/, '').toLowerCase()) } : {}),
    };
    busy = true;
    const r = await act(put<OidcSettings>(base, body), t.saved);
    busy = false;
    if (r && !r.quorum) fill(r.data);
    else if (r) f.client_secret = '';
  }

  async function test() {
    testing = true;
    result = null;
    try {
      result = (await post<Record<string, string>>(`${base}/test`)).data as Record<string, string>;
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
    <p class="intro muted">{tenant ? t.sp.idp.intro(tenant) : t.settings.oidc.intro}</p>
    {#if !admin}<p class="banner info">{t.settings.readOnly}</p>{/if}
    <fieldset disabled={!admin} class="plain">
      <section class="card" aria-labelledby="{id}-idp">
        <div class="card-head">
          <h2 id="{id}-idp">{t.settings.oidc.provider}</h2>
          <label class="inline-check"><input type="checkbox" bind:checked={f.enabled} />{t.settings.oidc.enabled}</label
          >
        </div>
        <div class="field">
          <label for="{id}-iss">{t.settings.oidc.issuer}</label>
          <input
            id="{id}-iss"
            type="url"
            class="mono"
            bind:value={f.issuer}
            required
            pattern="https://.+"
            placeholder="https://idp.example.com/realms/nexus"
            autocomplete="off"
            spellcheck="false"
            aria-describedby="{id}-iss-hint"
          />
          <div class="hint" id="{id}-iss-hint">{t.settings.oidc.issuerHint}</div>
        </div>
        <div class="form-grid">
          <div class="field">
            <label for="{id}-cid">{t.settings.oidc.clientId}</label>
            <input id="{id}-cid" class="mono" bind:value={f.client_id} required autocomplete="off" spellcheck="false" />
          </div>
          <div class="field">
            <label for="{id}-sec">{t.settings.oidc.clientSecret}</label>
            <input
              id="{id}-sec"
              type="password"
              bind:value={f.client_secret}
              autocomplete="new-password"
              aria-describedby="{id}-sec-hint"
            />
            <div class="hint" id="{id}-sec-hint">{secretSet ? t.writeOnlyKeep : t.writeOnlyHint}</div>
          </div>
          <div class="field">
            <label for="{id}-secexp">{t.settings.oidc.secretExpires}</label>
            <input id="{id}-secexp" type="date" bind:value={f.secret_expires} aria-describedby="{id}-secexp-hint" />
            <div class="hint" id="{id}-secexp-hint">{t.settings.oidc.secretExpiresHint}</div>
          </div>
        </div>
        <div class="field">
          <span class="field-label" id="{id}-redir">{t.settings.oidc.redirect}</span>
          <div class="copyline">
            <code aria-labelledby="{id}-redir">{redirect}</code>
            <button
              type="button"
              class="small"
              onclick={() => copyText(redirect)}
              aria-label="{t.users.copy}: {t.settings.oidc.redirect}"
              ><IconCopy aria-hidden="true" />{t.users.copy}</button
            >
          </div>
        </div>
        <div class="form-grid">
          <div class="field">
            <label for="{id}-scopes">{t.settings.oidc.scopes}</label>
            <input
              id="{id}-scopes"
              class="mono"
              bind:value={f.scopes}
              required
              autocomplete="off"
              spellcheck="false"
              aria-describedby="{id}-scopes-hint"
            />
            <div class="hint" id="{id}-scopes-hint">{t.settings.oidc.scopesHint}</div>
          </div>
          <div class="field">
            <label for="{id}-uc">{t.settings.oidc.usernameClaim}</label>
            <input
              id="{id}-uc"
              class="mono"
              bind:value={f.username_claim}
              required
              autocomplete="off"
              spellcheck="false"
            />
          </div>
          <div class="field">
            <label for="{id}-gc">{t.settings.oidc.groupsClaim}</label>
            <input
              id="{id}-gc"
              class="mono"
              bind:value={f.groups_claim}
              required
              autocomplete="off"
              spellcheck="false"
            />
          </div>
        </div>
        <div class="field">
          <label for="{id}-label">{t.settings.oidc.label}</label>
          <input id="{id}-label" bind:value={f.label} required maxlength="64" placeholder="Sign in with Keycloak" />
        </div>
        {#if tenant}
          <div class="field">
            <label for="{id}-dom">{t.sp.idp.domains}</label>
            <input
              id="{id}-dom"
              class="mono"
              bind:value={domains}
              autocomplete="off"
              spellcheck="false"
              placeholder="example.com"
              aria-describedby="{id}-dom-hint"
            />
            <div class="hint" id="{id}-dom-hint">{t.sp.idp.domainsHint}</div>
          </div>
        {/if}
      </section>

      <section class="card" aria-labelledby="{id}-map">
        <div class="card-head">
          <h2 id="{id}-map">{t.settings.oidc.mappings}</h2>
          <button
            type="button"
            class="small"
            onclick={() => f.mappings.push({ group: '', role: tenant ? 'tenant_user' : 'operator', tenants: '' })}
            ><IconPlus aria-hidden="true" />{t.settings.oidc.addMapping}</button
          >
        </div>
        <p class="muted">{tenant ? t.sp.idp.mappingsIntro(tenant) : t.settings.oidc.mappingsIntro}</p>
        {#if f.mappings.length === 0}
          <p class="banner warn">{t.settings.oidc.noMappings}</p>
        {:else}
          <div class="mapping-grid">
            <span class="head" id="{id}-h-g">{t.settings.oidc.group}</span>
            <span class="head" id="{id}-h-r">{t.settings.oidc.role}</span>
            <span class="head" id="{id}-h-t">{t.settings.oidc.tenants}</span>
            <span class="head"></span>
            {#each f.mappings as m, i (i)}
              <input
                class="mono"
                bind:value={m.group}
                required
                aria-labelledby="{id}-h-g"
                placeholder="nexus-admins"
                autocomplete="off"
                spellcheck="false"
              />
              <select bind:value={m.role} aria-labelledby="{id}-h-r">
                {#each roles as r (r)}<option value={r}>{t.roles[r]}</option>{/each}
              </select>
              <!-- an appliance user has one tenant: only tenant users and tenant admins get one, the other roles see all -->
              {@const scoped = !tenant && (m.role === 'tenant_user' || m.role === 'tenant_admin')}
              <select bind:value={m.tenants} aria-labelledby="{id}-h-t" required={scoped} disabled={!scoped}>
                {#if tenant}
                  <option value={tenant}>{tenant}</option>
                {:else if scoped}
                  <option value="" disabled>{t.settings.oidc.pickTenant}</option>
                  {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
                {:else}
                  <option value="">{t.allTenants}</option>
                {/if}
              </select>
              <button
                type="button"
                class="icon"
                aria-label={t.settings.oidc.removeMapping(m.group)}
                onclick={() => f.mappings.splice(i, 1)}><IconTrash aria-hidden="true" /></button
              >
            {/each}
          </div>
        {/if}
      </section>

      <section class="card">
        <p class="muted">{t.settings.oidc.quorumHint}</p>
        <div class="form-actions">
          <button type="button" onclick={test} disabled={testing} title={t.settings.oidc.testIntro}
            ><IconSend aria-hidden="true" />{testing ? t.settings.testing : t.settings.testConnection}</button
          >
          <button type="submit" class="primary" disabled={busy}>{t.save}</button>
        </div>
        {#if result}<TestResult {result} />{/if}
      </section>
    </fieldset>
  </form>
{/if}
