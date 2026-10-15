<script lang="ts">
  import { rowClick } from '../lib/rowlink';
  import { onMount } from 'svelte';
  import { get, post, put, act, errText, type Outcome } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { notify } from '../lib/notify.svelte';
  import { session } from '../lib/session.svelte';
  import { ROLES, TENANT_ROLES } from '../lib/roles';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { secondFactor } from '../lib/passkey';
  import { t } from '../lib/i18n';
  import type { Activation, Role, Tenant, User } from '../lib/types';
  import Modal from '../components/Modal.svelte';
  import Qr from '../components/Qr.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import ActivationCode from '../components/ActivationCode.svelte';
  import ApiTokens from '../components/ApiTokens.svelte';
  import RiskMarks from '../components/RiskMarks.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';

  // POST /users -> {user, activation}; PUT /users/{id} -> {user, totp_uri? (own account),
  // activation? (new_activation)}. Quorum-gated answers (202) carry the same fields next to
  // quorum_id; then `activation` is only the first half of the code.
  type UserResp = { user?: User; totp_uri?: string; activation?: Activation };
  const isSelf = (x: User | null) => !!x && x.id === session.user?.id;
  const privRole = (r: string) => r === 'admin' || r === 'security_officer';
  // single-sign-on accounts: role / tenants follow the IdP group mapping, credentials live at the IdP
  const isSso = (x: User | null) => x?.auth === 'oidc';

  // Phase 19b: a tenant admin manages the accounts of its own tenant (tenant admins, tenant users,
  // viewers); the tenant is fixed to theirs (the server enforces both).
  const tenantAdmin = $derived(session.user?.role === 'tenant_admin');
  const roleChoices = $derived(tenantAdmin ? TENANT_ROLES : ROLES);

  let items: User[] = $state([]);
  let tenants: Tenant[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      [items, tenants] = await Promise.all([get<User[]>('/users'), get<Tenant[]>('/tenants')]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  let open = $state(false);
  let editing: User | null = $state(null);
  let f = $state({
    name: '',
    password: '',
    role: 'operator' as Role,
    tenant: '',
    disabled: false,
    canDownload: true,
    expires: '',
    eligible: '',
  });
  // Phase 30: an eligible role for appliance-wide local operators and viewers (just-in-time elevation)
  const canBeEligible = $derived(
    (f.role === 'operator' || f.role === 'viewer') && !f.tenant && !isSso(editing) && !tenantAdmin,
  );
  // Phase 14d: download privilege defaults by role; expiry as a date (end of that day, local time)
  const roleDownloads = (r: Role) => r === 'admin' || r === 'operator' || r === 'tenant_admin' || r === 'tenant_user';
  const dateOf = (ts: number | null | undefined) => {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  };
  const tsOf = (date: string) => (date ? Math.floor(new Date(`${date}T23:59:59`).getTime() / 1000) : null);
  let downloadTouched = $state(false);
  $effect(() => {
    // viewers and security officers never download; otherwise a new account follows the
    // role's default until the box is changed by hand
    if (f.role === 'viewer' || f.role === 'security_officer') f.canDownload = false;
    else if (!downloadTouched && !editing) f.canDownload = roleDownloads(f.role);
  });
  let actFor: User | null = $state(null);
  let actOpen = $state(false);
  let shown = $state<{ name: string; activation: Activation | null }>({ name: '', activation: null });
  let shownOpen = $state(false);
  function showActivation(name: string, r: Outcome<UserResp> | null) {
    if (r?.data.activation) {
      shown = { name, activation: r.data.activation };
      shownOpen = true;
    }
  }
  // Re-authentication of the acting user: every password / authenticator change
  // (own or another user's) needs the current password and a fresh TOTP code (or a passkey,
  // Phase 21c: an empty code field means "confirm with a passkey").
  let re = $state({ password: '', totp: '' });
  const reauth = async () => ({ current_password: re.password, current_totp: await secondFactor(re.totp) });
  let resetFor: User | null = $state(null);
  let resetOpen = $state(false);
  const privileged = $derived(f.role === 'admin' || f.role === 'security_officer');

  // TOTP enrollment (shown once after create / reset)
  let enroll = $state<{ name: string; uri: string; pending: boolean } | null>(null);
  let enrollOpen = $state(false);
  const secret = $derived(enroll ? (new URL(enroll.uri).searchParams.get('secret') ?? '') : '');

  function edit(x: User | null) {
    editing = x;
    f = {
      name: x?.name ?? '',
      password: '',
      role: x?.role ?? (tenantAdmin ? 'tenant_user' : 'operator'),
      tenant: x?.tenant ?? (tenantAdmin ? (session.user?.tenant ?? '') : ''),
      disabled: x?.disabled ?? false,
      canDownload: x?.can_download ?? true,
      expires: dateOf(x?.expires),
      eligible: x?.eligible_role ?? '',
    };
    downloadTouched = false;
    re = { password: '', totp: '' };
    open = true;
  }

  function showEnroll(name: string, r: Outcome<UserResp> | null) {
    if (r?.data.totp_uri) {
      enroll = { name, uri: r.data.totp_uri, pending: r.quorum };
      enrollOpen = true;
    }
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const tenant = f.tenant || null;
    if (!editing) {
      const r = await act(
        post<UserResp>('/users', {
          name: f.name,
          role: f.role,
          tenant,
          can_download: f.canDownload,
          expires: tsOf(f.expires),
        }),
        t.created,
      );
      if (!r) return;
      open = false;
      showActivation(f.name, r);
    } else {
      const body: Record<string, unknown> = isSso(editing)
        ? { disabled: f.disabled }
        : { role: f.role, tenant, disabled: f.disabled };
      if (f.canDownload !== editing.can_download) body.can_download = f.canDownload;
      if (tsOf(f.expires) !== (editing.expires ?? null)) body.expires = tsOf(f.expires);
      const eligible = canBeEligible ? f.eligible || null : null;
      if (eligible !== (editing.eligible_role ?? null)) body.eligible_role = eligible;
      const id = editing.id;
      const extra =
        f.password && isSelf(editing) ? reauth().then((a) => ({ password: f.password, ...a })) : Promise.resolve({});
      const r = await act(
        extra.then((x) => put<UserResp>(`/users/${id}`, { ...body, ...x })),
        t.saved,
      );
      if (!r) return;
      open = false;
    }
    load();
  }

  async function endSessions(x: User) {
    if (!(await askConfirm(t.access.revokeUserConfirm(x.name)))) return;
    await act(post<{ revoked: number }>(`/users/${x.id}/sessions/revoke`, {}), (d) => t.access.revokedN(d.revoked));
  }

  function resetTotp(x: User) {
    resetFor = x;
    re = { password: '', totp: '' };
    resetOpen = true;
  }

  async function confirmReset(e: SubmitEvent) {
    e.preventDefault();
    const x = resetFor;
    if (!x) return;
    const r = await act(
      reauth().then((a) => put<UserResp>(`/users/${x.id}`, { reset_totp: true, ...a })),
      t.saved,
    );
    re = { password: '', totp: '' };
    if (!r) return;
    resetOpen = false;
    showEnroll(x.name, r);
  }

  function newActivation(x: User) {
    actFor = x;
    re = { password: '', totp: '' };
    actOpen = true;
  }

  async function confirmActivation(e: SubmitEvent) {
    e.preventDefault();
    const x = actFor;
    if (!x) return;
    const r = await act(
      reauth().then((a) => put<UserResp>(`/users/${x.id}`, { new_activation: true, ...a })),
      t.saved,
    );
    re = { password: '', totp: '' };
    if (!r) return;
    actOpen = false;
    showActivation(x.name, r);
    load();
  }

  function stateOf(x: User): { cls: string; text: string } {
    if (x.disabled) return { cls: 'bad', text: t.users.disabled };
    if (x.expires && x.expires <= Date.now() / 1000)
      return { cls: 'bad', text: t.access.expiredOn(fmtTime(x.expires)) };
    if (x.pending_activation) {
      const exp = x.activation_expires;
      const sub = !exp
        ? t.users.pendingApproval
        : exp < Date.now() / 1000
          ? t.users.expired
          : t.users.pendingUntil(fmtTime(exp));
      return { cls: 'warn', text: `${t.users.pending} · ${sub}` };
    }
    return { cls: 'ok', text: t.users.active };
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      notify('ok', t.users.copied);
    } catch {
      /* clipboard unavailable (non-secure context): the text is selectable */
    }
  }
</script>

<div class="page-head">
  <h1>{t.users.title}</h1>
  <button type="button" class="primary" onclick={() => edit(null)}><IconPlus aria-hidden="true" />{t.users.new}</button>
  <p class="lede">{t.users.lede}</p>
</div>
{#if tenantAdmin}<p class="muted">{t.users.tenantAdminHint}</p>{/if}
<ErrorBanner {error} />

<div class="card">
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.name}</th>
            <th scope="col">{t.users.role}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.state}</th>
            <th scope="col">{t.access.lastLogin}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            <tr use:rowClick={!tenantAdmin || TENANT_ROLES.includes(x.role) ? () => edit(x) : null}>
              <td><strong>{x.name}</strong></td>
              <td>
                {t.roles[x.role] ?? x.role}
                {#if x.eligible_role}<span class="chip accent" title={t.p30.elev.eligibleHint}
                    >{t.p30.elev.eligibleChip(t.roles[x.eligible_role])}</span
                  >{/if}
                {#if x.elevated_until}<span class="chip warn">{t.p30.elev.elevatedChip(fmtTime(x.elevated_until))}</span
                  >{/if}
              </td>
              <td>{x.tenant ?? t.allTenants}</td>
              <td>
                {#if x.disabled && x.pending_activation}
                  <span class="chip bad">{t.users.disabled}</span> <span class="chip warn">{t.users.pending}</span>
                {:else}
                  {@const st = stateOf(x)}
                  <span class="chip {st.cls}">{st.text}</span>
                {/if}
                {#if isSso(x)}<span class="chip accent sso-badge" title={t.users.ssoHint}>{t.users.sso}</span>{/if}
                {#if x.expires && x.expires > Date.now() / 1000}<span class="chip warn"
                    >{t.access.expiresOn(fmtTime(x.expires))}</span
                  >{/if}
                {#if x.can_download === false && x.role !== 'viewer' && x.role !== 'security_officer'}<span
                    class="chip"
                    title={t.access.canDownloadHint}>{t.access.noDownloadChip}</span
                  >{/if}
              </td>
              <td class="nowrap">{x.last_login ? fmtAgo(x.last_login) : t.ago.never}</td>
              <td class="actions">
                {#if !tenantAdmin || TENANT_ROLES.includes(x.role)}
                  <button type="button" class="small" onclick={() => edit(x)}>{t.edit}</button>
                {/if}
                {#if isSso(x) || (tenantAdmin && !TENANT_ROLES.includes(x.role))}
                  <!-- password and authenticator are managed by the identity provider -->
                {:else if isSelf(x)}
                  <button type="button" class="small" onclick={() => resetTotp(x)}>{t.users.resetTotp}</button>
                {:else}
                  <button type="button" class="small" onclick={() => newActivation(x)}>{t.users.newActivation}</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if session.user?.role === 'admin' && !session.impersonating}<RiskMarks hideEmpty />{/if}
{#if session.user?.role === 'admin' && !session.impersonating}<ApiTokens all />{/if}

<Modal bind:open title={editing ? `${t.users.title}: ${editing.name}` : t.users.new}>
  <form onsubmit={save}>
    {#if !editing}
      <div class="field">
        <label for="u-name">{t.name}</label>
        <input id="u-name" bind:value={f.name} required autocomplete="off" autocapitalize="none" spellcheck="false" />
      </div>
    {/if}
    {#if !editing}
      <p class="muted">{t.users.newHint}</p>
    {:else if isSso(editing)}
      <p class="banner info">{t.users.ssoHint}</p>
    {:else if isSelf(editing)}
      <div class="field">
        <label for="u-pw">{t.users.passwordOwn}</label>
        <input id="u-pw" type="password" bind:value={f.password} minlength="12" autocomplete="new-password" />
      </div>
    {/if}
    <div class="form-grid">
      <div class="field">
        <label for="u-role">{t.users.role}</label>
        <select id="u-role" bind:value={f.role} disabled={isSso(editing)}>
          {#each roleChoices as r (r)}<option value={r}>{t.roles[r]}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="u-tenant">{t.tenant}</label>
        <select
          id="u-tenant"
          bind:value={f.tenant}
          required={f.role === 'tenant_user' || f.role === 'tenant_admin'}
          disabled={isSso(editing) || tenantAdmin}
          aria-describedby="u-tenant-hint"
        >
          {#if !tenantAdmin}<option value="">{t.allTenants}</option>{/if}
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
        <div class="hint" id="u-tenant-hint">{t.users.tenantHint}</div>
      </div>
    </div>
    {#if editing && f.password && isSelf(editing)}
      <fieldset>
        <legend>{t.users.reauth}</legend>
        <p class="muted">{t.users.reauthHint}</p>
        {@render reauthFields('u')}
      </fieldset>
    {/if}
    {#if privileged && editing?.role !== f.role}<p class="banner info">{t.users.privilegedHint}</p>{/if}
    {#if editing && !tenantAdmin && !isSso(editing)}
      <div class="field">
        <label for="u-eligible">{t.p30.elev.eligible}</label>
        <select id="u-eligible" bind:value={f.eligible} disabled={!canBeEligible} aria-describedby="u-eligible-hint">
          <option value="">{t.p30.elev.eligibleNone}</option>
          <option value="admin">{t.roles.admin}</option>
          <option value="security_officer">{t.roles.security_officer}</option>
        </select>
        <div class="hint" id="u-eligible-hint">{t.p30.elev.eligibleHint}</div>
      </div>
    {/if}
    {#if f.role === 'viewer'}<p class="muted">{t.access.viewerHint}</p>{/if}
    <div class="form-grid">
      <div class="field">
        <label class="inline-check" title={t.access.canDownloadHint}>
          <input
            type="checkbox"
            bind:checked={f.canDownload}
            onchange={() => (downloadTouched = true)}
            disabled={f.role === 'viewer' || f.role === 'security_officer'}
          />{t.access.canDownload}
        </label>
        <div class="hint">{t.access.canDownloadHint}</div>
      </div>
      <div class="field">
        <label for="u-expires">{t.access.expires}</label>
        <input id="u-expires" type="date" bind:value={f.expires} aria-describedby="u-expires-hint" />
        <div class="hint" id="u-expires-hint">{t.access.expiresHint}</div>
      </div>
    </div>
    {#if editing}
      <div class="field">
        <label class="inline-check"><input type="checkbox" bind:checked={f.disabled} />{t.users.disabled}</label>
      </div>
      <div class="field">
        <button type="button" class="small" onclick={() => endSessions(editing!)}>{t.access.revokeUser}</button>
      </div>
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>

{#snippet reauthFields(id: string)}
  <div class="form-grid">
    <div class="field">
      <label for="{id}-cur-pw">{t.users.currentPassword}</label>
      <input id="{id}-cur-pw" type="password" bind:value={re.password} required autocomplete="current-password" />
    </div>
    <div class="field">
      <label for="{id}-cur-totp">{t.users.currentTotp}</label>
      <input
        id="{id}-cur-totp"
        bind:value={re.totp}
        inputmode="numeric"
        pattern={'[0-9]{6}'}
        maxlength="6"
        autocomplete="one-time-code"
        aria-describedby="{id}-cur-totp-hint"
      />
      <div class="hint" id="{id}-cur-totp-hint">{t.passkeys.totpOrPasskey}</div>
    </div>
  </div>
{/snippet}

<Modal bind:open={resetOpen} title="{t.users.resetTotp}: {resetFor?.name ?? ''}">
  <form onsubmit={confirmReset}>
    <p>{t.users.resetConfirm}</p>
    <p class="muted">{t.users.reauthHint}</p>
    {@render reauthFields('r')}
    <div class="form-actions">
      <button type="button" onclick={() => (resetOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.users.resetTotp}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={actOpen} title="{t.users.newActivation}: {actFor?.name ?? ''}">
  <form onsubmit={confirmActivation}>
    <p>{t.users.newActivationConfirm}</p>
    {#if actFor && privRole(actFor.role)}<p class="banner info">{t.users.newActivationPriv}</p>{/if}
    <p class="muted">{t.users.reauthHint}</p>
    {@render reauthFields('a')}
    <div class="form-actions">
      <button type="button" onclick={() => (actOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.users.newActivation}</button>
    </div>
  </form>
</Modal>

<ActivationCode bind:open={shownOpen} name={shown.name} activation={shown.activation} />

<Modal bind:open={enrollOpen} title="{t.users.enroll}: {enroll?.name ?? ''}">
  {#if enroll}
    <p>{t.users.enrollHint}</p>
    {#if enroll.pending}<p class="banner pending">{t.users.enrollPending}</p>{/if}
    <div class="qr-box">
      <Qr text={enroll.uri} label="{t.users.enroll} {enroll.name}" />
      <div>
        <div class="field">
          <span class="muted">{t.users.secret}</span>
          <code class="secret">{secret}</code>
          <button type="button" class="small" onclick={() => copy(secret)}>{t.users.copy}</button>
        </div>
        <div class="field">
          <span class="muted">{t.users.uri}</span>
          <code class="secret">{enroll.uri}</code>
          <button type="button" class="small" onclick={() => copy(enroll!.uri)}>{t.users.copy}</button>
        </div>
      </div>
    </div>
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (enrollOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>
