<script lang="ts">
  import { rowClick } from '../lib/rowlink';
  import { askConfirm, askText } from '../lib/confirm.svelte';
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtBytes, fmtTime } from '../lib/format';
  import type { LockdownInfo, LoginResponse, OffsiteListed, Policy, QuorumRequest, Tenant, TenantOffsite, TenantTombstone, SftpRemote, S3Remote } from '../lib/types';
  import { copyText } from '../lib/clipboard';
  import { setSession } from '../lib/session.svelte';
  import Modal from '../components/Modal.svelte';
  import BlackoutEditor from '../components/BlackoutEditor.svelte';
  import { bandwidthWeaker, timeZones, validRateWindow, type RateWindow } from '../lib/schedule';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import TenantRecoveryKey from '../components/TenantRecoveryKey.svelte';
  import TenantWizard from '../components/TenantWizard.svelte';
  import Sso from './settings/Sso.svelte';
  import Menu, { type MenuItem } from '../components/Menu.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconCloud from '@lucide/svelte/icons/cloud';
  import IconLink from '@lucide/svelte/icons/link';
  import IconKey from '@lucide/svelte/icons/key-round';
  import IconCloudDown from '@lucide/svelte/icons/cloud-download';
  import IconLockdown from '@lucide/svelte/icons/shield-ban';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { route, navigate } from '../lib/router.svelte';
  import { runJob } from '../lib/jobs';
  import { fetchFromOffsite, listedStatus } from '../lib/offsite';

  let items: Tenant[] = $state([]);
  // Phase 23a: onboarding wizard, the tenant's own IdP
  let wizardOpen = $state(false);
  let idpOf: string | null = $state(null);
  let idpOpen = $state(false);
  // tenant whose recovery key dialog is open (17e)
  let keyOf: string | null = $state(null);
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
    loadRequests();
    loadTenancy();
    loadLockdowns();
  }

  // Phase 28: tenant lockdown (incident mode for one tenant); lifting needs approval
  let lockdowns: LockdownInfo[] = $state([]);
  async function loadLockdowns() {
    if (can.lockdown(session.user)) lockdowns = await get<LockdownInfo[]>('/lockdowns').catch(() => []);
  }
  const lockOf = (name: string) => lockdowns.find((l) => l.tenant === name) ?? null;
  let ldOf: Tenant | null = $state(null);
  let ldOpen = $state(false);
  let ldReason = $state('');
  let ldHold: 'all' | 'range' | 'none' = $state('all');
  let ldFrom = $state('');
  let ldTo = $state('');
  let ldPassword = $state('');
  let ldTotp = $state('');
  let ldBusy = $state(false);
  // Phase 29: freezes of the lockdown (configuration of the tenant is always refused)
  let ldFreeze = $state({ deletions: false, restores: false });
  const ldParts = (l: LockdownInfo) =>
    [l.freeze?.deletions && t.p29.freeze.names.deletions, l.freeze?.restores && t.p29.freeze.names.restores].filter((x): x is string => !!x);
  function openLockdown(x: Tenant) {
    const local = (ts: number) => {
      const d = new Date(ts * 1000);
      return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    };
    const now = Math.floor(Date.now() / 1000);
    ldOf = x;
    ldReason = '';
    ldHold = 'all';
    ldFrom = local(now - 7 * 86400);
    ldTo = local(now);
    ldPassword = '';
    ldTotp = '';
    ldFreeze = { deletions: false, restores: false };
    ldOpen = true;
  }
  async function submitLockdown(e: SubmitEvent) {
    e.preventDefault();
    if (!ldOf) return;
    const ts = (v: string) => Math.floor(new Date(v).getTime() / 1000);
    const body: Record<string, unknown> = {
      reason: ldReason.trim(),
      freeze: { ...ldFreeze },
      current_password: ldPassword,
      current_totp: ldTotp.trim(),
    };
    if (ldHold === 'none') body.hold = null;
    if (ldHold === 'range') body.hold = { from: ts(ldFrom), to: ts(ldTo) };
    ldBusy = true;
    const ok = await act(post(`/tenants/${encodeURIComponent(ldOf.name)}/lockdown`, body), t.lockdown.done(ldOf.name));
    ldBusy = false;
    if (ok) {
      ldOpen = false;
      load();
    }
  }
  async function liftFreeze(x: Tenant) {
    if (!(await askConfirm(t.p29.freeze.liftConfirm))) return;
    if (await act(post(`/tenants/${encodeURIComponent(x.name)}/lockdown/freeze/lift`), t.p29.freeze.liftRequested)) loadLockdowns();
  }
  async function liftLockdown(x: Tenant) {
    if (!(await askConfirm(t.lockdown.liftConfirm(x.name)))) return;
    if (await act(post(`/tenants/${encodeURIComponent(x.name)}/lockdown/lift`), t.lockdown.liftRequested)) loadLockdowns();
  }

  // Phase 19b: assigned policies (admin), deleted names (admin, security officer)
  let policies: Policy[] = $state([]);
  let tombstones: TenantTombstone[] = $state([]);
  async function loadTenancy() {
    if (can.configure(session.user)) policies = await get<Policy[]>('/policies').catch(() => []);
    if (canKey) tombstones = await get<TenantTombstone[]>('/tenants/tombstones').catch(() => []);
  }
  const policyName = (id: number) => policies.find((p) => p.id === id)?.name ?? `#${id}`;
  let assignOf: Tenant | null = $state(null);
  let assignOpen = $state(false);
  let assigned: number[] = $state([]);
  function openAssign(x: Tenant) {
    assignOf = x;
    assigned = [...(x.policies ?? [])];
    assignOpen = true;
  }
  async function saveAssign(e: SubmitEvent) {
    e.preventDefault();
    if (!assignOf) return;
    const path = `/tenants/${encodeURIComponent(assignOf.name)}/policies`;
    if (await act(put(path, { policy_ids: assigned }), t.tenants.assignedSaved)) {
      assignOpen = false;
      load();
    }
  }

  // "View as tenant" (read-only, immediately) / "Act as tenant admin" (approval)
  async function impersonate(x: Tenant, elevated: boolean) {
    const q = elevated ? t.impersonate.actConfirm(x.name) : t.impersonate.viewConfirm(x.name);
    if (!(await askConfirm(q))) return;
    const o = await act(post(`/tenants/${encodeURIComponent(x.name)}/impersonate`, { elevated }), t.impersonate.started(x.name));
    if (!o || o.quorum) return;
    const me = await get<LoginResponse>('/auth/me').catch(() => null);
    if (me) {
      setSession(me.user, me.csrf);
      session.impersonating = me.impersonating ?? null;
      navigate('/');
    }
  }
  onMount(async () => {
    await load();
    // `?offsite=<tenant>` opens that tenant's offsite copy (links, ui-smoke)
    const o = items.find((x) => x.name === route.query.get('offsite'));
    if (o && can.restore(session.user)) openCopy(o);
    // `?wizard=1` / `?idp=<tenant>` (Phase 23a; links, ui-smoke)
    if (route.query.get('wizard') && can.configure(session.user)) wizardOpen = true;
    const i = items.find((x) => x.name === route.query.get('idp'));
    if (i && canKey) ((idpOf = i.name), (idpOpen = true));
  });

  // Phase 17d: attach requests (`tenant.attach_offsite`) still open
  let requests: QuorumRequest[] = $state([]);
  async function loadRequests() {
    if (!can.attachOffsite(session.user)) return;
    try {
      const qs = await get<QuorumRequest[]>('/quorum');
      requests = qs.filter((q) => q.action === 'tenant.attach_offsite' && (q.state === 'pending' || q.state === 'approved'));
    } catch {
      requests = [];
    }
  }
  const canKey = $derived(['admin', 'security_officer'].includes(session.user?.role ?? ''));

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
  // "Attach offsite copy" uses the same target form (step 1: request + approval)
  let attaching = $state(false);
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
  // Phase 17a: bandwidth windows of the offsite uploads
  let windows: RateWindow[] = $state([]);
  let tz = $state('UTC');
  const zones = timeZones();
  // soft quota in GiB (null = none); saved separately (PUT /tenants/{name}/quota, applies at once)
  const GIB = 2 ** 30;
  let quota: number | null = $state(null);

  function edit(x: Tenant | null, attach = false) {
    attaching = attach;
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
    windows = $state.snapshot(x?.offsite?.windows ?? []);
    tz = x?.offsite?.timezone ?? 'UTC';
    quota = x?.quota_bytes ? +(x.quota_bytes / GIB).toFixed(2) : null;
    if (attach) kind = 'sftp';
    open = true;
  }

  function offsite(): TenantOffsite {
    if (kind === 'none') return {};
    const common: TenantOffsite = { uploaders: Number(uploaders) || 1, bwlimit: bwlimit ? Number(bwlimit) * 1024 : null };
    if (windows.length) common.windows = $state.snapshot(windows);
    if (windows.length || tz !== 'UTC') common.timezone = tz;
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

  // an existing target whose windows allow more bandwidth: approval (shown before saving)
  const weaker = $derived.by(() => {
    const o = (editing as Tenant | null)?.offsite;
    return (
      !!o?.remote &&
      kind !== 'none' &&
      bandwidthWeaker({ windows: o.windows ?? [], base: o.bwlimit, tz: o.timezone ?? 'UTC' }, { windows, base: bwlimit ? Number(bwlimit) * 1024 : null, tz })
    );
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!windows.every(validRateWindow)) return;
    const o = offsite();
    if (attaching) {
      const r = await act(post<{ quorum_id?: number }>('/tenants/attach', { name, offsite: o }), t.offsite.attachDirect);
      if (!r) return;
      open = false;
      await loadRequests();
      // approvals disabled: the request is approved at once, the key can follow
      const q = requests.find((x) => x.id === r.data.quorum_id && x.state === 'approved');
      if (!r.quorum && q) openKey(q);
      return;
    }
    const r = editing
      ? await act(put(`/tenants/${encodeURIComponent(editing.name)}`, { offsite: o }), t.saved)
      : await act(post('/tenants', { name, offsite: o }), t.created);
    const q = quota ? Math.round(quota * GIB) : null;
    if (r && q !== (editing?.quota_bytes ?? null))
      await act(put(`/tenants/${encodeURIComponent(editing?.name ?? name)}/quota`, { quota_bytes: q }), t.storage.quotaSaved);
    if (r) {
      open = false;
      load();
    }
  }

  // Step 2 of the attach: the requester enters the old appliance's recovery key once.
  let keyOpen = $state(false);
  let keyReq: QuorumRequest | null = $state(null);
  let recoveryKey = $state('');
  let busy = $state(false);
  function openKey(q: QuorumRequest) {
    keyReq = q;
    recoveryKey = '';
    keyOpen = true;
  }
  async function runAttach(e: SubmitEvent) {
    e.preventDefault();
    if (!keyReq) return;
    busy = true;
    const r = await act(post<{ id: number }>(`/tenants/attach/${keyReq.id}/run`, { recovery_key: recoveryKey }), (d) =>
      t.offsite.runStarted(d.id),
    );
    busy = false;
    recoveryKey = '';
    if (r && !r.quorum) {
      keyOpen = false;
      navigate(`/jobs/${r.data.id}`);
    }
  }
  const reqName = (q: QuorumRequest) => String(q.params.name ?? '');
  const reqTarget = (q: QuorumRequest) => summary(q.params.offsite as TenantOffsite | undefined);

  // Offsite copy of a tenant: `offsite_list` (what the target holds), fetch back
  let copyOpen = $state(false);
  let copyOf: Tenant | null = $state(null);
  let listed: OffsiteListed[] | null = $state(null);
  let listedAt = $state(0);
  let checking = $state(false);
  let abort: AbortController | null = null;
  function openCopy(x: Tenant) {
    copyOf = x;
    listed = null;
    copyOpen = true;
    check();
  }
  async function check() {
    if (!copyOf) return;
    abort?.abort();
    abort = new AbortController();
    checking = true;
    try {
      const r = await runJob('offsite_list', copyOf.name, {}, abort.signal);
      if (r?.job.state === 'ok') {
        listed = (r.job.result?.snapshots as OffsiteListed[] | undefined) ?? [];
        listedAt = r.job.finished ?? Date.now() / 1000;
      } else if (r) error = (r.job.log ?? '').split('\n').filter(Boolean).pop() ?? r.job.state;
    } catch (e) {
      error = errText(e);
    }
    checking = false;
  }
  $effect(() => {
    if (!copyOpen) abort?.abort();
  });
  async function fetchBack(x: OffsiteListed) {
    if (!copyOf) return;
    const id = await fetchFromOffsite(copyOf.name, x.source, x.time);
    if (id) navigate(`/jobs/${id}`);
  }
  // Phase 17f: deactivation needs approval (backups stop); reactivation applies at once
  async function deactivate(x: Tenant) {
    const reason = await askText(t.tdis.reason(x.name));
    if (!reason?.trim()) return;
    if (await act(post(`/tenants/${encodeURIComponent(x.name)}/deactivate`, { reason: reason.trim() }), t.tdis.done)) load();
  }
  async function reactivate(x: Tenant) {
    if (!(await askConfirm(t.tdis.reactivateConfirm(x.name)))) return;
    if (await act(post(`/tenants/${encodeURIComponent(x.name)}/reactivate`), t.tdis.reactivated)) load();
  }

  async function remove(x: Tenant) {
    if (!(await askConfirm(t.confirmDelete(`${t.tenant} "${x.name}"`)))) return;
    if (await act(del(`/tenants/${encodeURIComponent(x.name)}`), t.deleted)) load();
  }
  /** The other actions of a tenant row (Edit and View as tenant are buttons of their own). */
  function tenantActions(x: Tenant, r: unknown): MenuItem[] {
    const out: MenuItem[] = [];
    if (r && can.restore(session.user)) out.push({ label: t.offsite.copy, icon: IconCloud, title: t.offsite.copyLabel(x.name), onselect: () => openCopy(x) });
    if (can.configure(session.user))
      out.push(x.disabled ? { label: t.tdis.reactivate, onselect: () => reactivate(x) } : { label: t.tdis.deactivate, onselect: () => deactivate(x) });
    if (can.lockdown(session.user)) {
      const l = lockOf(x.name);
      if (!l) out.push({ label: t.lockdown.action, icon: IconLockdown, title: t.lockdown.actionLabel(x.name), onselect: () => openLockdown(x) });
      else if (!l.lift_quorum) out.push({ label: t.lockdown.lift, title: t.lockdown.liftLabel(x.name), onselect: () => liftLockdown(x) });
      if (l && ldParts(l).length && !l.freeze_lift_quorum)
        out.push({ label: t.p29.freeze.lift, title: t.p29.freeze.liftLabel(x.name), onselect: () => liftFreeze(x) });
    }
    if (canKey) {
      out.push({ label: t.tkey.button, onselect: () => (keyOf = x.name) });
      out.push({ label: t.sp.idp.button, title: t.sp.idp.label(x.name), onselect: () => ((idpOf = x.name), (idpOpen = true)) });
    }
    if (can.configure(session.user)) out.push({ label: t.delete, onselect: () => remove(x) });
    return out;
  }
</script>

<div class="page-head">
  <h1>{t.tenants.title}</h1>
  {#if can.configure(session.user)}
    <button type="button" class="primary" onclick={() => (wizardOpen = true)}><IconPlus aria-hidden="true" />{t.tenants.new}</button>
  {/if}
  {#if can.attachOffsite(session.user)}
    <button type="button" onclick={() => edit(null, true)}><IconLink aria-hidden="true" />{t.offsite.attach}</button>
  {/if}
  <p class="lede">{t.tenants.lede}</p>
</div>
<ErrorBanner {error} />
{#each lockdowns as l (l.tenant)}
  <p class="banner error" role="alert">{t.lockdown.banner(l.tenant, l.by, fmtTime(l.since), l.reason)}</p>
{/each}

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
            <th scope="col">{t.tdis.status}</th>
            <th scope="col">{t.tenants.offsite}</th>
            <th scope="col">{t.tenants.uploaders}</th>
            <th scope="col">{t.storage.quota}</th>
            {#if can.configure(session.user)}<th scope="col">{t.tenants.assigned}</th>{/if}
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.name)}
            {@const r = remoteOf(x.offsite)}
            <tr use:rowClick={can.configure(session.user) ? () => edit(x) : null}>
              <td>
                <strong>{x.name}</strong>
                {#each x.tiers ?? [] as tier (tier)}<span class="chip accent">{t.tiers.names[tier]}</span>{/each}
                {#if x.uid}
                  <div>
                    <button type="button" class="link mono muted" title={`${t.tenants.uid}: ${x.uid} — ${t.tenants.uidHint}`} onclick={() => copyText(x.uid ?? '')}
                      >{x.uid.slice(0, 8)}…</button
                    >
                  </div>
                {/if}
              </td>
              <td>
                {#if x.disabled}
                  <span class="chip warn" title={t.tdis.since(x.disabled_by ?? '—', fmtTime(x.disabled_at), x.disabled_reason ?? '')}>{t.tdis.deactivated}</span>
                  <div class="muted">{x.disabled_reason}</div>
                {:else if !lockOf(x.name)}
                  <span class="chip ok">{t.tdis.active}</span>
                {/if}
                {#if lockOf(x.name)}
                  {@const l = lockOf(x.name)!}
                  <span class="chip bad" title={t.lockdown.chipTitle(l.by, fmtTime(l.since), l.reason)}>{t.lockdown.chip}</span>
                  {#if l.lift_quorum}<span class="chip warn plain">{t.lockdown.liftPending}</span>{/if}
                  {#if ldParts(l).length}<span class="chip warn plain">{t.p29.freeze.chip(ldParts(l))}</span>{/if}
                  {#if l.freeze_lift_quorum}<span class="chip warn plain">{t.p29.freeze.liftPendingShort}</span>{/if}
                {/if}
              </td>
              <td class="mono">
                {summary(x.offsite)}
                {#if r?.type === 's3' && r.lock}<span class="chip ok">{t.tenants.locked}</span>{/if}
              </td>
              <td>{r ? (x.offsite?.uploaders ?? 4) : '—'}</td>
              <td>{x.quota_bytes ? fmtBytes(x.quota_bytes) : '—'}</td>
              {#if can.configure(session.user)}
                <td class="nowrap">
                  <span title={(x.policies ?? []).map(policyName).join(', ')}
                    >{(x.policies ?? []).length ? t.tenants.assignedN((x.policies ?? []).length) : t.tenants.assignedNone}</span
                  >
                  <button type="button" class="small" onclick={() => openAssign(x)} aria-label={`${t.tenants.assigned}: ${x.name}`}>{t.edit}</button>
                </td>
              {/if}
              <td class="actions">
                {#if can.impersonate(session.user)}
                  <Menu
                    label={t.impersonate.view}
                    ariaLabel={`${t.impersonate.view}: ${x.name}`}
                    items={[
                      { label: t.impersonate.viewReadOnly, hint: t.impersonate.viewShort, title: t.impersonate.viewHint, onselect: () => impersonate(x, false) },
                      { label: t.impersonate.act, hint: t.impersonate.actShort, title: t.impersonate.actHint, onselect: () => impersonate(x, true) },
                    ]}
                  />
                {/if}
                {#if can.configure(session.user)}<button type="button" class="small" onclick={() => edit(x)}>{t.edit}</button>{/if}
                {#if tenantActions(x, r).length}
                  <Menu label={t.agents.more} ariaLabel={t.tenants.moreLabel(x.name)} items={tenantActions(x, r)} />
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if requests.length}
  <section class="card" aria-labelledby="att-h">
    <h2 id="att-h">{t.offsite.requests}</h2>
    <p class="muted">{t.offsite.requestsIntro}</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.offsite.reqTenant}</th>
            <th scope="col">{t.offsite.reqTarget}</th>
            <th scope="col">{t.offsite.reqBy}</th>
            <th scope="col">{t.offsite.reqState}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each requests as q (q.id)}
            <tr>
              <td><strong>{reqName(q)}</strong> <span class="muted">#{q.id}</span></td>
              <td class="mono">{reqTarget(q)}</td>
              <td>{q.requested_by}</td>
              <td>
                {#if q.state === 'pending'}<span class="chip warn">{t.offsite.waitApproval}</span>
                {:else}<span class="chip ok">{t.quorum.states.approved}{q.decided_by ? ` · ${q.decided_by}` : ''}</span>{/if}
              </td>
              <td class="actions">
                {#if q.state === 'approved' && q.requested_by === session.user?.name}
                  <button type="button" class="small primary" onclick={() => openKey(q)}><IconKey aria-hidden="true" />{t.offsite.enterKey}</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{/if}

{#if canKey && tombstones.length}
  <section class="card" aria-labelledby="tomb-h">
    <h2 id="tomb-h">{t.tenants.tombstones}</h2>
    <p class="muted">{t.tenants.tombstonesHint}</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.name}</th>
            <th scope="col">{t.tenants.uid}</th>
            <th scope="col">{t.tenants.deletedAt}</th>
            <th scope="col">{t.tenants.deletedBy}</th>
          </tr>
        </thead>
        <tbody>
          {#each tombstones as x (x.name)}
            <tr>
              <td><strong>{x.name}</strong></td>
              <td class="mono">{x.uid ?? '—'}</td>
              <td>{fmtTime(x.deleted_at)}</td>
              <td>{x.deleted_by}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{/if}

<Modal bind:open={assignOpen} title={assignOf ? `${t.tenants.assigned}: ${assignOf.name}` : ''}>
  <form onsubmit={saveAssign}>
    <p class="muted" id="assign-hint">{t.tenants.assignedHint}</p>
    <fieldset aria-describedby="assign-hint">
      <legend>{t.tenants.assigned}</legend>
      {#each policies as p (p.id)}
        <label class="inline-check">
          <input type="checkbox" value={p.id} bind:group={assigned} />
          {p.name}
          {#if p.tier}<span class="chip accent">{t.tiers.names[p.tier]}</span>{/if}
          <span class="muted mono">{p.schedule}</span>
        </label>
      {/each}
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (assignOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.save}</button>
    </div>
  </form>
</Modal>

<TenantRecoveryKey bind:tenant={keyOf} />

<Modal bind:open title={attaching ? t.offsite.attachTitle : editing ? `${t.tenant}: ${editing.name}` : t.tenants.new} wide>
  <form onsubmit={save}>
    {#if attaching}<p class="muted">{t.offsite.attachIntro}</p>{/if}
    {#if !editing}
      <div class="field">
        <label for="t-name">{attaching ? t.offsite.attachName : t.name}</label>
        <input
          id="t-name"
          bind:value={name}
          required
          pattern="[a-z0-9][a-z0-9\-]*"
          maxlength="32"
          aria-describedby={attaching ? 't-name-hint' : undefined}
        />
        {#if attaching}<div class="hint" id="t-name-hint">{t.offsite.attachNameHint}</div>{/if}
      </div>
    {/if}
    {#if !attaching}
      <div class="field">
        <label for="t-quota">{t.storage.quotaField}</label>
        <input id="t-quota" type="number" min="0.001" step="any" bind:value={quota} aria-describedby="t-quota-hint" />
        <div class="hint" id="t-quota-hint">{t.storage.quotaHint}</div>
      </div>
    {/if}
    <fieldset>
      <legend>{t.tenants.offsite}</legend>
      <div class="field">
        <label for="t-kind">{t.tenants.target}</label>
        <select id="t-kind" bind:value={kind}>
          {#each attaching ? ['sftp', 's3'] : ['none', 'sftp', 's3'] as k (k)}<option value={k}>{t.tenants.targets[k]}</option>{/each}
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
        <BlackoutEditor bind:windows mode="rate" idp="t-win" legend={t.windows.bandwidth} hint={t.tenants.windowsHint} />
        <div class="field">
          <label for="t-tz">{t.windows.timezone}</label>
          <select id="t-tz" bind:value={tz}>
            {#each zones as z (z)}<option value={z}>{z}</option>{/each}
          </select>
        </div>
        {#if weaker}<p class="banner warn" role="status">{t.windows.weaker}</p>{/if}
      {/if}
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{attaching ? t.offsite.attach : editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={keyOpen} title={keyReq ? t.offsite.keyTitle(reqName(keyReq)) : ''}>
  <form onsubmit={runAttach}>
    <p class="muted">{t.offsite.keyIntro}</p>
    <div class="field">
      <label for="att-key">{t.offsite.key}</label>
      <input
        id="att-key"
        class="mono"
        type="password"
        bind:value={recoveryKey}
        required
        autocomplete="off"
        spellcheck="false"
        aria-describedby="att-key-hint"
      />
      <div class="hint" id="att-key-hint">{t.offsite.keyHint}</div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (keyOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={busy}>{t.offsite.run}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={copyOpen} title={copyOf ? t.offsite.copyTitle(copyOf.name) : ''} wide>
  <p class="muted">{t.offsite.copyIntro}</p>
  {#if checking}
    <p class="muted" aria-busy="true">{t.offsite.checking}</p>
  {:else if listed}
    <p>{t.offsite.checked(listed.length, fmtTime(listedAt))}</p>
    {#if listed.length}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.offsite.source}</th>
              <th scope="col">{t.time}</th>
              <th scope="col" class="num">{t.offsite.size}</th>
              <th scope="col">{t.offsite.lock}</th>
              <th scope="col">{t.offsite.status}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each listed as x (`${x.source}/${x.time}`)}
              {@const [cls, text] = listedStatus(x)}
              <tr>
                <td class="mono">{x.source}</td>
                <td class="nowrap">{fmtTime(x.time)}</td>
                <td class="num">{x.size === null ? '—' : fmtBytes(x.size)}</td>
                <td class="nowrap">{x.lock_until > Date.now() / 1000 ? fmtTime(x.lock_until) : '—'}</td>
                <td><span class="chip {cls}">{text}</span></td>
                <td class="actions">
                  {#if !x.local && x.remote && x.inventory}
                    <button type="button" class="small" onclick={() => fetchBack(x)} aria-label={t.offsite.fetchLabel(x.source, fmtTime(x.time))}
                      ><IconCloudDown aria-hidden="true" />{t.offsite.fetch}</button
                    >
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
  <div class="form-actions">
    <button type="button" onclick={check} disabled={checking}>{t.offsite.check}</button>
    <button type="button" onclick={() => (copyOpen = false)}>{t.close}</button>
  </div>
</Modal>

<TenantWizard bind:open={wizardOpen} ondone={load} />
<Modal bind:open={idpOpen} wide title={idpOf ? t.sp.idp.title(idpOf) : ''}>
  {#if idpOf}<Sso tenant={idpOf} />{/if}
</Modal>

<Modal bind:open={ldOpen} title={ldOf ? t.lockdown.title(ldOf.name) : ''}>
  <form onsubmit={submitLockdown}>
    <p>{t.lockdown.intro}</p>
    <div class="field">
      <label for="ld-reason">{t.lockdown.reason}</label>
      <input id="ld-reason" maxlength="500" bind:value={ldReason} required />
    </div>
    <fieldset>
      <legend>{t.lockdown.hold}</legend>
      <label class="inline-check"><input type="radio" name="ld-hold" value="all" bind:group={ldHold} />{t.lockdown.holdAll}</label>
      <label class="inline-check"><input type="radio" name="ld-hold" value="range" bind:group={ldHold} />{t.lockdown.holdRange}</label>
      <label class="inline-check"><input type="radio" name="ld-hold" value="none" bind:group={ldHold} />{t.lockdown.holdNone}</label>
      {#if ldHold === 'range'}
        <div class="form-grid">
          <div class="field">
            <label for="ld-from">{t.lockdown.from}</label>
            <input id="ld-from" type="datetime-local" bind:value={ldFrom} required />
          </div>
          <div class="field">
            <label for="ld-to">{t.lockdown.to}</label>
            <input id="ld-to" type="datetime-local" bind:value={ldTo} required />
          </div>
        </div>
      {/if}
    </fieldset>
    <fieldset>
      <legend>{t.p29.freeze.legend}</legend>
      <p class="hint">{t.p29.freeze.introTenant}</p>
      <div class="field">
        <label class="inline-check"><input type="checkbox" bind:checked={ldFreeze.deletions} aria-describedby="ld-frz-del-hint" />{t.p29.freeze.deletions}</label>
        <p class="hint" id="ld-frz-del-hint">{t.p29.freeze.deletionsHint}</p>
      </div>
      <div class="field">
        <label class="inline-check"><input type="checkbox" bind:checked={ldFreeze.restores} aria-describedby="ld-frz-res-hint" />{t.p29.freeze.restores}</label>
        <p class="hint" id="ld-frz-res-hint">{t.p29.freeze.restoresHint}</p>
      </div>
    </fieldset>
    <p>{t.incident.reauth}</p>
    <div class="form-grid">
      <div class="field">
        <label for="ld-pw">{t.incident.password}</label>
        <input id="ld-pw" type="password" autocomplete="current-password" bind:value={ldPassword} required />
      </div>
      <div class="field">
        <label for="ld-totp">{t.incident.totp}</label>
        <input id="ld-totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{'{'}6{'}'}" bind:value={ldTotp} required />
      </div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (ldOpen = false)}>{t.cancel}</button>
      <button type="submit" class="danger" disabled={ldBusy || !ldReason.trim()}><IconLockdown aria-hidden="true" />{t.lockdown.confirm}</button>
    </div>
  </form>
</Modal>
