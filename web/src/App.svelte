<script lang="ts">
  import { onMount, type Component } from 'svelte';
  import { session, setSession } from './lib/session.svelte';
  import { route, match, href, navigate } from './lib/router.svelte';
  import { get, post, act } from './lib/api';
  import { can } from './lib/roles';
  import { t } from './lib/i18n';
  import { theme, setTheme, nextTheme } from './lib/theme.svelte';
  import type { Alert, ConsoleShell, LoginResponse, QuorumRequest, RestorePriority, User } from './lib/types';
  import Logo from './components/Logo.svelte';
  import Notices from './components/Notices.svelte';
  import ConfirmDialog from './components/ConfirmDialog.svelte';
  import StepUpDialog from './components/StepUpDialog.svelte';
  import ElevateDialog from './components/ElevateDialog.svelte';
  import Login from './pages/Login.svelte';
  import Activate from './pages/Activate.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Snapshots from './pages/Snapshots.svelte';
  import Storage from './pages/Storage.svelte';
  import Reports from './pages/Reports.svelte';
  import Files from './pages/Files.svelte';
  import Search from './pages/Search.svelte';
  import Hunt from './pages/Hunt.svelte';
  import Changes from './pages/Changes.svelte';
  import RestoreTests from './pages/RestoreTests.svelte';
  import RecoveryPlans from './pages/RecoveryPlans.svelte';
  import Jobs from './pages/Jobs.svelte';
  import JobDetail from './pages/JobDetail.svelte';
  import Alerts from './pages/Alerts.svelte';
  import Quorum from './pages/Quorum.svelte';
  import Audit from './pages/Audit.svelte';
  import Tenants from './pages/Tenants.svelte';
  import Sources from './pages/Sources.svelte';
  import Agents from './pages/Agents.svelte';
  import Replication from './pages/Replication.svelte';
  import Policies from './pages/Policies.svelte';
  import Groups from './pages/Groups.svelte';
  import Users from './pages/Users.svelte';
  import Plugins from './pages/Plugins.svelte';
  import Hardware from './pages/Hardware.svelte';
  import Settings from './pages/Settings.svelte';
  import Account from './pages/Account.svelte';
  import IconDashboard from '@lucide/svelte/icons/layout-dashboard';
  import IconVault from '@lucide/svelte/icons/lock-keyhole';
  import IconSnapshots from '@lucide/svelte/icons/database-backup';
  import IconSearch from '@lucide/svelte/icons/file-search';
  import IconHunt from '@lucide/svelte/icons/fingerprint';
  import IconCompare from '@lucide/svelte/icons/git-compare';
  import IconRestoreTest from '@lucide/svelte/icons/flask-conical';
  import IconRecovery from '@lucide/svelte/icons/life-buoy';
  import IconStorage from '@lucide/svelte/icons/hard-drive';
  import IconReports from '@lucide/svelte/icons/file-spreadsheet';
  import IconJobs from '@lucide/svelte/icons/list-checks';
  import IconAlerts from '@lucide/svelte/icons/bell';
  import IconApprovals from '@lucide/svelte/icons/stamp';
  import IconRunning from '@lucide/svelte/icons/activity';
  import IconAudit from '@lucide/svelte/icons/scroll-text';
  import IconTenants from '@lucide/svelte/icons/building';
  import IconSources from '@lucide/svelte/icons/server';
  import IconAgents from '@lucide/svelte/icons/computer';
  import IconReplication from '@lucide/svelte/icons/repeat-2';
  import IconPolicies from '@lucide/svelte/icons/calendar-clock';
  import IconGroups from '@lucide/svelte/icons/boxes';
  import IconUsers from '@lucide/svelte/icons/users';
  import IconPlugins from '@lucide/svelte/icons/puzzle';
  import IconHardware from '@lucide/svelte/icons/server-cog';
  import IconSettings from '@lucide/svelte/icons/settings';
  import IconMenu from '@lucide/svelte/icons/menu';
  import IconSun from '@lucide/svelte/icons/sun';
  import IconMoon from '@lucide/svelte/icons/moon';
  import IconSystem from '@lucide/svelte/icons/sun-moon';
  import IconLogout from '@lucide/svelte/icons/log-out';
  import IconCollapse from '@lucide/svelte/icons/panel-left-close';
  import IconExpand from '@lucide/svelte/icons/panel-left-open';
  import IconGlass from '@lucide/svelte/icons/shield-alert';
  import IconTerminal from '@lucide/svelte/icons/square-terminal';
  import IconSiren from '@lucide/svelte/icons/siren';
  import IconLifeBuoy from '@lucide/svelte/icons/life-buoy';
  import IconSnowflake from '@lucide/svelte/icons/snowflake';
  import IconStepUp from '@lucide/svelte/icons/user-lock';
  import IconElevate from '@lucide/svelte/icons/shield-plus';
  import { fmtTime } from './lib/format';

  type Allow = (u: User | null) => boolean;
  type Section = 'monitor' | 'governance' | 'config';
  const always: Allow = (u) => !!u;
  // Settings: approvals (everyone non-tenant), alerts / SSO (admin, security officer), SSH keys / updates (+ operator).
  const viewSettings: Allow = (u) => !!u && u.role !== 'tenant_user' && u.role !== 'viewer' && !u.tenant;
  // Approvals list: appliance-wide roles, and tenant admins for their own requests (Phase 19b).
  const viewApprovals: Allow = (u) => can.viewQuorum(u) || can.viewOwnQuorum(u);

  // Routes; `nav` entries appear in the sidebar (filtered by role — the server still decides).
  const routes: { path: string; comp: Component<any>; allow: Allow; nav?: string; section?: Section; icon?: Component<any> }[] = [
    { path: '/', comp: Dashboard, allow: always, nav: t.nav.dashboard, section: 'monitor', icon: IconDashboard },
    { path: '/snapshots', comp: Snapshots, allow: always, nav: t.nav.snapshots, section: 'monitor', icon: IconSnapshots },
    { path: '/search', comp: Search, allow: can.restore, nav: t.nav.search, section: 'monitor', icon: IconSearch },
    { path: '/hunt', comp: Hunt, allow: can.hunt, nav: t.nav.hunt, section: 'monitor', icon: IconHunt },
    { path: '/changes', comp: Changes, allow: can.restore, nav: t.nav.changes, section: 'monitor', icon: IconCompare },
    { path: '/restore-tests', comp: RestoreTests, allow: always, nav: t.nav.restoreTests, section: 'monitor', icon: IconRestoreTest },
    { path: '/storage', comp: Storage, allow: always, nav: t.nav.storage, section: 'monitor', icon: IconStorage },
    { path: '/reports', comp: Reports, allow: always, nav: t.nav.reports, section: 'monitor', icon: IconReports },
    { path: '/files', comp: Files, allow: can.restore },
    { path: '/jobs', comp: Jobs, allow: always, nav: t.nav.jobs, section: 'monitor', icon: IconJobs },
    { path: '/jobs/:id', comp: JobDetail, allow: always },
    { path: '/alerts', comp: Alerts, allow: can.viewAlerts, nav: t.nav.alerts, section: 'monitor', icon: IconAlerts },
    { path: '/quorum', comp: Quorum, allow: viewApprovals, nav: t.nav.quorum, section: 'governance', icon: IconApprovals },
    { path: '/audit', comp: Audit, allow: can.audit, nav: t.nav.audit, section: 'governance', icon: IconAudit },
    { path: '/tenants', comp: Tenants, allow: can.attachOffsite, nav: t.nav.tenants, section: 'config', icon: IconTenants },
    { path: '/sources', comp: Sources, allow: can.manageTenant, nav: t.nav.sources, section: 'config', icon: IconSources },
    { path: '/agents', comp: Agents, allow: can.manageTenant, nav: t.nav.agents, section: 'config', icon: IconAgents },
    { path: '/replication', comp: Replication, allow: can.viewReplication, nav: t.nav.replication, section: 'config', icon: IconReplication },
    { path: '/recovery-plans', comp: RecoveryPlans, allow: always, nav: t.nav.recoveryPlans, section: 'config', icon: IconRecovery },
    { path: '/policies', comp: Policies, allow: can.configure, nav: t.nav.policies, section: 'config', icon: IconPolicies },
    { path: '/groups', comp: Groups, allow: can.manageTenant, nav: t.nav.groups, section: 'config', icon: IconGroups },
    { path: '/users', comp: Users, allow: can.manageTenant, nav: t.nav.users, section: 'config', icon: IconUsers },
    { path: '/plugins', comp: Plugins, allow: can.viewPlugins, nav: t.nav.plugins, section: 'config', icon: IconPlugins },
    { path: '/hardware', comp: Hardware, allow: can.viewHardware, nav: t.nav.hardware, section: 'config', icon: IconHardware },
    { path: '/settings', comp: Settings, allow: viewSettings, nav: t.nav.settings, section: 'config', icon: IconSettings },
    { path: '/account', comp: Account, allow: always },
  ];
  const SECTIONS: { id: Section; label: string }[] = [
    { id: 'monitor', label: t.nav.monitor },
    { id: 'governance', label: t.nav.governance },
    { id: 'config', label: t.nav.config },
  ];

  const current = $derived.by(() => {
    for (const r of routes) {
      const params = match(r.path, route.path);
      if (params && r.allow(session.user)) return { comp: r.comp, params, key: `${route.path}?${route.query}` };
    }
    return null;
  });
  const navOf = (s: Section) => routes.filter((r) => r.nav && r.section === s && r.allow(session.user));
  const active = (p: string) => (p === '/' ? route.path === '/' : route.path === p || route.path.startsWith(p + '/'));
  // top-bar breadcrumb: section / page
  const crumb = $derived.by(() => {
    const r = routes.find((x) => x.nav && active(x.path)) ?? (route.path.startsWith('/files') ? routes[1] : null);
    return r ? { section: SECTIONS.find((s) => s.id === r.section)?.label ?? '', page: r.nav ?? '' } : null;
  });

  // Sidebar: collapsible to an icon rail (remembered per browser); off-canvas below 900 px.
  let menuOpen = $state(false);
  let collapsed = $state(localStorage.getItem('nexus.sidebar') === 'rail');
  function toggleRail() {
    collapsed = !collapsed;
    localStorage.setItem('nexus.sidebar', collapsed ? 'rail' : 'full');
  }
  $effect(() => {
    void route.path;
    menuOpen = false;
  });
  // A signed-in user landing on the sign-in route (e.g. after single sign-on) goes to the dashboard.
  $effect(() => {
    if (session.user && route.path === '/login') navigate('/');
  });

  // Badges: open unacknowledged alerts and pending approvals; the break-glass banner (contract §7) for admins.
  let alerts: Alert[] = $state([]);
  let pendingApprovals = $state(0);
  // jobs running right now (top bar, every page): refreshed every 10 s
  let runningJobs = $state(0);
  const openAlerts = $derived(alerts.filter((a) => !a.acked_by));
  const critical = $derived(openAlerts.some((a) => a.severity === 'critical'));
  const glass = $derived(session.user?.role === 'admin' ? openAlerts.find((a) => a.kind === 'break_glass') : undefined);
  // A root shell running on the appliance console (14c; GET /auth/me), for every appliance-wide role.
  let shell: ConsoleShell | null = $state(null);
  // Phase 21b: incident mode (GET /auth/me; appliance-wide accounts only)
  const incident = $derived(session.incident);
  // Phase 29: incident-mode / lockdown freezes and the account's risk mark (GET /auth/me)
  const frozen = $derived.by(() => {
    const f = session.freeze;
    if (!f) return null;
    const parts = [f.config && t.p29.freeze.names.config, f.deletions && t.p29.freeze.names.deletions, f.restores && t.p29.freeze.names.restores].filter(
      (x): x is string => !!x,
    );
    const tenants = (f.tenants ?? []).map((x) =>
      t.p29.freeze.tenantPart(x.tenant, [x.deletions && t.p29.freeze.names.deletions, x.restores && t.p29.freeze.names.restores].filter((y): y is string => !!y)),
    );
    return parts.length || tenants.length ? { parts, tenants } : null;
  });
  async function refreshCounts() {
    const u = session.user;
    if (!u) return;
    if (can.viewAlerts(u)) alerts = await get<Alert[]>('/alerts?state=open').catch(() => alerts);
    const me = await get<LoginResponse>('/auth/me').catch(() => null);
    if (me) {
      session.vault = !!me.vault_mode;
      session.impersonating = me.impersonating ?? null;
      if (can.viewQuorum(u)) shell = me.console_shell ?? null;
      session.incident = me.incident ?? null;
      session.freeze = me.freeze ?? null;
      session.stepUp = me.step_up ?? null;
      // Phase 30: an elevation that ended (expiry, another tab) brings the standing role back
      if ((me.elevation?.until ?? null) !== (session.elevation?.until ?? null) || me.user.role !== u.role) session.user = me.user;
      session.elevation = me.elevation ?? null;
    }
    // Phase 22b: restore priority (banner for everyone)
    session.priority = await get<RestorePriority>('/restore-priority').catch(() => session.priority);
    if (viewApprovals(u))
      pendingApprovals = await get<QuorumRequest[]>('/quorum')
        .then((q) => q.filter((x) => x.state === 'pending').length)
        .catch(() => pendingApprovals);
  }
  $effect(() => {
    if (!session.user) return;
    void route.path;
    refreshCounts();
    const iv = setInterval(refreshCounts, 30000);
    return () => clearInterval(iv);
  });
  $effect(() => {
    if (!session.user) return;
    const count = () => {
      if (document.visibilityState !== 'visible') return;
      get<unknown[]>('/jobs?state=running')
        .then((j) => (runningJobs = j.length))
        .catch(() => {});
    };
    count();
    const iv = setInterval(count, 10000);
    return () => clearInterval(iv);
  });
  async function ackGlass() {
    if (!glass) return;
    if (await act(post(`/alerts/${glass.id}/ack`), t.alerts.done)) refreshCounts();
  }
  const badge = (path: string) =>
    path === '/alerts' && openAlerts.length
      ? { n: openAlerts.length, cls: critical ? 'bad' : 'warn' }
      : path === '/quorum' && pendingApprovals
        ? { n: pendingApprovals, cls: 'warn' }
        : null;

  onMount(async () => {
    // After a reload the session cookie may still be valid; recover user + CSRF token.
    try {
      const me = await get<LoginResponse>('/auth/me');
      setSession(me.user, me.csrf);
      session.vault = !!me.vault_mode;
      session.impersonating = me.impersonating ?? null;
      shell = me.console_shell ?? null;
      session.incident = me.incident ?? null;
      session.freeze = me.freeze ?? null;
      session.stepUp = me.step_up ?? null;
      session.elevation = me.elevation ?? null;
    } catch {
      setSession(null, null);
    }
    session.ready = true;
  });

  async function logout() {
    try {
      await post('/auth/logout');
    } catch {
      /* session is gone either way */
    }
    setSession(null, null);
    navigate('/');
  }

  // "View as tenant" (Phase 19b): back to the admin's own role.
  async function endImpersonation() {
    if (!(await act(post('/auth/impersonation/end'), t.impersonate.ended))) return;
    const me = await get<LoginResponse>('/auth/me').catch(() => null);
    if (me) {
      setSession(me.user, me.csrf);
      session.impersonating = me.impersonating ?? null;
    }
    navigate('/tenants');
  }

  // Phase 30: just-in-time role elevation
  let elevateOpen = $state(false);
  async function endElevation() {
    if (!(await act(post('/auth/elevate/end'), t.p30.elev.ended))) return;
    const me = await get<LoginResponse>('/auth/me').catch(() => null);
    if (me) {
      setSession(me.user, me.csrf);
      session.elevation = me.elevation ?? null;
    }
  }

  function skipToMain() {
    document.getElementById('main')?.focus();
  }
  const themeLabel = $derived(`${t.nav.theme[theme.choice]} (${t.nav.themeNext[theme.choice]})`);
</script>

{#if !session.ready}
  <p class="loading-screen muted" aria-busy="true">{t.loading}</p>
{:else if route.path === '/activate'}
  <!-- self-enrollment: reachable without a session -->
  <Activate />
{:else if !session.user}
  <Login />
{:else}
  <button type="button" class="skip" onclick={skipToMain}>{t.skip}</button>
  <div class="shell" class:collapsed>
    <aside id="sidebar" class="sidebar" class:open={menuOpen}>
      <a class="brand" href={href('/')} aria-label={t.app}><Logo /><span class="label">{t.app}</span></a>
      <nav aria-label={t.nav.label}>
        {#each SECTIONS as s (s.id)}
          {@const items = navOf(s.id)}
          {#if items.length}
            <div class="section" id="nav-{s.id}"><span class="label">{s.label}</span></div>
            <ul aria-labelledby="nav-{s.id}">
              {#each items as r (r.path)}
                {@const b = badge(r.path)}
                <li>
                  <a
                    class="nav"
                    href={href(r.path)}
                    aria-current={active(r.path) ? 'page' : undefined}
                    title={collapsed ? r.nav : undefined}
                  >
                    {#if r.icon}<r.icon aria-hidden="true" />{/if}
                    <span class="label">{r.nav}</span>
                    {#if b}<span class="count {b.cls}"><span class="visually-hidden">(</span>{b.n}<span class="visually-hidden">)</span></span>{/if}
                  </a>
                </li>
              {/each}
            </ul>
          {/if}
        {/each}
      </nav>
      <div class="foot">
        <button type="button" class="collapse" onclick={toggleRail} aria-label={collapsed ? t.nav.expand : t.nav.collapse} title={collapsed ? t.nav.expand : undefined}>
          {#if collapsed}<IconExpand aria-hidden="true" />{:else}<IconCollapse aria-hidden="true" />{/if}
          <span class="label">{t.nav.collapse}</span>
        </button>
      </div>
    </aside>
    {#if menuOpen}
      <!-- tap outside the drawer closes it -->
      <button type="button" class="scrim" tabindex="-1" aria-label={t.close} onclick={() => (menuOpen = false)}></button>
    {/if}

    <div class="content">
      <header class="topbar">
        <button
          type="button"
          class="icon-btn menu-toggle"
          aria-expanded={menuOpen}
          aria-controls="sidebar"
          aria-label={t.nav.menu}
          onclick={() => (menuOpen = !menuOpen)}><IconMenu aria-hidden="true" /></button
        >
        <a class="brand" href={href('/')}><Logo />{t.app}</a>
        {#if crumb}
          <div class="crumbs">
            {#if crumb.section}<span>{crumb.section}</span><span aria-hidden="true">/</span>{/if}
            <strong>{crumb.page}</strong>
          </div>
        {/if}
        <span class="spacer"></span>
        {#if session.vault}
          {#if can.viewQuorum(session.user)}
            <a class="chip accent vault-badge" href={href('/settings?tab=vault')} title={t.vault.badgeTitle}><IconVault aria-hidden="true" />{t.vault.badge}</a>
          {:else}
            <span class="chip accent vault-badge" title={t.vault.badgeTitle}><IconVault aria-hidden="true" />{t.vault.badge}</span>
          {/if}
        {/if}
        <a
          class="icon-btn running"
          class:active={runningJobs > 0}
          href={href('/jobs?state=running')}
          aria-label={t.nav.jobsRunning(runningJobs)}
          title={t.nav.jobsRunning(runningJobs)}
        >
          <IconRunning aria-hidden="true" />
          {#if runningJobs}<span class="dot info" aria-hidden="true">{runningJobs}</span>{/if}
        </a>
        {#if viewApprovals(session.user)}
          <a class="icon-btn" href={href('/quorum')} aria-label={t.nav.approvalsPending(pendingApprovals)} title={t.nav.approvalsPending(pendingApprovals)}>
            <IconApprovals aria-hidden="true" />
            {#if pendingApprovals}<span class="dot warn" aria-hidden="true">{pendingApprovals}</span>{/if}
          </a>
        {/if}
        {#if can.viewAlerts(session.user)}
          <a class="icon-btn" href={href('/alerts')} aria-label={t.nav.alertsOpen(openAlerts.length)} title={t.nav.alertsOpen(openAlerts.length)}>
            <IconAlerts aria-hidden="true" />
            {#if openAlerts.length}<span class="dot" class:warn={!critical} aria-hidden="true">{openAlerts.length}</span>{/if}
          </a>
        {/if}
        <button type="button" class="icon-btn theme-toggle" aria-label={themeLabel} title={themeLabel} onclick={() => setTheme(nextTheme(theme.choice))}>
          {#if theme.choice === 'light'}<IconSun aria-hidden="true" />{:else if theme.choice === 'dark'}<IconMoon aria-hidden="true" />{:else}<IconSystem aria-hidden="true" />{/if}
        </button>
        <a class="whoami" href={href('/account')} title={t.account.title} aria-current={route.path === '/account' ? 'page' : undefined}>
          <span class="avatar" aria-hidden="true">{session.user.name.slice(0, 2)}</span>
          <span class="who">
            <strong>{session.user.name}</strong>
            <small>{t.roles[session.user.role]}{session.user.tenant ? ` · ${session.user.tenant}` : ''}</small>
          </span>
        </a>
        {#if session.user.eligible_role && !session.elevation && !session.impersonating}
          <button type="button" class="icon-btn" onclick={() => (elevateOpen = true)} aria-label={t.p30.elev.open(t.roles[session.user.eligible_role])} title={t.p30.elev.open(t.roles[session.user.eligible_role])}
            ><IconElevate aria-hidden="true" /></button
          >
        {/if}
        <button type="button" class="icon-btn" onclick={logout} aria-label={t.nav.logout} title={t.nav.logout}><IconLogout aria-hidden="true" /></button>
      </header>

      {#if session.impersonating}
        <div class="glass impersonating" role="status">
          <IconTenants aria-hidden="true" />
          <p>
            <strong>
              {session.impersonating.role === 'viewer'
                ? t.impersonate.bannerView(session.impersonating.tenant)
                : t.impersonate.bannerAct(session.impersonating.tenant)}
            </strong>
            {t.impersonate.bannerAudit}
          </p>
          <button type="button" class="small" onclick={endImpersonation}>{t.impersonate.end}</button>
        </div>
      {/if}
      {#if incident}
        <div class="glass" role="alert">
          <IconSiren aria-hidden="true" />
          <p>
            <strong>{t.incident.banner(incident.by, fmtTime(incident.since), incident.reason)}</strong>
            {#if can.viewQuorum(session.user)}<a href={href('/settings?tab=incident')}>{t.incident.open}</a>{/if}
          </p>
        </div>
      {/if}
      {#if frozen}
        <div class="glass" role="alert">
          <IconSnowflake aria-hidden="true" />
          <p>
            <strong>{frozen.parts.length ? t.p29.freeze.banner(frozen.parts) : t.p29.freeze.bannerTenants}</strong>
            {frozen.tenants.join(' · ')}
            {#if can.lockdown(session.user)}<a href={href(frozen.parts.length ? '/settings?tab=incident' : '/tenants')}>{t.p29.freeze.manage}</a>{/if}
          </p>
        </div>
      {/if}
      {#if session.elevation}
        <div class="glass priority" role="status">
          <IconElevate aria-hidden="true" />
          <p>
            <strong>{t.p30.elev.banner(t.roles[session.elevation.role], fmtTime(session.elevation.until))}</strong>
            {t.p30.elev.bannerStanding(t.roles[session.elevation.standing_role])}
          </p>
          <button type="button" class="small" onclick={endElevation}>{t.p30.elev.end}</button>
        </div>
      {/if}
      {#if session.stepUp}
        <div class="glass priority" role="status">
          <IconStepUp aria-hidden="true" />
          <p>
            <strong>{t.p29.stepUp.banner(session.stepUp.reason, fmtTime(session.stepUp.until))}</strong>
            {session.stepUp.done ? t.p29.stepUp.bannerDone : t.p29.stepUp.bannerTodo}
          </p>
        </div>
      {/if}
      {#if session.priority?.active}
        <div class="glass priority" role="status">
          <IconLifeBuoy aria-hidden="true" />
          <p>
            <strong>{t.priority.banner(fmtTime(session.priority.until ?? 0), session.priority.by ?? '?', session.priority.reason ?? '')}</strong>
            {t.priority.bannerHeld}
            {#if can.backup(session.user) && !session.user.tenant}<a href={href('/')}>{t.priority.manage}</a>{/if}
          </p>
        </div>
      {/if}
      {#if shell}
        <div class="glass" role="alert">
          <IconTerminal aria-hidden="true" />
          <p>
            <strong>{t.console.active}:</strong>
            {t.console.activeText(
              fmtTime(shell.at),
              fmtTime(shell.until),
              shell.method === 'code' ? t.console.viaCode(shell.unlock, shell.requested_by) : t.console.viaRecovery,
            )}
            <a href={href('/audit')}>{t.glass.audit}</a>
          </p>
        </div>
      {/if}
      {#if glass}
        <div class="glass" role="alert">
          <IconGlass aria-hidden="true" />
          <p>{t.glass.text(glass.message)} <a href={href('/audit')}>{t.glass.audit}</a></p>
          <button type="button" class="small" onclick={ackGlass}>{t.glass.ack}</button>
        </div>
      {/if}

      <main id="main" tabindex="-1">
        {#if current}
          {#key current.key}
            <current.comp {...current.params} />
          {/key}
        {:else}
          <h1>{t.notFound}</h1>
          <p><a href={href('/')}>{t.nav.dashboard}</a></p>
        {/if}
      </main>
    </div>
  </div>
{/if}
<Notices />
<ConfirmDialog />
<StepUpDialog />
<ElevateDialog bind:open={elevateOpen} />
