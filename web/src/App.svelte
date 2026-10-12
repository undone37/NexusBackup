<script lang="ts">
  import { onMount, type Component } from 'svelte';
  import { session, setSession } from './lib/session.svelte';
  import { route, match, href, navigate } from './lib/router.svelte';
  import { get, post, act } from './lib/api';
  import { can } from './lib/roles';
  import { t } from './lib/i18n';
  import { theme, setTheme, nextTheme } from './lib/theme.svelte';
  import type { Alert, ConsoleShell, LoginResponse, QuorumRequest, User } from './lib/types';
  import Logo from './components/Logo.svelte';
  import Notices from './components/Notices.svelte';
  import ConfirmDialog from './components/ConfirmDialog.svelte';
  import Login from './pages/Login.svelte';
  import Activate from './pages/Activate.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Snapshots from './pages/Snapshots.svelte';
  import Storage from './pages/Storage.svelte';
  import Reports from './pages/Reports.svelte';
  import Files from './pages/Files.svelte';
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
  import Settings from './pages/Settings.svelte';
  import IconDashboard from '@lucide/svelte/icons/layout-dashboard';
  import IconSnapshots from '@lucide/svelte/icons/database-backup';
  import IconStorage from '@lucide/svelte/icons/hard-drive';
  import IconReports from '@lucide/svelte/icons/file-spreadsheet';
  import IconJobs from '@lucide/svelte/icons/list-checks';
  import IconAlerts from '@lucide/svelte/icons/bell';
  import IconApprovals from '@lucide/svelte/icons/stamp';
  import IconAudit from '@lucide/svelte/icons/scroll-text';
  import IconTenants from '@lucide/svelte/icons/building';
  import IconSources from '@lucide/svelte/icons/server';
  import IconAgents from '@lucide/svelte/icons/computer';
  import IconReplication from '@lucide/svelte/icons/repeat-2';
  import IconPolicies from '@lucide/svelte/icons/calendar-clock';
  import IconGroups from '@lucide/svelte/icons/boxes';
  import IconUsers from '@lucide/svelte/icons/users';
  import IconPlugins from '@lucide/svelte/icons/puzzle';
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
  import { fmtTime } from './lib/format';

  type Allow = (u: User | null) => boolean;
  type Section = 'monitor' | 'governance' | 'config';
  const always: Allow = (u) => !!u;
  // Settings: approvals (everyone non-tenant), alerts / SSO (admin, security officer), SSH keys / updates (+ operator).
  const viewSettings: Allow = (u) => !!u && u.role !== 'tenant_user' && !u.tenant;

  // Routes; `nav` entries appear in the sidebar (filtered by role — the server still decides).
  const routes: { path: string; comp: Component<any>; allow: Allow; nav?: string; section?: Section; icon?: Component<any> }[] = [
    { path: '/', comp: Dashboard, allow: always, nav: t.nav.dashboard, section: 'monitor', icon: IconDashboard },
    { path: '/snapshots', comp: Snapshots, allow: always, nav: t.nav.snapshots, section: 'monitor', icon: IconSnapshots },
    { path: '/storage', comp: Storage, allow: always, nav: t.nav.storage, section: 'monitor', icon: IconStorage },
    { path: '/reports', comp: Reports, allow: always, nav: t.nav.reports, section: 'monitor', icon: IconReports },
    { path: '/files', comp: Files, allow: can.restore },
    { path: '/jobs', comp: Jobs, allow: always, nav: t.nav.jobs, section: 'monitor', icon: IconJobs },
    { path: '/jobs/:id', comp: JobDetail, allow: always },
    { path: '/alerts', comp: Alerts, allow: can.viewAlerts, nav: t.nav.alerts, section: 'monitor', icon: IconAlerts },
    { path: '/quorum', comp: Quorum, allow: can.viewQuorum, nav: t.nav.quorum, section: 'governance', icon: IconApprovals },
    { path: '/audit', comp: Audit, allow: can.audit, nav: t.nav.audit, section: 'governance', icon: IconAudit },
    { path: '/tenants', comp: Tenants, allow: can.configure, nav: t.nav.tenants, section: 'config', icon: IconTenants },
    { path: '/sources', comp: Sources, allow: can.configure, nav: t.nav.sources, section: 'config', icon: IconSources },
    { path: '/agents', comp: Agents, allow: can.configure, nav: t.nav.agents, section: 'config', icon: IconAgents },
    { path: '/replication', comp: Replication, allow: can.viewReplication, nav: t.nav.replication, section: 'config', icon: IconReplication },
    { path: '/policies', comp: Policies, allow: can.configure, nav: t.nav.policies, section: 'config', icon: IconPolicies },
    { path: '/groups', comp: Groups, allow: can.configure, nav: t.nav.groups, section: 'config', icon: IconGroups },
    { path: '/users', comp: Users, allow: can.configure, nav: t.nav.users, section: 'config', icon: IconUsers },
    { path: '/plugins', comp: Plugins, allow: can.viewPlugins, nav: t.nav.plugins, section: 'config', icon: IconPlugins },
    { path: '/settings', comp: Settings, allow: viewSettings, nav: t.nav.settings, section: 'config', icon: IconSettings },
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
  const openAlerts = $derived(alerts.filter((a) => !a.acked_by));
  const critical = $derived(openAlerts.some((a) => a.severity === 'critical'));
  const glass = $derived(session.user?.role === 'admin' ? openAlerts.find((a) => a.kind === 'break_glass') : undefined);
  // A root shell running on the appliance console (14c; GET /auth/me), for every appliance-wide role.
  let shell: ConsoleShell | null = $state(null);
  async function refreshCounts() {
    const u = session.user;
    if (!u) return;
    if (can.viewAlerts(u)) alerts = await get<Alert[]>('/alerts?state=open').catch(() => alerts);
    if (can.viewQuorum(u)) shell = await get<LoginResponse>('/auth/me').then((m) => m.console_shell ?? null).catch(() => shell);
    if (can.viewQuorum(u))
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
      shell = me.console_shell ?? null;
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
        {#if can.viewQuorum(session.user)}
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
        <div class="whoami">
          <span class="avatar" aria-hidden="true">{session.user.name.slice(0, 2)}</span>
          <span class="who">
            <strong>{session.user.name}</strong>
            <small>{t.roles[session.user.role]}{session.user.tenant ? ` · ${session.user.tenant}` : ''}</small>
          </span>
        </div>
        <button type="button" class="icon-btn" onclick={logout} aria-label={t.nav.logout} title={t.nav.logout}><IconLogout aria-hidden="true" /></button>
      </header>

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
