<script lang="ts">
  import { onMount, type Component } from 'svelte';
  import { session, setSession } from './lib/session.svelte';
  import { route, match, href, navigate } from './lib/router.svelte';
  import { get, post } from './lib/api';
  import { can } from './lib/roles';
  import { t } from './lib/i18n';
  import type { LoginResponse, User } from './lib/types';
  import logo from './favicon.svg';
  import Notices from './components/Notices.svelte';
  import Login from './pages/Login.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Snapshots from './pages/Snapshots.svelte';
  import Files from './pages/Files.svelte';
  import Jobs from './pages/Jobs.svelte';
  import JobDetail from './pages/JobDetail.svelte';
  import Alerts from './pages/Alerts.svelte';
  import Quorum from './pages/Quorum.svelte';
  import Audit from './pages/Audit.svelte';
  import Tenants from './pages/Tenants.svelte';
  import Sources from './pages/Sources.svelte';
  import Agents from './pages/Agents.svelte';
  import Policies from './pages/Policies.svelte';
  import Groups from './pages/Groups.svelte';
  import Users from './pages/Users.svelte';

  type Allow = (u: User | null) => boolean;
  const always: Allow = (u) => !!u;

  // Routes; `nav` entries appear in the sidebar (filtered by role — the server still decides).
  const routes: { path: string; comp: Component<any>; allow: Allow; nav?: string; section?: 'config' }[] = [
    { path: '/', comp: Dashboard, allow: always, nav: t.nav.dashboard },
    { path: '/snapshots', comp: Snapshots, allow: always, nav: t.nav.snapshots },
    { path: '/files', comp: Files, allow: can.restore },
    { path: '/jobs', comp: Jobs, allow: always, nav: t.nav.jobs },
    { path: '/jobs/:id', comp: JobDetail, allow: always },
    { path: '/alerts', comp: Alerts, allow: can.viewAlerts, nav: t.nav.alerts },
    { path: '/quorum', comp: Quorum, allow: can.viewQuorum, nav: t.nav.quorum },
    { path: '/audit', comp: Audit, allow: can.audit, nav: t.nav.audit },
    { path: '/tenants', comp: Tenants, allow: can.configure, nav: t.nav.tenants, section: 'config' },
    { path: '/sources', comp: Sources, allow: can.configure, nav: t.nav.sources, section: 'config' },
    { path: '/agents', comp: Agents, allow: can.configure, nav: t.nav.agents, section: 'config' },
    { path: '/policies', comp: Policies, allow: can.configure, nav: t.nav.policies, section: 'config' },
    { path: '/groups', comp: Groups, allow: can.configure, nav: t.nav.groups, section: 'config' },
    { path: '/users', comp: Users, allow: can.configure, nav: t.nav.users, section: 'config' },
  ];

  const current = $derived.by(() => {
    for (const r of routes) {
      const params = match(r.path, route.path);
      if (params && r.allow(session.user)) return { comp: r.comp, params, key: `${route.path}?${route.query}` };
    }
    return null;
  });
  const navMain = $derived(routes.filter((r) => r.nav && !r.section && r.allow(session.user)));
  const navConfig = $derived(routes.filter((r) => r.nav && r.section === 'config' && r.allow(session.user)));
  const active = (p: string) => (p === '/' ? route.path === '/' : route.path === p || route.path.startsWith(p + '/'));

  let menuOpen = $state(false);
  $effect(() => {
    void route.path;
    menuOpen = false;
  });

  onMount(async () => {
    // After a reload the session cookie may still be valid; recover user + CSRF token.
    try {
      const me = await get<LoginResponse>('/auth/me');
      setSession(me.user, me.csrf);
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
</script>

{#if !session.ready}
  <p class="login muted" aria-busy="true">{t.loading}</p>
{:else if !session.user}
  <Login />
{:else}
  <button type="button" class="skip" onclick={skipToMain}>{t.skip}</button>
  <div class="shell">
    <header class="topbar">
      <button
        type="button"
        class="menu-toggle"
        aria-expanded={menuOpen}
        aria-controls="sidebar"
        onclick={() => (menuOpen = !menuOpen)}>{t.nav.menu}</button
      >
      <a class="brand" href={href('/')}><img src={logo} alt="" />{t.app}</a>
      <span class="spacer"></span>
      <div class="whoami">
        {session.user.name}
        <small>{t.roles[session.user.role]}{session.user.tenant ? ` · ${session.user.tenant}` : ''}</small>
      </div>
      <button type="button" onclick={logout}>{t.nav.logout}</button>
    </header>

    <nav id="sidebar" class="sidebar" class:open={menuOpen} aria-label={t.nav.label}>
      <ul>
        {#each navMain as r (r.path)}
          <li><a href={href(r.path)} aria-current={active(r.path) ? 'page' : undefined}>{r.nav}</a></li>
        {/each}
      </ul>
      {#if navConfig.length}
        <div class="section" id="nav-config">{t.nav.config}</div>
        <ul aria-labelledby="nav-config">
          {#each navConfig as r (r.path)}
            <li><a href={href(r.path)} aria-current={active(r.path) ? 'page' : undefined}>{r.nav}</a></li>
          {/each}
        </ul>
      {/if}
    </nav>

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
{/if}
<Notices />
