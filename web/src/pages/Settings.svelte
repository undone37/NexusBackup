<script lang="ts">
  import type { Component } from 'svelte';
  import { session } from '../lib/session.svelte';
  import { route, navigate } from '../lib/router.svelte';
  import { t } from '../lib/i18n';
  import type { User } from '../lib/types';
  import Approvals from './settings/Approvals.svelte';
  import AlertDelivery from './settings/AlertDelivery.svelte';
  import Sso from './settings/Sso.svelte';
  import SshKeys from './settings/SshKeys.svelte';
  import Updates from './settings/Updates.svelte';
  import Anomaly from './settings/Anomaly.svelte';
  import Certificate from './settings/Certificate.svelte';
  import Diagnostics from './settings/Diagnostics.svelte';

  // Tabs per role (docs/phase12-contract.md: alerts + SSO readable by admins and security officers,
  // SSH keys + updates also by operators; diagnostics: checks for both, support bundles for admins;
  // only admins change anything — the server decides).
  // appliance-wide settings: never for tenant-scoped accounts (as the route guard in App.svelte)
  const officer = (u: User | null) => !u?.tenant && (u?.role === 'admin' || u?.role === 'security_officer');
  const staff = (u: User | null) => officer(u) || (!u?.tenant && u?.role === 'operator');
  const TABS: { id: string; comp: Component<any>; allow: (u: User | null) => boolean }[] = [
    { id: 'approvals', comp: Approvals, allow: staff },
    { id: 'alerts', comp: AlertDelivery, allow: officer },
    { id: 'sso', comp: Sso, allow: officer },
    { id: 'ssh', comp: SshKeys, allow: staff },
    { id: 'updates', comp: Updates, allow: staff },
    { id: 'anomaly', comp: Anomaly, allow: officer },
    { id: 'certificate', comp: Certificate, allow: officer },
    { id: 'diagnostics', comp: Diagnostics, allow: officer },
  ];
  const tabs = $derived(TABS.filter((x) => x.allow(session.user)));
  const tab = $derived(tabs.find((x) => x.id === route.query.get('tab')) ?? tabs[0]);
  const id = $props.id();

  function select(next: string) {
    navigate(`/settings?tab=${next}`);
  }
  // arrow keys move between tabs (WAI-ARIA tabs pattern, automatic activation)
  function keys(e: KeyboardEvent) {
    const i = tabs.findIndex((x) => x.id === tab?.id);
    const n = tabs.length;
    const j = e.key === 'ArrowRight' ? (i + 1) % n : e.key === 'ArrowLeft' ? (i + n - 1) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
    if (j < 0) return;
    e.preventDefault();
    select(tabs[j].id);
  }
  // focus the selected tab after keyboard navigation (the page re-renders on the new route)
  $effect(() => {
    if (sessionStorage.getItem('nexus.tabFocus') === '1') {
      sessionStorage.removeItem('nexus.tabFocus');
      document.getElementById(`${id}-tab-${tab?.id}`)?.focus();
    }
  });
</script>

<div class="page-head">
  <h1>{t.settings.title}</h1>
  <p class="lede">{t.settings.lede}</p>
</div>

<div class="tabs" role="tablist" aria-label={t.settings.title} tabindex="-1" onkeydown={(e) => (sessionStorage.setItem('nexus.tabFocus', '1'), keys(e))}>
  {#each tabs as x (x.id)}
    <button
      type="button"
      role="tab"
      id="{id}-tab-{x.id}"
      aria-selected={x.id === tab?.id}
      aria-controls="{id}-panel"
      tabindex={x.id === tab?.id ? 0 : -1}
      onclick={() => select(x.id)}>{t.settings.tabs[x.id]}</button
    >
  {/each}
</div>

{#if tab}
  <div id="{id}-panel" role="tabpanel" aria-labelledby="{id}-tab-{tab.id}">
    <tab.comp />
  </div>
{/if}
