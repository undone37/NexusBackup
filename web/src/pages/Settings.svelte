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
  import Forwarding from './settings/Forwarding.svelte';
  import Diagnostics from './settings/Diagnostics.svelte';
  import ConfigBackup from './settings/ConfigBackup.svelte';
  import Console from './settings/Console.svelte';
  import Security from './settings/Security.svelte';
  import Firewall from './settings/Firewall.svelte';
  import Network from './settings/Network.svelte';
  import Time from './settings/Time.svelte';
  import Vault from './settings/Vault.svelte';
  import Incident from './settings/Incident.svelte';
  import MalwareScan from './settings/MalwareScan.svelte';
  import HashLists from './settings/HashLists.svelte';
  import Edges from './settings/Edges.svelte';

  // Tabs per role (docs/phase12-contract.md: alerts + SSO readable by admins and security officers,
  // SSH keys + updates also by operators; diagnostics: checks for both, support bundles for admins;
  // only admins change anything — the server decides).
  // appliance-wide settings: never for tenant-scoped accounts (as the route guard in App.svelte)
  const officer = (u: User | null) => !u?.tenant && (u?.role === 'admin' || u?.role === 'security_officer');
  const staff = (u: User | null) => officer(u) || (!u?.tenant && u?.role === 'operator');
  // Grouped by what people come for (ported from NexusStor): the appliance itself, who may do what, how it
  // reports, threat detection, and keeping it running; the first tab of the list is the default.
  type Group = 'system' | 'access' | 'monitoring' | 'threats' | 'maintenance';
  const TABS: { id: string; group: Group; comp: Component<any>; allow: (u: User | null) => boolean }[] = [
    { id: 'network', group: 'system', comp: Network, allow: staff },
    { id: 'time', group: 'system', comp: Time, allow: staff },
    { id: 'certificate', group: 'system', comp: Certificate, allow: officer },
    { id: 'updates', group: 'system', comp: Updates, allow: staff },
    // Phase 26: edge proxies (GET /edges is admin only)
    { id: 'edges', group: 'system', comp: Edges, allow: (u) => !u?.tenant && u?.role === 'admin' },
    { id: 'approvals', group: 'access', comp: Approvals, allow: staff },
    { id: 'security', group: 'access', comp: Security, allow: officer },
    { id: 'firewall', group: 'access', comp: Firewall, allow: officer },
    { id: 'sso', group: 'access', comp: Sso, allow: officer },
    { id: 'ssh', group: 'access', comp: SshKeys, allow: staff },
    { id: 'console', group: 'access', comp: Console, allow: officer },
    { id: 'vault', group: 'access', comp: Vault, allow: staff },
    { id: 'alerts', group: 'monitoring', comp: AlertDelivery, allow: officer },
    { id: 'forwarding', group: 'monitoring', comp: Forwarding, allow: officer },
    { id: 'anomaly', group: 'threats', comp: Anomaly, allow: officer },
    { id: 'malware', group: 'threats', comp: MalwareScan, allow: officer },
    { id: 'iocHashes', group: 'threats', comp: HashLists, allow: officer },
    { id: 'incident', group: 'threats', comp: Incident, allow: officer },
    { id: 'diagnostics', group: 'maintenance', comp: Diagnostics, allow: officer },
    { id: 'configBackup', group: 'maintenance', comp: ConfigBackup, allow: officer },
  ];
  const GROUPS: Group[] = ['system', 'access', 'monitoring', 'threats', 'maintenance'];
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
    const j =
      e.key === 'ArrowRight' || e.key === 'ArrowDown'
        ? (i + 1) % n
        : e.key === 'ArrowLeft' || e.key === 'ArrowUp'
          ? (i + n - 1) % n
          : e.key === 'Home'
            ? 0
            : e.key === 'End'
              ? n - 1
              : -1;
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

<!-- narrow screens: one select instead of rows of tabs -->
<div class="field settings-pick">
  <label for="{id}-pick">{t.ux.settingsSection}</label>
  <select id="{id}-pick" value={tab?.id} onchange={(e) => select(e.currentTarget.value)}>
    {#each GROUPS as g (g)}
      {@const xs = tabs.filter((x) => x.group === g)}
      {#if xs.length}
        <optgroup label={t.ux.settingsGroups[g]}>
          {#each xs as x (x.id)}<option value={x.id}>{t.settings.tabs[x.id]}</option>{/each}
        </optgroup>
      {/if}
    {/each}
  </select>
</div>

<div class="settings-layout">
  <div
    class="tabs grouped"
    role="tablist"
    aria-label={t.settings.title}
    aria-orientation="vertical"
    tabindex="-1"
    onkeydown={(e) => (sessionStorage.setItem('nexus.tabFocus', '1'), keys(e))}
  >
    {#each tabs as x, i (x.id)}
      {#if i === 0 || tabs[i - 1].group !== x.group}
        <span class="tab-group" aria-hidden="true">{t.ux.settingsGroups[x.group]}</span>
      {/if}
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
    <div id="{id}-panel" class="settings-panel" role="tabpanel" aria-labelledby="{id}-tab-{tab.id}">
      <tab.comp />
    </div>
  {/if}
</div>

<style>
  /* Wide screens: the sections as a grouped list beside the page (20 tabs in a row wrapped into three
     rows); narrower: a select with the groups as option groups. */
  .settings-panel {
    min-width: 0;
  }
  .settings-layout {
    display: grid;
    grid-template-columns: 12.5rem minmax(0, 1fr);
    gap: 1.5rem;
    align-items: start;
  }
  .settings-pick {
    display: none;
  }
  .tabs.grouped {
    position: sticky;
    top: 4.5rem;
    flex-direction: column;
    flex-wrap: nowrap;
    gap: 0.1rem;
    margin: 0;
    border-bottom: 0;
    border-right: 1px solid var(--border);
    padding-right: 0.75rem;
  }
  .tab-group {
    display: block;
    margin: 0.9rem 0 0.25rem 0.8rem;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--muted);
  }
  .tab-group:first-child {
    margin-top: 0;
  }
  .tabs.grouped [role='tab'] {
    justify-content: flex-start;
    text-align: left;
    padding: 0.4rem 0.8rem;
    border-radius: var(--radius-s);
  }
  .tabs.grouped [role='tab']:hover {
    background: var(--surface-3);
  }
  .tabs.grouped [role='tab'][aria-selected='true'] {
    background: var(--surface);
    box-shadow: var(--shadow);
  }
  .tabs.grouped [role='tab'][aria-selected='true']::after {
    left: -0.05rem;
    right: auto;
    top: 0.45rem;
    bottom: 0.45rem;
    width: 3px;
    height: auto;
    border-radius: 2px;
  }
  @media (max-width: 1099px) {
    .settings-layout {
      display: block;
    }
    .settings-pick {
      display: block;
      max-width: 24rem;
      margin-bottom: 1rem;
    }
    .tabs.grouped {
      display: none;
    }
  }
</style>
