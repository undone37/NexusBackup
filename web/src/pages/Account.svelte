<script lang="ts">
  import { onMount } from 'svelte';
  import { get, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { SessionInfo } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import ApiTokens from '../components/ApiTokens.svelte';
  import SessionTable from '../components/SessionTable.svelte';
  import Passkeys from '../components/Passkeys.svelte';

  // My account (Phase 14d): who I am, where I am signed in (every user may end their own
  // sessions), my passkeys (Phase 21c, local accounts) and my API tokens.
  let sessions: SessionInfo[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  const u = $derived(session.user);

  async function load() {
    try {
      sessions = await get<SessionInfo[]>('/auth/sessions');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);
</script>

<div class="page-head">
  <h1>{t.account.title}</h1>
  <p class="lede">{t.access.accountLede}</p>
</div>
<ErrorBanner {error} />

{#if u}
  <section class="card" aria-labelledby="acc-h">
    <h2 id="acc-h" class="visually-hidden">{t.access.account}</h2>
    <dl class="kv">
      <dt>{t.name}</dt>
      <dd><strong>{u.name}</strong>{#if u.auth === 'oidc'} <span class="chip accent">{t.users.sso}</span>{/if}</dd>
      <dt>{t.users.role}</dt>
      <dd>{t.roles[u.role] ?? u.role}</dd>
      <dt>{t.tenant}</dt>
      <dd>{u.tenant ?? t.allTenants}</dd>
      <dt>{t.access.canDownload}</dt>
      <dd>{u.can_download ? t.yes : t.no}</dd>
      <dt>{t.access.expires}</dt>
      <dd>{u.expires ? fmtTime(u.expires) : t.ago.never}</dd>
    </dl>
    {#if u.role === 'viewer'}<p class="muted">{t.access.viewerHint}</p>{/if}
  </section>
{/if}

<section class="card" aria-labelledby="acc-s">
  <div class="card-head"><h2 id="acc-s">{t.access.sessions}</h2></div>
  <p class="muted">{t.access.sessionsLede}</p>
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else}
    <SessionTable {sessions} onchange={load} />
  {/if}
</section>

{#if u && u.auth !== 'oidc'}<Passkeys />{/if}

<ApiTokens />
