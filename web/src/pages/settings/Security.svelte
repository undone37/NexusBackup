<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, act, errText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { t } from '../../lib/i18n';
  import type { SecuritySettings, SessionInfo } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import SessionTable from '../../components/SessionTable.svelte';

  // Phase 14d settings (docs/control-plane.md "Access"). The server gates: longer session
  // timeouts and every allow-list change need approval; the rest applies directly (audited).
  let cur: SecuritySettings | null = $state(null);
  let error: string | null = $state(null);
  let sess = $state({ idle_min: 30, absolute_h: 12 });
  let dormant = $state(0);
  let banner = $state('');
  let mgmt = $state('');
  let confirmIp = $state('');
  let sessions: SessionInfo[] = $state([]);
  const isAdmin = $derived(session.user?.role === 'admin');

  async function load() {
    try {
      cur = await get<SecuritySettings>('/settings/security');
      sess = { ...cur.session };
      dormant = cur.dormant_days;
      banner = cur.login_banner;
      mgmt = cur.mgmt_allow.join('\n');
      confirmIp = '';
      if (isAdmin) sessions = await get<SessionInfo[]>('/sessions');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  const mgmtList = $derived(
    mgmt
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean),
  );
  // client-side hint only (exact CIDR matching happens on the server)
  const lockout = $derived.by(() => {
    const ip = cur?.client_ip ?? '';
    return mgmtList.length > 0 && !mgmtList.some((c) => c === ip || covers(c, ip));
  });

  function covers(c: string, ip: string): boolean {
    const [net, p] = c.split('/');
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(net ?? '') || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
    const n = (s: string) => s.split('.').reduce((a, x) => a * 256 + Number(x), 0);
    const size = 2 ** (32 - Number(p ?? 32));
    return Math.floor(n(net) / size) === Math.floor(n(ip) / size);
  }

  async function saveSession(e: SubmitEvent) {
    e.preventDefault();
    if (await act(put('/settings/session', { idle_min: Number(sess.idle_min), absolute_h: Number(sess.absolute_h) }), t.saved)) load();
  }
  async function saveDormant(e: SubmitEvent) {
    e.preventDefault();
    if (await act(put('/settings/dormant', { days: Number(dormant) }), t.saved)) load();
  }
  async function saveBanner(e: SubmitEvent) {
    e.preventDefault();
    if (await act(put('/settings/banner', { banner }), t.saved)) load();
  }
  async function saveMgmt(e: SubmitEvent) {
    e.preventDefault();
    const body = lockout ? { mgmt_allow: mgmtList, force: true, confirm: confirmIp.trim() } : { mgmt_allow: mgmtList };
    if (await act(put('/settings/mgmt-allow', body), t.saved)) load();
  }
</script>

<ErrorBanner {error} />
{#if !cur}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  <section class="card settings-section" aria-labelledby="sec-mgmt">
    <div class="card-head"><h2 id="sec-mgmt">{t.access.mgmt}</h2></div>
    <p>{t.access.mgmtHint}</p>
    <p class="muted">
      {cur.mgmt_allow.length ? cur.mgmt_allow.join(', ') : t.access.mgmtAny} · {t.access.mgmtYou(cur.client_ip, cur.client_allowed)}
    </p>
    {#if cur.pending.mgmt_allow}
      <p class="banner pending"><span>{t.access.pending(cur.pending.mgmt_allow)} <a href={href('/quorum')}>{t.nav.quorum}</a></span></p>
    {/if}
    <form onsubmit={saveMgmt}>
      <fieldset disabled={!isAdmin}>
        <div class="field">
          <label for="sec-mgmt-list">{t.access.mgmtField}</label>
          <textarea id="sec-mgmt-list" rows="4" bind:value={mgmt} spellcheck="false" autocapitalize="none"></textarea>
        </div>
        {#if lockout && isAdmin}
          <p class="banner warn" role="alert">{t.access.mgmtLockout(cur.client_ip)}</p>
          <div class="field">
            <label for="sec-mgmt-confirm">{t.access.mgmtConfirm}</label>
            <input id="sec-mgmt-confirm" bind:value={confirmIp} required autocomplete="off" spellcheck="false" />
          </div>
        {/if}
      </fieldset>
      {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
    </form>
  </section>

  <section class="card settings-section" aria-labelledby="sec-sess">
    <div class="card-head"><h2 id="sec-sess">{t.access.timeouts}</h2></div>
    <p>{t.access.timeoutsHint}</p>
    {#if cur.pending.session}
      <p class="banner pending"><span>{t.access.pending(cur.pending.session)} <a href={href('/quorum')}>{t.nav.quorum}</a></span></p>
    {/if}
    <form onsubmit={saveSession}>
      <fieldset disabled={!isAdmin}>
        <div class="form-grid">
          <div class="field">
            <label for="sec-idle">{t.access.idle}</label>
            <input id="sec-idle" type="number" min="5" max="120" step="1" bind:value={sess.idle_min} required />
          </div>
          <div class="field">
            <label for="sec-abs">{t.access.absolute}</label>
            <input id="sec-abs" type="number" min="1" max="24" step="1" bind:value={sess.absolute_h} required />
          </div>
        </div>
      </fieldset>
      {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
    </form>
  </section>

  <section class="card settings-section" aria-labelledby="sec-dormant">
    <div class="card-head">
      <h2 id="sec-dormant">{t.access.dormant}</h2>
      <span class="chip {cur.dormant_days ? 'ok' : 'warn'}">{cur.dormant_days ? `${cur.dormant_days} d` : t.quorum.off}</span>
    </div>
    <p>{t.access.dormantHint}</p>
    <form onsubmit={saveDormant}>
      <fieldset disabled={!isAdmin}>
        <div class="field">
          <label for="sec-days">{t.access.dormantDays}</label>
          <input id="sec-days" type="number" min="0" max="3650" step="1" bind:value={dormant} required />
        </div>
      </fieldset>
      {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
    </form>
  </section>

  <section class="card settings-section" aria-labelledby="sec-banner">
    <div class="card-head"><h2 id="sec-banner">{t.access.banner}</h2></div>
    <p>{t.access.bannerHint}</p>
    <form onsubmit={saveBanner}>
      <fieldset disabled={!isAdmin}>
        <div class="field">
          <label for="sec-banner-text" class="visually-hidden">{t.access.banner}</label>
          <textarea id="sec-banner-text" rows="4" maxlength="2000" bind:value={banner}></textarea>
        </div>
      </fieldset>
      {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
    </form>
  </section>

  {#if isAdmin}
    <section class="card settings-section" aria-labelledby="sec-all">
      <div class="card-head"><h2 id="sec-all">{t.access.allSessions}</h2></div>
      <SessionTable {sessions} showUser revokeAll onchange={load} />
    </section>
  {:else}
    <p class="hint">{t.settings.readOnly}</p>
  {/if}
{/if}
