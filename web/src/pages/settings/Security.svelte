<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, act, errText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { t } from '../../lib/i18n';
  import type { PasskeySettings, RiskSettings, RiskThresholds, SecuritySettings, SessionInfo } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import SessionTable from '../../components/SessionTable.svelte';
  import RiskMarks from '../../components/RiskMarks.svelte';

  // Phase 14d settings (docs/control-plane.md "Access"). The server gates: longer session
  // timeouts need approval (the allow-list moved to Settings → Firewall); the rest applies directly (audited).
  let cur: SecuritySettings | null = $state(null);
  let error: string | null = $state(null);
  let sess = $state({ idle_min: 30, absolute_h: 12 });
  let dormant = $state(0);
  let maxSessions = $state(5);
  let dekDays = $state(365);
  let banner = $state('');
  let sessions: SessionInfo[] = $state([]);
  // Phase 21c: passkey requirement for admins / security officers, relying party ID
  let pk: PasskeySettings | null = $state(null);
  let pkf = $state({ require_privileged: false, rp_id: '' });
  const isAdmin = $derived(session.user?.role === 'admin');
  // Phase 30: role elevation needs a second person
  let elevApproval = $state(false);
  // Phase 39 S2: thresholds of the risk-signal rules (gated; loosening counts as weakening)
  let risk: RiskSettings | null = $state(null);
  let rf = $state<RiskThresholds | null>(null);

  async function load() {
    try {
      cur = await get<SecuritySettings>('/settings/security');
      sess = { ...cur.session };
      dormant = cur.dormant_days;
      maxSessions = cur.max_sessions;
      dekDays = cur.dek_rotation_days;
      banner = cur.login_banner;
      elevApproval = cur.elevation.settings.approval;
      pk = await get<PasskeySettings>('/settings/passkeys');
      pkf = { ...pk.policy };
      risk = await get<RiskSettings>('/settings/risk');
      rf = { ...risk.thresholds };
      if (isAdmin) sessions = await get<SessionInfo[]>('/sessions');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  async function saveSession(e: SubmitEvent) {
    e.preventDefault();
    if (
      await act(
        put('/settings/session', { idle_min: Number(sess.idle_min), absolute_h: Number(sess.absolute_h) }),
        t.saved,
      )
    )
      load();
  }
  async function savePasskeys(e: SubmitEvent) {
    e.preventDefault();
    if (
      await act(
        put('/settings/passkeys', { require_privileged: pkf.require_privileged, rp_id: pkf.rp_id.trim() }),
        t.saved,
      )
    )
      load();
  }
  async function saveDormant(e: SubmitEvent) {
    e.preventDefault();
    if (await act(put('/settings/dormant', { days: Number(dormant) }), t.saved)) load();
  }
  async function saveMaxSessions(e: SubmitEvent) {
    e.preventDefault();
    if (await act(put('/settings/max-sessions', { max: Number(maxSessions) }), t.saved)) load();
  }
  async function saveDek(e: SubmitEvent) {
    e.preventDefault();
    if (await act(put('/settings/dek-rotation', { days: Number(dekDays) }), t.saved)) load();
  }
  async function saveRisk(e: SubmitEvent) {
    e.preventDefault();
    if (!rf) return;
    const n = (v: unknown) => Number(v);
    const thresholds = {
      ...rf,
      weakening_burst: n(rf.weakening_burst),
      delete_burst: n(rf.delete_burst),
      download_factor: n(rf.download_factor),
      download_floor_mib: n(rf.download_floor_mib),
      hour_baseline_days: n(rf.hour_baseline_days),
      hour_min_sign_ins: n(rf.hour_min_sign_ins),
    };
    if (await act(put('/settings/risk', { thresholds }), t.saved)) load();
  }
  async function saveElevation(e: SubmitEvent) {
    e.preventDefault();
    if (await act(put('/settings/elevation', { approval: elevApproval }), t.saved)) load();
  }
  async function saveBanner(e: SubmitEvent) {
    e.preventDefault();
    if (await act(put('/settings/banner', { banner }), t.saved)) load();
  }
</script>

<ErrorBanner {error} />
{#if !cur}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  <section class="card settings-section" aria-labelledby="sec-mgmt">
    <div class="card-head"><h2 id="sec-mgmt">{t.access.mgmt}</h2></div>
    <p>{t.access.mgmtHint} <a href={href('/settings?tab=firewall')}>{t.access.mgmtLink}</a></p>
  </section>

  {#if pk}
    <section class="card settings-section" aria-labelledby="sec-pk">
      <div class="card-head">
        <h2 id="sec-pk">{t.passkeys.settingsTitle}</h2>
        <span class="chip {pk.policy.require_privileged ? 'ok' : ''}"
          >{pk.policy.require_privileged ? t.passkeys.on : t.passkeys.off}</span
        >
      </div>
      <p>{t.passkeys.settingsHint}</p>
      {#if pk.pending}
        <p class="banner pending">
          <span>{t.passkeys.pending(pk.pending)} <a href={href('/quorum')}>{t.nav.quorum}</a></span>
        </p>
      {/if}
      {#if pk.without_passkey.length}
        <p class="banner {pk.policy.require_privileged ? 'warn' : 'info'}">{t.passkeys.without(pk.without_passkey)}</p>
      {:else if pk.rp_id}
        <p class="muted">{t.passkeys.allHave}</p>
      {/if}
      <form onsubmit={savePasskeys}>
        <fieldset disabled={!isAdmin}>
          <div class="field">
            <label class="inline-check"
              ><input type="checkbox" bind:checked={pkf.require_privileged} />{t.passkeys.require}</label
            >
          </div>
          <div class="field">
            <label for="sec-rp">{t.passkeys.rpId}</label>
            <input
              id="sec-rp"
              bind:value={pkf.rp_id}
              placeholder={pk.rp_id ?? ''}
              autocapitalize="none"
              spellcheck="false"
              aria-describedby="sec-rp-hint"
            />
            <div class="hint" id="sec-rp-hint">{t.passkeys.rpIdHint(pk.rp_id)}</div>
          </div>
        </fieldset>
        {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
      </form>
    </section>
  {/if}

  <section class="card settings-section" aria-labelledby="sec-sess">
    <div class="card-head"><h2 id="sec-sess">{t.access.timeouts}</h2></div>
    <p>{t.access.timeoutsHint}</p>
    {#if cur.pending.session}
      <p class="banner pending">
        <span>{t.access.pending(cur.pending.session)} <a href={href('/quorum')}>{t.nav.quorum}</a></span>
      </p>
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

  <section class="card settings-section" aria-labelledby="sec-elev">
    <div class="card-head">
      <h2 id="sec-elev">{t.p30.elev.settingsTitle}</h2>
      <span class="chip {cur.elevation.settings.approval ? 'ok' : 'plain'}"
        >{cur.elevation.settings.approval ? t.p30.elev.withApproval : t.p30.elev.withoutApproval}</span
      >
      {#if cur.elevation.pending}<span class="chip warn">{t.quorumPending(cur.elevation.pending)}</span>{/if}
    </div>
    <p>{t.p30.elev.settingsHint(cur.elevation.min_minutes, cur.elevation.max_minutes)}</p>
    <form onsubmit={saveElevation}>
      <fieldset disabled={!isAdmin}>
        <label class="inline-check"><input type="checkbox" bind:checked={elevApproval} />{t.p30.elev.approval}</label>
        <div class="hint">{t.p30.elev.approvalHint}</div>
      </fieldset>
      {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
    </form>
  </section>

  <section class="card settings-section" aria-labelledby="sec-max">
    <div class="card-head">
      <h2 id="sec-max">{t.access.maxSessions}</h2>
      <span class="chip plain">{cur.max_sessions}</span>
    </div>
    <p>{t.access.maxSessionsHint}</p>
    <form onsubmit={saveMaxSessions}>
      <fieldset disabled={!isAdmin}>
        <div class="field">
          <label for="sec-max-n">{t.access.maxSessionsLabel}</label>
          <input id="sec-max-n" type="number" min="1" max="50" step="1" bind:value={maxSessions} required />
        </div>
      </fieldset>
      {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
    </form>
  </section>

  <section class="card settings-section" aria-labelledby="sec-dek">
    <div class="card-head">
      <h2 id="sec-dek">{t.access.dekRotation}</h2>
      <span class="chip {cur.dek_rotation_days ? 'ok' : 'warn'}"
        >{cur.dek_rotation_days ? `${cur.dek_rotation_days} d` : t.quorum.off}</span
      >
    </div>
    <p>{t.access.dekRotationHint}</p>
    <form onsubmit={saveDek}>
      <fieldset disabled={!isAdmin}>
        <div class="field">
          <label for="sec-dek-days">{t.access.dekRotationDays}</label>
          <input id="sec-dek-days" type="number" min="0" max="3650" step="1" bind:value={dekDays} required />
        </div>
      </fieldset>
      {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
    </form>
  </section>

  <section class="card settings-section" aria-labelledby="sec-dormant">
    <div class="card-head">
      <h2 id="sec-dormant">{t.access.dormant}</h2>
      <span class="chip {cur.dormant_days ? 'ok' : 'warn'}"
        >{cur.dormant_days ? `${cur.dormant_days} d` : t.quorum.off}</span
      >
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

  {#if risk && rf}
    <section class="card settings-section" aria-labelledby="sec-risk">
      <div class="card-head">
        <h2 id="sec-risk">{t.riskSettings.title}</h2>
        {#if risk.request_pending}<a class="chip warn" href={href(`/quorum?id=${risk.request_pending}`)}
            >{t.riskSettings.pending(risk.request_pending)}</a
          >{/if}
      </div>
      <p>{t.riskSettings.hint}</p>
      <form onsubmit={saveRisk}>
        <fieldset disabled={!isAdmin}>
          <div class="form-grid">
            {#each [['weakening_burst', t.riskSettings.weakening, 2, 50], ['delete_burst', t.riskSettings.deletes, 2, 200], ['download_factor', t.riskSettings.factor, 2, 1000], ['download_floor_mib', t.riskSettings.floor, 64, 1048576], ['hour_baseline_days', t.riskSettings.baseline, 14, 365], ['hour_min_sign_ins', t.riskSettings.minSignIns, 3, 100]] as [key, label, min, max] (key)}
              <div class="field">
                <label for="risk-{key}">{label}</label>
                <input
                  id="risk-{key}"
                  type="number"
                  min={min as number}
                  max={max as number}
                  step="1"
                  bind:value={(rf as unknown as Record<string, number>)[key as string]}
                  required
                />
              </div>
            {/each}
          </div>
          <label class="inline-check"
            ><input type="checkbox" bind:checked={rf.token_networks} />{t.riskSettings.tokens}</label
          >
          <div class="hint">
            {t.riskSettings.defaults(
              `${risk.defaults.weakening_burst} / ${risk.defaults.delete_burst} per hour, ${risk.defaults.download_factor}x and ${risk.defaults.download_floor_mib} MiB, ${risk.defaults.hour_baseline_days} days, ${risk.defaults.hour_min_sign_ins} sign-ins`,
            )}
          </div>
        </fieldset>
        {#if isAdmin}<div class="form-actions"><button type="submit" class="primary">{t.save}</button></div>{/if}
      </form>
    </section>
  {/if}

  <RiskMarks />

  {#if isAdmin}
    <section class="card settings-section" aria-labelledby="sec-all">
      <div class="card-head"><h2 id="sec-all">{t.access.allSessions}</h2></div>
      <SessionTable {sessions} showUser revokeAll onchange={load} />
    </section>
  {:else}
    <p class="hint">{t.settings.readOnly}</p>
  {/if}
{/if}
