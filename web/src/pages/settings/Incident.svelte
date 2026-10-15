<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { Group, Incident, LoginResponse, Tenant } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconSiren from '@lucide/svelte/icons/siren';

  // Phase 21b: incident mode (docs/control-plane.md "Incident mode"). Entering: security officers,
  // re-authenticated, at once; leaving: an approval request (security officer or admin).
  let inc: Incident | null = $state(null);
  let tenants: Tenant[] = $state([]);
  let groups: Group[] = $state([]);
  let error: string | null = $state(null);
  const officer = $derived(session.user?.role === 'security_officer');
  const canLeave = $derived(officer || session.user?.role === 'admin');

  // the form: hold the last 7 days by default, pause every group
  const local = (ts: number) => {
    const d = new Date(ts * 1000);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  };
  const nowTs = Math.floor(Date.now() / 1000);
  let reason = $state('');
  let doHold = $state(true);
  let holdTenants: string[] = $state([]);
  let sources = $state('');
  let from = $state(local(nowTs - 7 * 86400));
  let to = $state(local(nowTs));
  let allGroups = $state(true);
  let chosen: number[] = $state([]);
  let password = $state('');
  let totp = $state('');
  // Phase 29: freezes (configuration, deletions, restores to production)
  let frz = $state({ config: false, deletions: false, restores: false });
  const frozenParts = (f: Incident['freeze']) =>
    f
      ? [
          f.config && t.p29.freeze.names.config,
          f.deletions && t.p29.freeze.names.deletions,
          f.restores && t.p29.freeze.names.restores,
        ].filter((x): x is string => !!x)
      : [];

  async function load() {
    try {
      inc = await get<Incident>('/incident');
      session.incident = inc.active ? { since: inc.since ?? 0, by: inc.by ?? '', reason: inc.reason ?? '' } : null;
      // the freeze banner (GET /auth/me) at once, not at the next refresh
      get<LoginResponse>('/auth/me')
        .then((me) => (session.freeze = me.freeze ?? null))
        .catch(() => {});
      if (officer) [tenants, groups] = await Promise.all([get<Tenant[]>('/tenants'), get<Group[]>('/groups')]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  const ts = (v: string) => Math.floor(new Date(v).getTime() / 1000);
  async function enter(e: SubmitEvent) {
    e.preventDefault();
    if (!(await askConfirm(t.incident.enterConfirm))) return;
    const body = {
      reason,
      hold: doHold
        ? {
            tenants: holdTenants,
            sources: sources
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean),
            from: ts(from),
            to: ts(to),
          }
        : null,
      groups: allGroups ? null : chosen,
      freeze: { ...frz },
      current_password: password,
      current_totp: totp,
    };
    if (await act(post('/incident', body), t.incident.entered)) {
      password = totp = '';
      load();
    }
  }
  async function liftFreeze() {
    if (!(await askConfirm(t.p29.freeze.liftConfirm))) return;
    if (await act(post('/incident/freeze/lift'), t.p29.freeze.liftRequested)) load();
  }
  async function leave() {
    if (!(await askConfirm(t.incident.leaveConfirm))) return;
    if (await act(post('/incident/leave'), t.incident.leaveRequested)) load();
  }
</script>

<ErrorBanner {error} />
{#if !inc}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else if inc.active}
  <section class="card settings-section incident" aria-labelledby="inc-head">
    <div class="card-head">
      <h2 id="inc-head"><IconSiren aria-hidden="true" />{t.incident.activeTitle}</h2>
      <span class="chip bad">{t.incident.open}</span>
    </div>
    <p>{t.incident.since(fmtTime(inc.since ?? 0), inc.by ?? '—')}</p>
    <p><strong>{t.incident.reason}:</strong> {inc.reason}</p>
    <ul>
      <li>{t.incident.held(inc.held?.length ?? 0)}</li>
      <li>{t.incident.paused(inc.paused?.length ?? 0)}</li>
      <li>{t.incident.ended(inc.sessions_ended ?? 0, inc.tokens_revoked ?? 0)}</li>
    </ul>
    {#if frozenParts(inc.freeze).length}
      <div class="banner warn freeze" role="status">
        <span><strong>{t.p29.freeze.active(frozenParts(inc.freeze))}</strong></span>
        {#if inc.freeze_lift_quorum}
          <span>{t.p29.freeze.liftPending(inc.freeze_lift_quorum)} <a href={href('/quorum')}>{t.nav.quorum}</a></span>
        {:else if canLeave}
          <button type="button" class="small" onclick={liftFreeze}>{t.p29.freeze.lift}</button>
        {/if}
      </div>
    {/if}
    {#if inc.leave_quorum}
      <p class="banner pending">
        <span>{t.incident.leavePending(inc.leave_quorum)} <a href={href('/quorum')}>{t.nav.quorum}</a></span>
      </p>
    {:else if canLeave}
      <div class="form-actions"><button type="button" onclick={leave}>{t.incident.leave}</button></div>
    {/if}
  </section>
{:else}
  <section class="card settings-section" aria-labelledby="inc-head">
    <div class="card-head"><h2 id="inc-head">{t.settings.tabs.incident}</h2></div>
    <p>{t.incident.intro}</p>
    {#if inc.ended_at}
      <p class="muted">{t.incident.last(fmtTime(inc.ended_at), inc.ended_by ?? '—', inc.approved_by ?? '—')}</p>
    {/if}
    {#if !officer}
      <p class="hint">{t.incident.officerOnly}</p>
    {:else}
      <form onsubmit={enter}>
        <div class="field">
          <label for="inc-reason">{t.incident.reason}</label>
          <input id="inc-reason" maxlength="500" bind:value={reason} required aria-describedby="inc-reason-hint" />
          <p class="hint" id="inc-reason-hint">{t.incident.reasonHint}</p>
        </div>
        <fieldset>
          <legend>{t.incident.holdTitle}</legend>
          <label class="inline-check"><input type="checkbox" bind:checked={doHold} />{t.incident.hold}</label>
          {#if doHold}
            <div class="form-grid">
              <div class="field">
                <label for="inc-tenants">{t.incident.tenants}</label>
                <select id="inc-tenants" multiple bind:value={holdTenants} aria-describedby="inc-tenants-hint">
                  {#each tenants as x (x.name)}<option value={x.name}>{x.name}</option>{/each}
                </select>
                <p class="hint" id="inc-tenants-hint">{t.incident.tenantsHint}</p>
              </div>
              <div class="field">
                <label for="inc-sources">{t.incident.sources}</label>
                <input id="inc-sources" bind:value={sources} aria-describedby="inc-sources-hint" />
                <p class="hint" id="inc-sources-hint">{t.incident.sourcesHint}</p>
              </div>
              <div class="field">
                <label for="inc-from">{t.incident.from}</label>
                <input id="inc-from" type="datetime-local" bind:value={from} required />
              </div>
              <div class="field">
                <label for="inc-to">{t.incident.to}</label>
                <input id="inc-to" type="datetime-local" bind:value={to} required />
              </div>
            </div>
          {/if}
        </fieldset>
        <fieldset>
          <legend>{t.incident.groupsTitle}</legend>
          <label class="inline-check"
            ><input type="radio" name="inc-groups" value={true} bind:group={allGroups} />{t.incident.allGroups}</label
          >
          <label class="inline-check"
            ><input type="radio" name="inc-groups" value={false} bind:group={allGroups} />{t.incident
              .chosenGroups}</label
          >
          {#if !allGroups}
            <div class="group-list">
              {#each groups as g (g.id)}
                <label class="inline-check"
                  ><input type="checkbox" value={g.id} bind:group={chosen} />{g.tenant} / {g.name}</label
                >
              {/each}
            </div>
          {/if}
        </fieldset>
        <fieldset>
          <legend>{t.p29.freeze.legend}</legend>
          <p class="hint">{t.p29.freeze.intro}</p>
          <div class="field">
            <label class="inline-check"
              ><input type="checkbox" bind:checked={frz.config} aria-describedby="inc-frz-config-hint" />{t.p29.freeze
                .config}</label
            >
            <p class="hint" id="inc-frz-config-hint">{t.p29.freeze.configHint}</p>
          </div>
          <div class="field">
            <label class="inline-check"
              ><input type="checkbox" bind:checked={frz.deletions} aria-describedby="inc-frz-del-hint" />{t.p29.freeze
                .deletions}</label
            >
            <p class="hint" id="inc-frz-del-hint">{t.p29.freeze.deletionsHint}</p>
          </div>
          <div class="field">
            <label class="inline-check"
              ><input type="checkbox" bind:checked={frz.restores} aria-describedby="inc-frz-res-hint" />{t.p29.freeze
                .restores}</label
            >
            <p class="hint" id="inc-frz-res-hint">{t.p29.freeze.restoresHint}</p>
          </div>
        </fieldset>
        <p>{t.incident.reauth}</p>
        <div class="form-grid">
          <div class="field">
            <label for="inc-pw">{t.incident.password}</label>
            <input id="inc-pw" type="password" autocomplete="current-password" bind:value={password} required />
          </div>
          <div class="field">
            <label for="inc-totp">{t.incident.totp}</label>
            <input
              id="inc-totp"
              inputmode="numeric"
              autocomplete="one-time-code"
              pattern="[0-9]{'{'}6{'}'}"
              bind:value={totp}
              required
            />
          </div>
        </div>
        <div class="form-actions">
          <button type="submit" class="danger"><IconSiren aria-hidden="true" />{t.incident.enter}</button>
        </div>
      </form>
    {/if}
  </section>
{/if}

<style>
  .incident {
    border-color: var(--bad, #c62828);
  }
  h2 :global(svg) {
    vertical-align: -0.15em;
    margin-right: 0.35rem;
  }
  fieldset {
    margin: 1rem 0;
  }
  .freeze {
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 1rem;
  }
  .group-list {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
    gap: 0.25rem 1rem;
    margin-top: 0.5rem;
  }
</style>
