<script lang="ts">
  // Phase 24a: endpoint settings of one agent — the endpoint UI policy (admins), laptop
  // options and the session summaries the endpoint shows (docs/endpoint-ui.md).
  import { get, put, act, errText } from '../lib/api';
  import { fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { session } from '../lib/session.svelte';
  import { href } from '../lib/router.svelte';
  import type { Agent, AgentLaptop, AgentSession, AgentUiPolicy } from '../lib/types';
  import Modal from './Modal.svelte';
  import ErrorBanner from './ErrorBanner.svelte';

  let { open = $bindable(false), agent, onsaved }: { open?: boolean; agent: Agent | null; onsaved: () => void } = $props();

  const isAdmin = $derived(session.user?.role === 'admin');
  let pol: AgentUiPolicy = $state({ accent: '', header: '', hide_backup_now: false, hide_tray: false });
  let lap: AgentLaptop = $state({ min_battery: 0, skip_metered: false, run_missed: false, retry_hours: 0 });
  let sessions: AgentSession[] = $state([]);
  let sessErr: string | null = $state(null);

  $effect(() => {
    if (!open || !agent) return;
    const p = agent.ui_policy as Partial<AgentUiPolicy>;
    pol = { accent: p.accent ?? '', header: p.header ?? '', hide_backup_now: !!p.hide_backup_now, hide_tray: !!p.hide_tray };
    const l = agent.laptop as Partial<AgentLaptop>;
    lap = { min_battery: l.min_battery ?? 0, skip_metered: !!l.skip_metered, run_missed: !!l.run_missed, retry_hours: l.retry_hours ?? 0 };
    sessions = [];
    sessErr = null;
    get<AgentSession[]>(`/agents/${encodeURIComponent(agent.id)}/sessions?limit=10`)
      .then((s) => (sessions = s))
      .catch((e) => (sessErr = errText(e)));
  });

  async function savePolicy(e: SubmitEvent) {
    e.preventDefault();
    if (!agent) return;
    const body = { ...pol, accent: pol.accent.trim(), header: pol.header.trim() };
    if (await act(put(`/agents/${encodeURIComponent(agent.id)}/ui-policy`, body), t.saved)) onsaved();
  }

  async function saveLaptop(e: SubmitEvent) {
    e.preventDefault();
    if (!agent) return;
    const body = {
      min_battery: Number(lap.min_battery) || 0,
      skip_metered: lap.skip_metered,
      run_missed: lap.run_missed,
      retry_hours: Number(lap.retry_hours) || 0,
    };
    if (await act(put(`/agents/${encodeURIComponent(agent.id)}/laptop`, body), t.saved)) onsaved();
  }

  const resultCls: Record<string, string> = { Success: 'ok', Warning: 'warn', Failed: 'bad', Cancelled: 'info' };
</script>

<Modal bind:open title={t.ep.title(agent?.name ?? '')} wide>
  {#if agent}
    <p class="hint">{t.ep.intro}</p>

    <h3>{t.ep.policy}</h3>
    <form onsubmit={savePolicy}>
      <fieldset disabled={!isAdmin}>
        <div class="form-grid">
          <div class="field">
            <label for="ep-accent">{t.ep.accent}</label>
            <input id="ep-accent" class="mono" bind:value={pol.accent} maxlength="7" pattern={'#[0-9a-fA-F]{6}'} placeholder="#0a7f5a" aria-describedby="ep-accent-hint" />
            <div class="hint" id="ep-accent-hint">{t.ep.accentHint}</div>
          </div>
          <div class="field">
            <label for="ep-header">{t.ep.header}</label>
            <input id="ep-header" bind:value={pol.header} maxlength="64" aria-describedby="ep-header-hint" />
            <div class="hint" id="ep-header-hint">{t.ep.headerHint}</div>
          </div>
        </div>
        <label class="inline-check"><input type="checkbox" bind:checked={pol.hide_backup_now} />{t.ep.hideBackupNow}</label>
        <label class="inline-check"><input type="checkbox" bind:checked={pol.hide_tray} />{t.ep.hideTray}</label>
      </fieldset>
      <p class="muted">
        {t.ep.policySeen(agent.ui_policy_version ?? 0, agent.ui_policy_seen ?? null)}
        {#if !isAdmin}— {t.ep.adminOnly}{/if}
      </p>
      {#if isAdmin}
        <div class="form-actions"><button type="submit" class="primary">{t.ep.savePolicy}</button></div>
      {/if}
    </form>

    <h3>{t.ep.laptop}</h3>
    <form onsubmit={saveLaptop}>
      <div class="form-grid">
        <div class="field">
          <label for="ep-bat">{t.ep.minBattery}</label>
          <input id="ep-bat" type="number" min="0" max="100" bind:value={lap.min_battery} aria-describedby="ep-bat-hint" />
          <div class="hint" id="ep-bat-hint">{t.ep.minBatteryHint}</div>
        </div>
        <div class="field">
          <label for="ep-retry">{t.ep.retryHours}</label>
          <input id="ep-retry" type="number" min="0" max="336" bind:value={lap.retry_hours} disabled={!lap.run_missed} />
        </div>
      </div>
      <label class="inline-check"><input type="checkbox" bind:checked={lap.skip_metered} />{t.ep.skipMetered}</label>
      <label class="inline-check"><input type="checkbox" bind:checked={lap.run_missed} />{t.ep.runMissed}</label>
      <div class="form-actions"><button type="submit" class="primary">{t.ep.saveLaptop}</button></div>
    </form>

    <h3>{t.ep.sessions}</h3>
    <ErrorBanner error={sessErr} />
    {#if sessErr}
      <!-- shown by the banner above -->
    {:else if sessions.length === 0}
      <p class="empty">{t.ep.sessionsNone}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.ep.job}</th>
              <th scope="col">{t.ep.result}</th>
              <th scope="col" class="num">{t.ep.transferred}</th>
              <th scope="col"><span class="visually-hidden">{t.ep.delivered}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each sessions as s (s.job)}
              <tr>
                <td class="mono"><a href={href(`/jobs/${s.job}`)}>{s.job}</a> <span class="muted">{s.kind}</span></td>
                <td>
                  <span class="chip {resultCls[s.result] ?? 'info'}">{t.ep.results[s.result] ?? s.result}</span>
                  <span class="muted nowrap">{fmtTime(s.ended)}</span>
                  {#if s.first_error}<div class="muted">{s.first_error}</div>{/if}
                </td>
                <td class="num nowrap">{fmtBytes(s.transferred_bytes)}</td>
                <td class="muted">{s.delivered ? t.ep.delivered : t.ep.pending}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>
