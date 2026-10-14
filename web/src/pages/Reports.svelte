<script lang="ts">
  import { rowClick } from '../lib/rowlink';
  import { onMount } from 'svelte';
  import { API, get, put, post, act, errText, qs } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { askConfirm } from '../lib/confirm.svelte';
  import { notify } from '../lib/notify.svelte';
  import { href } from '../lib/router.svelte';
  import { fmtTime } from '../lib/format';
  import { timeZones } from '../lib/schedule';
  import { t } from '../lib/i18n';
  import type { ReportType, ScheduledReport, ScheduledReports, Tenant } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import JobState from '../components/JobState.svelte';
  import Modal from '../components/Modal.svelte';
  import ScheduleInput from '../components/ScheduleInput.svelte';
  import IconDownload from '@lucide/svelte/icons/download';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconSend from '@lucide/svelte/icons/send';

  // GET /reports/{type}.csv (docs/control-plane.md "Reports"); scheduled reports: setting `reports`.
  const TYPES: ReportType[] = ['protection', 'failed', 'sla', 'storage', 'usage'];
  const isoDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);
  let type = $state<ReportType>('protection');
  let from = $state(isoDay(Date.now() - 6 * 86400_000));
  let to = $state(isoDay(Date.now()));
  let tenant = $state('');
  let tenants: Tenant[] = $state([]);
  const scoped = $derived(!!session.user?.tenant);
  const ranged = $derived(type === 'failed' || type === 'sla' || type === 'usage');
  const badRange = $derived(ranged && from > to);
  const csvUrl = $derived(
    `${API}/reports/${type}.csv${qs({ from: ranged ? from : null, to: ranged ? to : null, tenant: scoped ? null : tenant })}`,
  );

  // scheduled reports: administrators change them, security officers read them
  const appliance = $derived(!session.user?.tenant);
  const admin = $derived(appliance && session.user?.role === 'admin');
  const officer = $derived(admin || (appliance && session.user?.role === 'security_officer'));
  let sched: ScheduledReports | null = $state(null);
  let error: string | null = $state(null);

  async function load() {
    try {
      sched = await get<ScheduledReports>('/settings/reports');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(async () => {
    if (!scoped) get<Tenant[]>('/tenants').then((x) => (tenants = x), () => {});
    if (officer) await load();
  });

  const zones = timeZones();
  let open = $state(false);
  let editing: ScheduledReport | null = $state(null);
  const blank = () => ({
    name: '',
    types: ['protection', 'failed'] as ReportType[],
    schedule: 'Mon 07:00',
    timezone: 'UTC',
    recipients: '',
    tenant: '',
  });
  let f = $state(blank());

  function edit(x: ScheduledReport | null) {
    editing = x;
    f = x
      ? { name: x.name, types: [...x.types], schedule: x.schedule, timezone: x.timezone, recipients: x.recipients.join('\n'), tenant: x.tenant ?? '' }
      : blank();
    open = true;
  }

  /** The stored form (without the server's `last`). */
  const plain = (x: ScheduledReport) => ({
    name: x.name,
    types: x.types,
    schedule: x.schedule,
    timezone: x.timezone,
    recipients: x.recipients,
    tenant: x.tenant,
  });

  async function store(list: ReturnType<typeof plain>[], ok: string) {
    const r = await act(put<ScheduledReports>('/settings/reports', { reports: list }), ok);
    if (r && !r.quorum) sched = r.data;
    return !!r;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!f.types.length) {
      notify('error', t.reports.pickOne);
      return;
    }
    const item = {
      name: f.name.trim(),
      types: TYPES.filter((x) => f.types.includes(x)),
      schedule: f.schedule.trim(),
      timezone: f.timezone.trim() || 'UTC',
      recipients: f.recipients.split(/[\s,;]+/).filter(Boolean),
      tenant: f.tenant || null,
    };
    const rest = (sched?.reports ?? []).filter((x) => x !== editing).map(plain);
    const list = editing ? (sched?.reports ?? []).map((x) => (x === editing ? item : plain(x))) : [...rest, item];
    if (await store(list, editing ? t.saved : t.created)) open = false;
  }

  async function remove(x: ScheduledReport) {
    if (!(await askConfirm(t.reports.confirmDelete(x.name)))) return;
    await store((sched?.reports ?? []).filter((y) => y !== x).map(plain), t.deleted);
  }

  async function sendNow(x: ScheduledReport) {
    const r = await act(post<{ job_id: number }>(`/settings/reports/${encodeURIComponent(x.name)}/send`), (d) => t.reports.sendQueued(d.job_id));
    if (r) load();
  }
</script>

<div class="page-head">
  <h1>{t.reports.title}</h1>
  <p class="lede">{t.reports.lede}</p>
</div>

<section class="card" aria-labelledby="r-export">
  <h2 id="r-export">{t.reports.export}</h2>
  <fieldset class="report-types">
    <legend>{t.reports.type}</legend>
    {#each TYPES as k (k)}
      <label class="report-type" class:selected={type === k}>
        <input type="radio" name="report-type" value={k} bind:group={type} />
        <span><strong>{t.reports.types[k]}</strong><span class="note">{t.reports.typeHints[k]}</span></span>
      </label>
    {/each}
  </fieldset>
  <div class="form-grid">
    <div class="field">
      <label for="r-from">{t.reports.from}</label>
      <input id="r-from" type="date" bind:value={from} disabled={!ranged} aria-describedby="r-range-hint" />
    </div>
    <div class="field">
      <label for="r-to">{t.reports.to}</label>
      <input id="r-to" type="date" bind:value={to} disabled={!ranged} aria-describedby="r-range-hint" />
    </div>
    {#if !scoped}
      <div class="field">
        <label for="r-tenant">{t.reports.tenantFilter}</label>
        <select id="r-tenant" bind:value={tenant}>
          <option value="">{t.reports.allTenants}</option>
          {#each tenants as x (x.name)}<option value={x.name}>{x.name}</option>{/each}
        </select>
      </div>
    {/if}
  </div>
  <p class="note" id="r-range-hint">{t.reports.rangeHint}</p>
  {#if badRange}<p class="banner error" role="alert">{t.reports.rangeInvalid}</p>{/if}
  <div class="form-actions start">
    {#if badRange}
      <button type="button" class="primary" disabled><IconDownload aria-hidden="true" />{t.reports.download}</button>
    {:else}
      <a class="button primary" href={csvUrl} download><IconDownload aria-hidden="true" />{t.reports.download}</a>
    {/if}
  </div>
  <p class="note">{t.reports.csvHint}</p>
</section>

{#if officer}
  <section class="card" aria-labelledby="r-sched">
    <div class="card-head">
      <div><h2 id="r-sched">{t.reports.scheduled}</h2><div class="sub">{t.reports.scheduledLede}</div></div>
      {#if admin}
        <button type="button" class="primary" disabled={!sched?.smtp} onclick={() => edit(null)}><IconPlus aria-hidden="true" />{t.reports.add}</button>
      {/if}
    </div>
    <ErrorBanner {error} />
    {#if sched && !sched.smtp}<p class="banner info">{t.reports.noSmtp}</p>{/if}
    {#if !admin}<p class="note">{t.reports.readOnly}</p>{/if}
    {#if sched && sched.reports.length === 0}
      <p class="empty">{t.reports.empty}</p>
    {:else if sched}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.name}</th>
              <th scope="col">{t.reports.reportsField}</th>
              <th scope="col">{t.reports.schedule}</th>
              <th scope="col">{t.reports.recipients}</th>
              <th scope="col">{t.reports.tenant}</th>
              <th scope="col">{t.reports.last}</th>
              {#if admin}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
            </tr>
          </thead>
          <tbody>
            {#each sched.reports as x (x.name)}
              <tr use:rowClick={() => edit(x)}>
                <th scope="row">{x.name}</th>
                <td>{x.types.map((k) => t.reports.types[k]).join(', ')}</td>
                <td class="nowrap"><span class="mono">{x.schedule}</span>{#if x.timezone !== 'UTC'}<div class="muted">{x.timezone}</div>{/if}</td>
                <td>{x.recipients.join(', ')}</td>
                <td>{x.tenant ?? t.reports.allTenants}</td>
                <td class="nowrap">
                  {#if x.last}
                    <a href={href(`/jobs/${x.last.job_id}`)}><JobState state={x.last.state} /></a>
                    <span class="muted">{fmtTime(x.last.finished ?? x.last.created)}</span>
                  {:else}<span class="muted">{t.reports.never}</span>{/if}
                </td>
                {#if admin}
                  <td class="actions">
                    <button type="button" class="small" disabled={!sched.smtp} onclick={() => sendNow(x)}><IconSend aria-hidden="true" />{t.reports.sendNow}</button>
                    <button type="button" class="small" onclick={() => edit(x)}>{t.edit}</button>
                    <button type="button" class="small danger" onclick={() => remove(x)}>{t.delete}</button>
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if !error}
      <p class="muted" aria-busy="true">{t.loading}</p>
    {/if}
  </section>
{/if}

<Modal bind:open wide title={editing ? t.reports.editTitle(editing.name) : t.reports.newTitle}>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="rs-name">{t.name}</label>
        <input id="rs-name" bind:value={f.name} required pattern="[A-Za-z0-9_\-][A-Za-z0-9._\-]{'{0,63}'}" aria-describedby="rs-name-hint" />
        <div class="hint" id="rs-name-hint">{t.reports.nameHint}</div>
      </div>
      <div class="field">
        <label for="rs-tenant">{t.reports.tenant}</label>
        <select id="rs-tenant" bind:value={f.tenant} aria-describedby="rs-tenant-hint">
          <option value="">{t.reports.allTenants}</option>
          {#each tenants as x (x.name)}<option value={x.name}>{x.name}</option>{/each}
        </select>
        <div class="hint" id="rs-tenant-hint">{t.reports.tenantHint}</div>
      </div>
    </div>
    <fieldset>
      <legend>{t.reports.reportsField}</legend>
      {#each TYPES as k (k)}
        <label class="inline-check"><input type="checkbox" value={k} bind:group={f.types} />{t.reports.types[k]}</label>
      {/each}
    </fieldset>
    <fieldset>
      <legend>{t.reports.schedule}</legend>
      <ScheduleInput id="rs-sched" bind:value={f.schedule} kinds={['weekdays', 'daily', 'monthly']} hint={t.reports.scheduleHint} />
      <div class="field">
        <label for="rs-tz">{t.runctl.timezone}</label>
        <input id="rs-tz" list="rs-tz-list" bind:value={f.timezone} required />
        <datalist id="rs-tz-list">{#each zones as z (z)}<option value={z}></option>{/each}</datalist>
      </div>
    </fieldset>
    <div class="field">
      <label for="rs-to">{t.reports.recipients}</label>
      <textarea id="rs-to" bind:value={f.recipients} rows="3" spellcheck="false" required aria-describedby="rs-to-hint"></textarea>
      <div class="hint" id="rs-to-hint">{t.reports.recipientsHint}</div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>

<style>
  .report-types {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
    gap: 0.6rem;
    border: 0;
    padding: 0;
    margin: 0 0 1rem;
  }
  .report-types legend {
    font-weight: 600;
    margin-bottom: 0.4rem;
  }
  .report-type {
    display: flex;
    gap: 0.6rem;
    align-items: flex-start;
    padding: 0.7rem 0.8rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-s);
    cursor: pointer;
  }
  .report-type.selected {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .report-type input {
    margin-top: 0.2rem;
  }
  .report-type > span {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .note {
    font-size: 0.82rem;
    color: var(--muted);
  }
  .form-actions.start {
    justify-content: flex-start;
  }
</style>
