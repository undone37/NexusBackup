<script lang="ts">
  import { askConfirm } from '../lib/confirm.svelte';
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { t } from '../lib/i18n';
  import type { Gfs, Policy } from '../lib/types';
  import Check from '../components/Check.svelte';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import ScheduleInput from '../components/ScheduleInput.svelte';
  import BlackoutEditor from '../components/BlackoutEditor.svelte';
  import { validWindow, type BlackoutWindow } from '../lib/schedule';
  import { notify } from '../lib/notify.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';

  const GFS: (keyof Gfs)[] = ['daily', 'weekly', 'monthly', 'yearly'];

  let items: Policy[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      items = await get<Policy[]>('/policies');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  let open = $state(false);
  let editing: Policy | null = $state(null);
  const blank = () => ({
    name: '',
    schedule: 'daily 01:00',
    gfs: { daily: 14, weekly: 8, monthly: 12, yearly: 0 } as Gfs,
    offsite: true,
    retry: { count: 3, delay_min: 5 },
    blackout: [] as BlackoutWindow[],
    sla: '' as string | number,
    exclude: '',
    exclude_regex: '',
  });
  const lines = (v: string) =>
    v
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
  let f = $state(blank());

  function edit(x: Policy | null) {
    editing = x;
    f = x
      ? {
          name: x.name,
          schedule: x.schedule,
          gfs: { ...x.gfs },
          offsite: x.offsite,
          retry: { ...(x.retry ?? { count: 3, delay_min: 5 }) },
          blackout: (x.blackout ?? []).map((w) => ({ ...w, days: [...w.days] })),
          sla: x.sla_minutes ?? '',
          exclude: (x.file_filters?.exclude ?? []).join('\n'),
          exclude_regex: (x.file_filters?.exclude_regex ?? []).join('\n'),
        }
      : blank();
    open = true;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!f.blackout.every(validWindow)) {
      notify('error', t.runctl.windowInvalid);
      return;
    }
    const body = {
      name: f.name,
      schedule: f.schedule.trim(),
      offsite: f.offsite,
      gfs: Object.fromEntries(GFS.map((k) => [k, Number(f.gfs[k]) || 0])),
      retry: { count: Number(f.retry.count) || 0, delay_min: Number(f.retry.delay_min) || 1 },
      blackout: f.blackout,
      sla_minutes: f.sla === '' || f.sla === null ? null : Number(f.sla),
      file_filters: { exclude: lines(f.exclude), exclude_regex: lines(f.exclude_regex) },
    };
    // A weakening change comes back as 202 {quorum_id}; act() reports it as pending.
    const r = editing ? await act(put(`/policies/${editing.id}`, body), t.saved) : await act(post('/policies', body), t.created);
    if (r) {
      open = false;
      load();
    }
  }

  async function remove(x: Policy) {
    if (!(await askConfirm(t.confirmDelete(`${t.groups.policy} "${x.name}"`)))) return;
    if (await act(del(`/policies/${x.id}`), t.deleted)) load();
  }
</script>

<div class="page-head">
  <h1>{t.policies.title}</h1>
  <button type="button" class="primary" onclick={() => edit(null)}><IconPlus aria-hidden="true" />{t.policies.new}</button>
  <p class="lede">{t.policies.lede}</p>
</div>
<ErrorBanner {error} />

<div class="card">
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if items.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.name}</th>
            <th scope="col">{t.policies.schedule}</th>
            {#each GFS as k (k)}<th scope="col" class="num">{t.policies[k]}</th>{/each}
            <th scope="col">{t.policies.offsite}</th>
            <th scope="col">{t.runctl.retry}</th>
            <th scope="col">{t.runctl.blackout}</th>
            <th scope="col">SLA</th>
            <th scope="col">{t.policies.fileFilters}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as x (x.id)}
            <tr>
              <td><strong>{x.name}</strong></td>
              <td class="mono">{x.schedule}</td>
              {#each GFS as k (k)}<td class="num">{x.gfs?.[k] ?? 0}</td>{/each}
              <td><Check on={x.offsite} /></td>
              <td class="nowrap">{t.runctl.retryShort(x.retry?.count ?? 0, x.retry?.delay_min ?? 0)}</td>
              <td
                class="nowrap"
                title={(x.blackout ?? []).map((w) => `${w.days.join(',') || '*'} ${w.from}–${w.to}${w.abort ? ' (abort)' : ''}`).join('; ')}
                >{t.runctl.blackoutShort(x.blackout?.length ?? 0)}</td
              >
              <td class="nowrap">{t.runctl.slaShort(x.sla_minutes)}</td>
              <td class="mono" title={[...(x.file_filters?.exclude ?? []), ...(x.file_filters?.exclude_regex ?? [])].join('  ')}
                >{(x.file_filters?.exclude?.length ?? 0) + (x.file_filters?.exclude_regex?.length ?? 0) || '—'}</td
              >
              <td class="actions">
                <button type="button" class="small" onclick={() => edit(x)}>{t.edit}</button>
                <button type="button" class="small danger" onclick={() => remove(x)}>{t.delete}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal bind:open wide title={editing ? `${t.groups.policy}: ${editing.name}` : t.policies.new}>
  <form onsubmit={save}>
    {#if editing}<p class="banner info">{t.policies.weakenHint}</p>{/if}
    <div class="form-grid">
      <div class="field">
        <label for="p-name">{t.name}</label>
        <input id="p-name" bind:value={f.name} required />
      </div>
    </div>
    <fieldset>
      <legend>{t.policies.schedule}</legend>
      <ScheduleInput id="p-sched" bind:value={f.schedule} />
    </fieldset>
    <fieldset>
      <legend>{t.policies.gfs}</legend>
      <div class="form-grid">
        {#each GFS as k (k)}
          <div class="field">
            <label for="p-{k}">{t.policies[k]}</label>
            <input id="p-{k}" type="number" min="0" max="10000" bind:value={f.gfs[k]} required />
          </div>
        {/each}
      </div>
    </fieldset>
    <div class="field">
      <label class="inline-check"><input type="checkbox" bind:checked={f.offsite} />{t.policies.offsite}</label>
    </div>
    <fieldset class="field">
      <legend>{t.runctl.retry}</legend>
      <div class="form-grid">
        <div class="field">
          <label for="p-rcount">{t.runctl.retryCount}</label>
          <input id="p-rcount" type="number" min="0" max="10" bind:value={f.retry.count} required />
        </div>
        <div class="field">
          <label for="p-rdelay">{t.runctl.retryDelay}</label>
          <input id="p-rdelay" type="number" min="1" max="1440" bind:value={f.retry.delay_min} required />
        </div>
        <div class="field">
          <label for="p-sla">{t.runctl.sla}</label>
          <input id="p-sla" type="number" min="1" max="10080" bind:value={f.sla} aria-describedby="p-sla-hint" />
          <div class="hint" id="p-sla-hint">{t.runctl.slaHint}</div>
        </div>
      </div>
      <p class="hint">{t.runctl.retryHint}</p>
    </fieldset>
    <BlackoutEditor bind:windows={f.blackout} />
    <fieldset class="field">
      <legend>{t.policies.fileFilters}</legend>
      <p class="hint">{t.policies.fileFiltersHint}</p>
      <div class="form-grid">
        <div class="field">
          <label for="p-fx">{t.policies.globalExclude}</label>
          <textarea id="p-fx" bind:value={f.exclude} spellcheck="false" placeholder={'*.tmp\n/var/cache/**'}></textarea>
        </div>
        <div class="field">
          <label for="p-frx">{t.policies.globalRegex}</label>
          <textarea id="p-frx" bind:value={f.exclude_regex} spellcheck="false" placeholder={'~$'}></textarea>
        </div>
      </div>
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>
