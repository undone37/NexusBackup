<script lang="ts">
  import { askConfirm } from '../lib/confirm.svelte';
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { t } from '../lib/i18n';
  import type { Gfs, Policy } from '../lib/types';
  import Check from '../components/Check.svelte';
  import Modal from '../components/Modal.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

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
  let f = $state({ name: '', schedule: 'daily 01:00', gfs: { daily: 14, weekly: 8, monthly: 12, yearly: 0 } as Gfs, offsite: true });

  function edit(x: Policy | null) {
    editing = x;
    f = x
      ? { name: x.name, schedule: x.schedule, gfs: { ...x.gfs }, offsite: x.offsite }
      : { name: '', schedule: 'daily 01:00', gfs: { daily: 14, weekly: 8, monthly: 12, yearly: 0 }, offsite: true };
    open = true;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const body = {
      name: f.name,
      schedule: f.schedule.trim(),
      offsite: f.offsite,
      gfs: Object.fromEntries(GFS.map((k) => [k, Number(f.gfs[k]) || 0])),
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
  <button type="button" class="primary" onclick={() => edit(null)}>{t.policies.new}</button>
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

<Modal bind:open title={editing ? `${t.groups.policy}: ${editing.name}` : t.policies.new}>
  <form onsubmit={save}>
    {#if editing}<p class="banner info">{t.policies.weakenHint}</p>{/if}
    <div class="form-grid">
      <div class="field">
        <label for="p-name">{t.name}</label>
        <input id="p-name" bind:value={f.name} required />
      </div>
      <div class="field">
        <label for="p-sched">{t.policies.schedule}</label>
        <input
          id="p-sched"
          class="mono"
          bind:value={f.schedule}
          required
          pattern={'(daily [0-2][0-9]:[0-5][0-9]|hourly [0-5][0-9])'}
          aria-describedby="p-sched-hint"
        />
        <div class="hint" id="p-sched-hint">{t.policies.scheduleHint}</div>
      </div>
    </div>
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
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{editing ? t.save : t.create}</button>
    </div>
  </form>
</Modal>
