<script lang="ts">
  import { jobLink } from '../lib/jobs';
  import { rowClick, rowLink } from '../lib/rowlink';
  import { onMount } from 'svelte';
  import { get, post, put, del, act, errText } from '../lib/api';
  import { href, route } from '../lib/router.svelte';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { can } from '../lib/roles';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { checkSummary, checksForm, emptyChecks, stateChip, toChecks } from '../lib/rtest';
  import type { Group, RestoreTest, RtSchedule, Snapshot, Source } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import Modal from '../components/Modal.svelte';
  import RtChecksFields from '../components/RtChecksFields.svelte';
  import IconPlay from '@lucide/svelte/icons/play';
  import IconPlus from '@lucide/svelte/icons/plus';

  // Phase 25: results (GET /restore-tests), group schedules, "Test a snapshot" (a restore_test job).
  let tests: RestoreTest[] = $state([]);
  let schedules: RtSchedule[] = $state([]);
  let groups: Group[] = $state([]);
  let sources: Source[] = $state([]);
  let snaps: Snapshot[] = $state([]);
  let loaded = $state(false);
  let error: string | null = $state(null);
  let filter = $state(route.query.get('state') ?? '');
  let tenantF = $state('');

  const runner = $derived(can.backup(session.user));
  const writer = $derived(can.manageTenant(session.user));
  const pveIds = $derived(new Set(sources.filter((s) => s.kind === 'pve').map((s) => s.id)));
  const pveGroups = $derived(groups.filter((g) => pveIds.has(g.source_id)));
  const tenants = $derived([...new Set(tests.map((x) => x.tenant))].sort());
  const shown = $derived(tests.filter((x) => (!filter || x.state === filter) && (!tenantF || x.tenant === tenantF)));
  const nodesOf = (sid: number | undefined) =>
    Object.keys(
      ((sources.find((s) => s.id === sid)?.config as Record<string, unknown> | undefined)?.nodes as object) ?? {},
    );

  async function load() {
    try {
      [tests, schedules] = await Promise.all([
        get<RestoreTest[]>('/restore-tests'),
        get<RtSchedule[]>('/restore-tests/schedules'),
      ]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(() => {
    load();
    Promise.all([get<Group[]>('/groups'), get<Source[]>('/sources'), get<Snapshot[]>('/snapshots')])
      .then(([g, s, sn]) => ((groups = g), (sources = s), (snaps = sn)))
      .catch(() => {});
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  });

  // ---- test a snapshot now
  let testOpen = $state(false);
  let tf = $state({ tenant: '', source: '', time: '', node: '', storage: 'local-lvm', bridge: '' });
  let tc = $state(emptyChecks());
  const guestSnaps = $derived(snaps.filter((s) => s.local && /^(vm|ct)-\d+$/.test(s.source)));
  const guestSources = $derived([...new Set(guestSnaps.map((s) => `${s.tenant}/${s.source}`))].sort());
  const versions = $derived(
    guestSnaps.filter((s) => `${s.tenant}/${s.source}` === `${tf.tenant}/${tf.source}`).sort((a, b) => b.time - a.time),
  );
  const tfSourceId = $derived(
    groups.find(
      (g) => g.tenant === tf.tenant && pveIds.has(g.source_id) && g.guests.includes(Number(tf.source.slice(3))),
    )?.source_id,
  );
  function openTest() {
    tf = { tenant: '', source: '', time: '', node: '', storage: 'local-lvm', bridge: '' };
    tc = emptyChecks();
    testOpen = true;
  }
  function pickGuest(e: Event) {
    const [tenant, source] = (e.currentTarget as HTMLSelectElement).value.split('/');
    tf.tenant = tenant;
    tf.source = source;
    tf.time = versions.length ? String(versions[0].time) : '';
    tf.node = nodesOf(tfSourceId)[0] ?? tf.node;
  }
  async function startTest(e: Event) {
    e.preventDefault();
    const ct = tf.source.startsWith('ct-');
    const params: Record<string, unknown> = {
      source: tf.source,
      time: Number(tf.time),
      node: tf.node,
      storage: tf.storage,
      checks: toChecks(tc, ct),
    };
    if (tf.bridge.trim()) params.bridge = tf.bridge.trim();
    const o = await act(
      post<{ id: number }>('/jobs', { kind: 'restore_test', tenant: tf.tenant, params }),
      (d) => t.rtest.started(d.id),
      jobLink,
    );
    if (o) {
      testOpen = false;
      load();
    }
  }

  // ---- schedules
  let schedOpen = $state(false);
  let sf = $state({ group_id: 0, every_days: 7, node: '', storage: 'local-lvm', bridge: '' });
  let sc = $state(emptyChecks());
  let schedEditing = $state(false);
  function editSchedule(s: RtSchedule | null) {
    schedEditing = !!s;
    sf = s
      ? { group_id: s.group_id, every_days: s.every_days, node: s.node, storage: s.storage, bridge: s.bridge ?? '' }
      : {
          group_id: pveGroups.find((g) => !schedules.some((x) => x.group_id === g.id))?.id ?? 0,
          every_days: 7,
          node: '',
          storage: 'local-lvm',
          bridge: '',
        };
    sc = checksForm(s?.checks);
    schedOpen = true;
  }
  const groupName = (id: number) => groups.find((g) => g.id === id)?.name ?? `#${id}`;
  async function saveSchedule(e: Event) {
    e.preventDefault();
    const body = {
      every_days: Number(sf.every_days),
      node: sf.node,
      storage: sf.storage,
      bridge: sf.bridge.trim() || null,
      checks: toChecks(sc, false),
    };
    if (await act(put(`/restore-tests/schedules/${sf.group_id}`, body), t.rtest.saved)) {
      schedOpen = false;
      load();
    }
  }
  async function removeSchedule(s: RtSchedule) {
    if (!(await askConfirm(t.rtest.deleteSchedule(s.group)))) return;
    if (await act(del(`/restore-tests/schedules/${s.group_id}`), t.rtest.removed)) load();
  }
</script>

<div class="page-head">
  <h1>{t.rtest.title}</h1>
  {#if runner}<button type="button" class="primary" onclick={openTest}
      ><IconPlay aria-hidden="true" />{t.rtest.testNow}</button
    >{/if}
  <p class="lede">{t.rtest.lede}</p>
</div>
<ErrorBanner {error} />

<section class="card" aria-labelledby="rt-sched-h">
  <div class="card-head">
    <div>
      <h2 id="rt-sched-h">{t.rtest.schedules}</h2>
      <div class="sub">{t.rtest.schedulesHint}</div>
    </div>
    {#if writer}<button type="button" onclick={() => editSchedule(null)} disabled={!pveGroups.length}
        ><IconPlus aria-hidden="true" />{t.rtest.addSchedule}</button
      >{/if}
  </div>
  {#if schedules.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.rtest.group}</th>
            {#if !session.user?.tenant}<th scope="col">{t.tenant}</th>{/if}
            <th scope="col">{t.rtest.every}</th>
            <th scope="col">{t.rtest.node} / {t.rtest.storage}</th>
            <th scope="col">{t.rtest.bridge}</th>
            <th scope="col">{t.rtest.checks}</th>
            <th scope="col">{t.rtest.lastRun}</th>
            {#if writer}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each schedules as s (s.group_id)}
            <tr use:rowClick={writer ? () => editSchedule(s) : null}>
              <td><strong>{s.group}</strong></td>
              {#if !session.user?.tenant}<td>{s.tenant}</td>{/if}
              <td class="nowrap">{t.rtest.everyShort(s.every_days)}</td>
              <td class="mono">{s.node} / {s.storage}</td>
              <td class="mono">{s.bridge ?? t.rtest.linksDown}</td>
              <td class="mono small"
                >{[
                  ...(s.checks.ports ?? []).map((p) => `tcp/${p}`),
                  ...(s.checks.command?.length ? ['command'] : []),
                ].join(' ') || 'guest_agent'}</td
              >
              <td class="nowrap">{s.last_run ? fmtAgo(s.last_run) : t.rtest.never}</td>
              {#if writer}
                <td class="actions">
                  <button type="button" class="small" onclick={() => editSchedule(s)}>{t.edit}</button>
                  <button type="button" class="small danger" onclick={() => removeSchedule(s)}>{t.delete}</button>
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<section class="card" aria-labelledby="rt-res-h">
  <div class="card-head">
    <h2 id="rt-res-h">{t.rtest.results}</h2>
    <div class="row">
      {#if tenants.length > 1}
        <label class="visually-hidden" for="rt-tenant">{t.tenant}</label>
        <select id="rt-tenant" bind:value={tenantF}>
          <option value="">{t.allTenants}</option>
          {#each tenants as x (x)}<option value={x}>{x}</option>{/each}
        </select>
      {/if}
      <label class="visually-hidden" for="rt-state">{t.state}</label>
      <select id="rt-state" bind:value={filter}>
        <option value="">{t.all}</option>
        {#each ['passed', 'failed', 'cancelled', 'skipped'] as s (s)}<option value={s}>{t.rtest.states[s]}</option
          >{/each}
      </select>
    </div>
  </div>
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if shown.length === 0}
    <p class="empty">{t.rtest.noTests}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.rtest.guest}</th>
            <th scope="col">{t.rtest.snapshot}</th>
            <th scope="col">{t.rtest.result}</th>
            <th scope="col">{t.rtest.checks}</th>
            <th scope="col" class="num">{t.rtest.boot}</th>
            <th scope="col">{t.rtest.finished}</th>
            <th scope="col">{t.rtest.job}</th>
          </tr>
        </thead>
        <tbody>
          {#each shown as x (x.id)}
            {@const bad = (x.checks ?? []).filter((c) => !c.ok)}
            <tr use:rowLink={`/jobs/${x.job_id}`}>
              <td
                ><strong>{x.source}</strong>{#if !session.user?.tenant}<span class="muted small"
                    >&nbsp;· {x.tenant}</span
                  >{/if}{#if x.name}<div class="muted small mono">{x.target} {x.name}</div>{/if}</td
              >
              <td class="nowrap"
                ><a href={href(`/files?tenant=${x.tenant}&source=${x.source}&time=${x.time}`)}>{fmtTime(x.time)}</a></td
              >
              <td><span class="chip {stateChip(x.state)}">{t.rtest.states[x.state] ?? x.state}</span></td>
              <td>
                <span class="mono small">{checkSummary(x.checks)}</span>
                {#each bad as c (c.name)}<div class="small bad-text">{c.name}: {c.detail}</div>{/each}
                {#if x.error}<div class="small bad-text">{x.error}</div>{/if}
                {#if x.destroyed === false}<div class="small bad-text">
                    <strong>{t.rtest.notDestroyed(x.target)}</strong>
                  </div>{/if}
              </td>
              <td class="num nowrap">{x.boot_secs !== null ? `${x.boot_secs} s` : '—'}</td>
              <td class="nowrap" title={fmtTime(x.finished)}>{fmtAgo(x.finished)}</td>
              <td
                ><a href={href(`/jobs/${x.job_id}`)}>#{x.job_id}</a>{#if x.run_id}<span class="muted small">
                    · {t.rplan.mode.test}</span
                  >{/if}</td
              >
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<Modal bind:open={testOpen} wide title={t.rtest.testNow}>
  <form onsubmit={startTest}>
    <div class="form-grid">
      <div class="field">
        <label for="rt-guest">{t.rtest.guest}</label>
        <select id="rt-guest" required value={tf.source ? `${tf.tenant}/${tf.source}` : ''} onchange={pickGuest}>
          <option value="" disabled>{t.rtest.pick}</option>
          {#each guestSources as g (g)}<option value={g}>{session.user?.tenant ? g.split('/')[1] : g}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="rt-time">{t.rtest.snapshot}</label>
        <select id="rt-time" required bind:value={tf.time}>
          {#each versions as v (v.time)}<option value={String(v.time)}>{fmtTime(v.time)}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="rt-node">{t.rtest.node}</label>
        <input id="rt-node" required bind:value={tf.node} list="rt-nodes" />
        <datalist id="rt-nodes"
          >{#each nodesOf(tfSourceId) as n (n)}<option value={n}></option>{/each}</datalist
        >
      </div>
      <div class="field">
        <label for="rt-storage">{t.rtest.storage}</label>
        <input id="rt-storage" required bind:value={tf.storage} aria-describedby="rt-storage-hint" />
        <div class="hint" id="rt-storage-hint">{t.rtest.storageHint}</div>
      </div>
      <div class="field">
        <label for="rt-bridge">{t.rtest.bridge}</label>
        <input
          id="rt-bridge"
          bind:value={tf.bridge}
          placeholder={t.rtest.linksDown}
          aria-describedby="rt-bridge-hint"
        />
        <div class="hint" id="rt-bridge-hint">{t.rtest.bridgeHint}</div>
      </div>
    </div>
    <fieldset>
      <legend>{t.rtest.checks}</legend>
      <RtChecksFields id="rt-c" bind:value={tc} ct={tf.source.startsWith('ct-')} />
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (testOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={!tf.source || !tf.time}
        ><IconPlay aria-hidden="true" />{t.rtest.testNow}</button
      >
    </div>
  </form>
</Modal>

<Modal
  bind:open={schedOpen}
  wide
  title={schedEditing ? t.rtest.editSchedule(groupName(sf.group_id)) : t.rtest.addSchedule}
>
  <form onsubmit={saveSchedule}>
    <div class="form-grid">
      <div class="field">
        <label for="rs-group">{t.rtest.group}</label>
        <select
          id="rs-group"
          bind:value={sf.group_id}
          disabled={schedEditing}
          required
          aria-describedby="rs-group-hint"
        >
          {#each pveGroups as g (g.id)}<option value={g.id}
              >{session.user?.tenant ? g.name : `${g.tenant} / ${g.name}`}</option
            >{/each}
        </select>
        <div class="hint" id="rs-group-hint">{t.rtest.pveGroupsOnly}</div>
      </div>
      <div class="field">
        <label for="rs-every">{t.rtest.every}</label>
        <input id="rs-every" type="number" min="1" max="365" required bind:value={sf.every_days} />
      </div>
      <div class="field">
        <label for="rs-node">{t.rtest.node}</label>
        <input id="rs-node" required bind:value={sf.node} list="rs-nodes" />
        <datalist id="rs-nodes"
          >{#each nodesOf(groups.find((g) => g.id === sf.group_id)?.source_id) as n (n)}<option value={n}
            ></option>{/each}</datalist
        >
      </div>
      <div class="field">
        <label for="rs-storage">{t.rtest.storage}</label>
        <input id="rs-storage" required bind:value={sf.storage} />
      </div>
      <div class="field">
        <label for="rs-bridge">{t.rtest.bridge}</label>
        <input
          id="rs-bridge"
          bind:value={sf.bridge}
          placeholder={t.rtest.linksDown}
          aria-describedby="rs-bridge-hint"
        />
        <div class="hint" id="rs-bridge-hint">{t.rtest.bridgeHint}</div>
      </div>
    </div>
    <fieldset>
      <legend>{t.rtest.vmOnlyChecks}</legend>
      <RtChecksFields id="rs-c" bind:value={sc} />
      <p class="hint">{t.rtest.ctHint}</p>
    </fieldset>
    <div class="form-actions">
      <button type="button" onclick={() => (schedOpen = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.save}</button>
    </div>
  </form>
</Modal>

<style>
  .bad-text {
    color: var(--bad, #b42318);
  }
</style>
