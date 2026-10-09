<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { href } from '../lib/router.svelte';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { kindLabel } from '../lib/jobs';
  import type { Agent, Alert, Group, Job, Policy, QuorumRequest, Snapshot, Source } from '../lib/types';
  import Check from '../components/Check.svelte';
  import JobState from '../components/JobState.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let groups: Group[] = $state([]);
  let policies: Policy[] = $state([]);
  let snaps: Snapshot[] = $state([]);
  let failed: Job[] = $state([]);
  let alerts: Alert[] = $state([]);
  let agents: Agent[] = $state([]);
  let sources: Source[] = $state([]);
  let pending: number | null = $state(null);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      const [g, p, s, j, a] = await Promise.all([
        get<Group[]>('/groups'),
        get<Policy[]>('/policies'),
        get<Snapshot[]>('/snapshots'),
        get<Job[]>('/jobs?state=failed'),
        get<Alert[]>('/alerts'),
      ]);
      groups = g;
      policies = p;
      snaps = s;
      failed = j.filter((x) => (x.finished ?? x.created) > Date.now() / 1000 - 7 * 86400);
      alerts = a.filter((x) => !x.acked_by);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    try {
      [agents, sources] = await Promise.all([get<Agent[]>('/agents'), get<Source[]>('/sources')]);
    } catch {
      /* agent names / source kinds are cosmetic here */
    }
    if (can.viewQuorum(session.user)) {
      try {
        pending = (await get<QuorumRequest[]>('/quorum')).filter((q) => q.state === 'pending').length;
      } catch {
        pending = null;
      }
    }
    loaded = true;
  }

  onMount(() => {
    load();
    const iv = setInterval(load, 30000);
    return () => clearInterval(iv);
  });

  // Latest snapshot per tenant/guest.
  const latest = $derived.by(() => {
    const m = new Map<string, Snapshot>();
    for (const s of snaps) {
      const k = `${s.tenant}/${s.source}`;
      const cur = m.get(k);
      if (!cur || s.time > cur.time) m.set(k, s);
    }
    return m;
  });

  // Snapshot source names a guest can have: VM/CT IDs (pve), agent ids (linux hosts),
  // datasets (truenas: `nas-<source>-<pool.dataset>`) or the share itself (nfs/smb:
  // `share-<source>`, the group has no guests: one row for the share).
  const kindOf = (g: Group) => sources.find((s) => s.id === g.source_id)?.kind;
  const isNas = (g: Group) => kindOf(g) === 'truenas';
  const isShare = (g: Group) => kindOf(g) === 'nfs' || kindOf(g) === 'smb';
  const SHARE = '\u0000share';
  const guestsOf = (g: Group): (number | string)[] => (isShare(g) ? [SHARE] : g.guests);
  const sourcesOf = (g: Group, guest: number | string) =>
    guest === SHARE
      ? [`share-${g.source_id}`]
      : typeof guest === 'string'
        ? isNas(g)
          ? [`nas-${g.source_id}-${guest.replaceAll('/', '.')}`]
          : [`host-${guest}`]
        : [`vm-${guest}`, `ct-${guest}`];

  function lastFor(g: Group, guest: number | string): Snapshot | undefined {
    for (const s of sourcesOf(g, guest)) {
      const hit = latest.get(`${g.tenant}/${s}`);
      if (hit) return hit;
    }
    return undefined;
  }
  // Newest snapshot of a guest that is offsite / verified (the latest one may still be uploading).
  function newestWhere(g: Group, guest: number | string, pred: (s: Snapshot) => boolean): Snapshot | undefined {
    const names = sourcesOf(g, guest);
    return snaps
      .filter((s) => s.tenant === g.tenant && names.includes(s.source) && pred(s))
      .sort((a, b) => b.time - a.time)[0];
  }
  function guestLabel(g: Group, guest: number | string) {
    if (guest === SHARE) return sources.find((s) => s.id === g.source_id)?.name ?? `share-${g.source_id}`;
    if (typeof guest === 'string')
      return isNas(g) ? guest : (agents.find((a) => a.id === guest)?.name ?? `host-${guest}`);
    return lastFor(g, guest)?.source ?? String(guest);
  }
  const showAlerts = $derived(can.viewAlerts(session.user));
  const policyOf = (g: Group) => policies.find((p) => p.id === g.policy_id);

  function status(g: Group, s: Snapshot | undefined): 'ok' | 'stale' | 'missing' {
    if (!s) return 'missing';
    const hourly = policyOf(g)?.schedule.startsWith('hourly');
    const maxAge = hourly ? 2 * 3600 : 26 * 3600;
    return Date.now() / 1000 - s.time > maxAge ? 'stale' : 'ok';
  }
  const statusCls = { ok: 'ok', stale: 'warn', missing: 'bad' };

  const totals = $derived.by(() => {
    let all = 0;
    let ok = 0;
    for (const g of groups)
      for (const v of guestsOf(g)) {
        all++;
        if (status(g, lastFor(g, v)) === 'ok') ok++;
      }
    return { all, ok };
  });

  async function backupNow(g: Group) {
    await act(post('/jobs', { kind: 'backup', tenant: g.tenant, params: { group_id: g.id } }), t.dash.backupQueued);
  }
</script>

<h1>{t.dash.title}</h1>
<ErrorBanner {error} />

{#if !loaded}
  <p class="muted" aria-busy="true">{t.loading}</p>
{:else}
  <div class="grid-tiles">
    <div class="tile" class:ok={totals.ok === totals.all} class:warn={totals.ok < totals.all}>
      <div class="value">{totals.ok}/{totals.all}</div>
      <div class="label">{t.dash.ok}</div>
    </div>
    <a class="tile" class:bad={failed.length > 0} href={href('/jobs?state=failed')}>
      <div class="value">{failed.length}</div>
      <div class="label">{t.dash.failedRecent}</div>
    </a>
    {#if showAlerts}
      <a class="tile" class:warn={alerts.length > 0} href={href('/alerts')}>
        <div class="value">{alerts.length}</div>
        <div class="label">{t.dash.openAlerts}</div>
      </a>
    {/if}
    {#if pending !== null}
      <a class="tile" class:warn={pending > 0} href={href('/quorum')}>
        <div class="value">{pending}</div>
        <div class="label">{t.dash.pendingQuorum}</div>
      </a>
    {/if}
  </div>

  <section class="card" aria-labelledby="prot">
    <h2 id="prot">{t.dash.protection}</h2>
    {#if groups.length === 0}
      <p class="empty">{t.dash.noGroups}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.dash.group}</th>
              <th scope="col">{t.dash.guest}</th>
              <th scope="col">{t.dash.lastBackup}</th>
              <th scope="col">{t.dash.local}</th>
              <th scope="col">{t.dash.offsite}</th>
              <th scope="col">{t.dash.verified}</th>
              <th scope="col">{t.dash.status}</th>
              {#if can.backup(session.user)}<th scope="col"><span class="visually-hidden">{t.actions}</span></th>{/if}
            </tr>
          </thead>
          <tbody>
            {#each groups as g (g.id)}
              {#each guestsOf(g) as v, i (v)}
                {@const s = lastFor(g, v)}
                {@const st = status(g, s)}
                {@const ver = newestWhere(g, v, (x) => !!x.verified)}
                {@const off = newestWhere(g, v, (x) => x.offsite)}
                <tr>
                  {#if i === 0}
                    <th scope="rowgroup" rowspan={guestsOf(g).length}>
                      {g.name}
                      <div class="muted">{g.tenant} · {policyOf(g)?.name ?? '—'}</div>
                    </th>
                  {/if}
                  <td class="mono">{guestLabel(g, v)}</td>
                  <td class="nowrap" title={fmtTime(s?.time)}>{fmtAgo(s?.time)}</td>
                  <td><Check on={s?.local} /></td>
                  <td>
                    {#if policyOf(g)?.offsite === false}<span class="muted">{t.dash.na}</span>{:else}<Check on={off} />
                      <span class="muted">{off ? fmtAgo(off.time) : ''}</span>{/if}
                  </td>
                  <td class="nowrap">
                    <Check on={ver} title={ver ? `${t.dash.verified}: ${fmtTime(ver.verified)}` : ''} />
                    <span class="muted">{ver ? fmtAgo(ver.time) : ''}</span>
                  </td>
                  <td><span class="chip {statusCls[st]}">{t.dash[st]}</span></td>
                  {#if can.backup(session.user) && i === 0}
                    <td class="actions" rowspan={guestsOf(g).length}>
                      <button type="button" class="small" onclick={() => backupNow(g)}>{t.dash.runBackup}</button>
                    </td>
                  {/if}
                </tr>
              {/each}
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <div class="two-col">
    <section class="card" aria-labelledby="fj">
      <h2 id="fj">{t.dash.failedJobs} <a href={href('/jobs?state=failed')} class="muted">{t.nav.jobs} →</a></h2>
      {#if failed.length === 0}
        <p class="empty">{t.none}</p>
      {:else}
        <table>
          <tbody>
            {#each failed.slice(0, 6) as j (j.id)}
              <tr>
                <td><a href={href(`/jobs/${j.id}`)}>#{j.id}</a></td>
                <td>{kindLabel(j.kind)}</td>
                <td>{j.tenant}</td>
                <td class="nowrap">{fmtAgo(j.finished ?? j.created)}</td>
                <td><JobState state={j.state} /></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
    {#if showAlerts}<section class="card" aria-labelledby="oa">
      <h2 id="oa">{t.dash.openAlerts} <a href={href('/alerts')} class="muted">{t.nav.alerts} →</a></h2>
      {#if alerts.length === 0}
        <p class="empty">{t.none}</p>
      {:else}
        <table>
          <tbody>
            {#each alerts.slice(0, 6) as a (a.id)}
              <tr>
                <td>
                  <span class="chip {a.severity === 'critical' ? 'bad' : a.severity === 'warning' ? 'warn' : 'info'}"
                    >{a.severity}</span
                  >
                </td>
                <td>{a.message}</td>
                <td class="nowrap muted">{fmtAgo(a.ts)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>{/if}
  </div>
{/if}
