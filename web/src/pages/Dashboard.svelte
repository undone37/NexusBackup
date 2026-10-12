<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { href } from '../lib/router.svelte';
  import { fmtAgo, fmtBytes, fmtDuration, fmtPct, fmtRatio, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { kindLabel } from '../lib/jobs';
  import { parsePluginSnapshot, pluginKinds, type KindInfo } from '../lib/plugins';
  import type { Agent, Alert, ApprovalsState, Dashboard as DashboardData, Group, Job, Plugin, Policy, Snapshot, Source } from '../lib/types';
  import Check from '../components/Check.svelte';
  import JobState from '../components/JobState.svelte';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import KpiTile from '../components/KpiTile.svelte';
  import StackedBars from '../components/charts/StackedBars.svelte';
  import TrendLine from '../components/charts/TrendLine.svelte';
  import Ring from '../components/charts/Ring.svelte';
  import HBars from '../components/charts/HBars.svelte';
  import IconShield from '@lucide/svelte/icons/shield-check';
  import IconClock from '@lucide/svelte/icons/clock-alert';
  import IconJobs from '@lucide/svelte/icons/list-checks';
  import IconDisk from '@lucide/svelte/icons/hard-drive';
  import IconLayers from '@lucide/svelte/icons/layers';
  import IconTrend from '@lucide/svelte/icons/trending-up';
  import IconCloud from '@lucide/svelte/icons/cloud-upload';
  import IconLock from '@lucide/svelte/icons/lock';
  import IconPlay from '@lucide/svelte/icons/play';

  // ---- key figures (GET /dashboard, docs/phase12-contract.md §1)
  const DAYS = 'nexus.dashDays';
  let days = $state(sessionStorage.getItem(DAYS) === '7' ? 7 : 30);
  let kpi = $state<DashboardData | null>(null);
  let kpiError: string | null = $state(null);
  async function loadKpi() {
    try {
      kpi = await get<DashboardData>(`/dashboard?days=${days}`);
      kpiError = null;
    } catch (e) {
      kpiError = `${t.dash.loadFailed} (${errText(e)})`;
    }
  }
  function setDays(n: number) {
    if (n === days) return;
    days = n;
    sessionStorage.setItem(DAYS, String(n));
    loadKpi();
  }
  const scope = $derived(session.user?.tenant ? t.dash.scopeTenant(session.user.tenant) : t.dash.scopeAll);
  const pr = $derived(kpi?.protection);
  const notInGroup = $derived(pr ? Math.max(0, pr.objects - pr.sla_ok - pr.sla_breach - pr.never) : 0);
  const cap = $derived(kpi?.capacity);
  const os = $derived(kpi?.offsite);
  const jb = $derived(kpi?.jobs);
  const usedShare = $derived(cap && cap.total > 0 ? cap.used / cap.total : null);
  let kinds: Map<string, KindInfo> = $state(new Map());
  // plugin kinds by their plugin name (e.g. "PostgreSQL"), else the generic label
  const kindName = (k: string) => t.dash.kinds[k] ?? kinds.get(k)?.plugin.name ?? (k.startsWith('plugin') ? t.dash.kinds.plugin : k);
  const worstKind = kindName;
  // only what needs action; healthy objects are counted in the protection chart
  const attention = $derived(pr?.worst.filter((w) => w.sla !== 'ok') ?? []);
  const slaCls: Record<string, string> = { ok: 'ok', breach: 'bad', never: 'warn' };
  const toneOf = (bad: boolean, warn: boolean): '' | 'bad' | 'warn' => (bad ? 'bad' : warn ? 'warn' : '');

  let groups: Group[] = $state([]);
  let policies: Policy[] = $state([]);
  let snaps: Snapshot[] = $state([]);
  let failed: Job[] = $state([]);
  let alerts: Alert[] = $state([]);
  let agents: Agent[] = $state([]);
  let sources: Source[] = $state([]);
  let approvals: ApprovalsState | null = $state(null);
  // The "enable approvals" recommendation can be dismissed for this browser session.
  const DISMISS = 'nexus.approvalsBannerDismissed';
  let dismissed = $state(sessionStorage.getItem(DISMISS) === '1');
  function dismiss() {
    sessionStorage.setItem(DISMISS, '1');
    dismissed = true;
  }
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      const [g, p, s, j, a] = await Promise.all([
        get<Group[]>('/groups'),
        get<Policy[]>('/policies'),
        get<Snapshot[]>('/snapshots'),
        get<Job[]>('/jobs?state=failed'),
        get<Alert[]>('/alerts?state=open'),
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
      let plugins: Plugin[];
      [agents, sources, plugins] = await Promise.all([get<Agent[]>('/agents'), get<Source[]>('/sources'), get<Plugin[]>('/plugins')]);
      kinds = pluginKinds(plugins);
    } catch {
      /* agent names / source kinds are cosmetic here */
    }
    if (can.viewQuorum(session.user)) {
      try {
        approvals = await get<ApprovalsState>('/settings/approvals');
      } catch {
        approvals = null;
      }
    }
    loaded = true;
  }

  onMount(() => {
    load();
    loadKpi();
    const iv = setInterval(load, 30000);
    const iv2 = setInterval(loadKpi, 60000);
    return () => {
      clearInterval(iv);
      clearInterval(iv2);
    };
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
  // datasets (truenas: `nas-<source>-<pool.dataset>`), the share itself (nfs/smb:
  // `share-<source>`, the group has no guests: one row for the share) or plugin guests
  // (`plugin-<plugin id>-<source>[-<guest>]`; a group without guests backs up the whole source).
  const kindOf = (g: Group) => sources.find((s) => s.id === g.source_id)?.kind;
  const isNas = (g: Group) => kindOf(g) === 'truenas';
  const isShare = (g: Group) => kindOf(g) === 'nfs' || kindOf(g) === 'smb';
  const isPlugin = (g: Group) => !!kindOf(g)?.startsWith('plugin:');
  const SHARE = '\u0000share';
  const guestsOf = (g: Group): (number | string)[] =>
    isShare(g) || (isPlugin(g) && !g.guests.length) ? [SHARE] : g.guests;
  // plugin snapshot names per source and guest ('' = whole source), from the snapshot list
  const pluginNames = $derived.by(() => {
    const m = new Map<string, Set<string>>();
    for (const s of snaps) {
      const p = parsePluginSnapshot(s.source);
      if (!p) continue;
      const k = `${s.tenant}/${p.sourceId}/${p.guest ?? ''}`;
      if (!m.has(k)) m.set(k, new Set());
      m.get(k)!.add(s.source);
    }
    return m;
  });
  const sourcesOf = (g: Group, guest: number | string): string[] =>
    isPlugin(g)
      ? [...(pluginNames.get(`${g.tenant}/${g.source_id}/${guest === SHARE ? '' : guest}`) ?? [])]
      : guest === SHARE
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
      return isNas(g) || isPlugin(g) ? guest : (agents.find((a) => a.id === guest)?.name ?? `host-${guest}`);
    return lastFor(g, guest)?.source ?? String(guest);
  }
  const showAlerts = $derived(can.viewAlerts(session.user));
  const policyOf = (g: Group) => policies.find((p) => p.id === g.policy_id);

  function status(g: Group, s: Snapshot | undefined): 'ok' | 'stale' | 'missing' {
    if (!s) return 'missing';
    // same rule as the KPIs (docs/phase12-contract.md §1): breach after 1.5 × the policy period (RPO)
    const rpo = policyOf(g)?.schedule.startsWith('hourly') ? 3600 : 86400;
    const maxAge = 1.5 * rpo;
    return Date.now() / 1000 - s.time > maxAge ? 'stale' : 'ok';
  }
  const statusCls = { ok: 'ok', stale: 'warn', missing: 'bad' };


  async function backupNow(g: Group) {
    await act(post('/jobs', { kind: 'backup', tenant: g.tenant, params: { group_id: g.id } }), t.dash.backupQueued);
  }
</script>

<div class="page-head dash-head">
  <h1>{t.dash.title}</h1>
  <div class="tools">
    {#if kpi}<span class="stamp">{t.dash.updated(fmtTime(kpi.generated))}</span>{/if}
    <div class="seg" role="group" aria-label={t.dash.range}>
      {#each [7, 30] as n (n)}
        <button type="button" aria-pressed={days === n} onclick={() => setDays(n)}>{t.dash.days(n)}</button>
      {/each}
    </div>
  </div>
  <p class="lede">{scope} · {t.dash.lastDays(days)}</p>
</div>
<ErrorBanner {error} />
{#if approvals?.recommend && !dismissed && can.configure(session.user)}
  <div class="banner warn approvals-banner" role="status">
    <span>{t.dash.approvalsBanner(approvals.possible_approvers)} <a href={href('/settings?tab=approvals')}>{t.dash.approvalsLink}</a></span>
    <button type="button" class="small" onclick={dismiss}>{t.dash.dismiss}</button>
  </div>
{/if}
{#if kpiError}<p class="banner warn" role="status">{kpiError}</p>{/if}

{#if kpi && pr && jb && cap && os}
  <section class="kpis" aria-label={t.dash.title}>
    <KpiTile
      icon={IconShield}
      label={t.dash.kProtection}
      value={fmtPct(pr.objects ? pr.protected / pr.objects : null)}
      sub={t.dash.kProtectionSub(pr.protected, pr.objects)}
      meter={pr.objects ? pr.protected / pr.objects : null}
      tone={pr.protected < pr.objects ? 'warn' : 'ok'}
    />
    <KpiTile
      icon={IconClock}
      label={t.dash.kSla}
      value={String(pr.sla_breach)}
      sub={t.dash.kSlaSub(pr.sla_ok, pr.never)}
      tone={toneOf(pr.sla_breach > 0, pr.never > 0)}
    />
    <KpiTile
      icon={IconJobs}
      label={t.dash.kJobs}
      value={fmtPct(jb.success_rate)}
      sub={t.dash.kJobsSub(jb.failed, jb.warning, jb.total)}
      tone={toneOf(jb.success_rate !== null && jb.success_rate < 0.95, jb.failed > 0)}
      href={href('/jobs?state=failed')}
    />
    <KpiTile
      icon={IconDisk}
      label={t.dash.kStorage}
      value={fmtPct(usedShare, 0)}
      sub={t.dash.kStorageSub(fmtBytes(cap.free), fmtBytes(cap.total))}
      meter={usedShare}
      tone={toneOf((usedShare ?? 0) > 0.9, (usedShare ?? 0) > 0.75)}
    />
    <KpiTile
      icon={IconLayers}
      label={t.dash.kReduction}
      value={fmtRatio(cap.reduction)}
      sub={t.dash.kReductionSub(fmtRatio(cap.dedup), fmtRatio(cap.compression))}
    />
    <KpiTile
      icon={IconTrend}
      label={t.dash.kForecast}
      value={cap.forecast_full_days === null ? t.dash.kForecastNone : t.dash.kForecastDays(cap.forecast_full_days)}
      sub={t.dash.kForecastSub}
      tone={toneOf(cap.forecast_full_days !== null && cap.forecast_full_days < 30, cap.forecast_full_days !== null && cap.forecast_full_days < 90)}
    />
    <KpiTile
      icon={IconCloud}
      label={t.dash.kOffsite}
      value={os.tenants ? fmtDuration(os.lag_max_s) : t.dash.unknown}
      sub={(os.tenants ? t.dash.kOffsiteSub(os.lagging, os.tenants) : t.dash.kOffsiteNone) +
        (os.replication_lag_max_s !== null ? ` · ${t.dash.kReplSub(fmtDuration(os.replication_lag_max_s))}` : '')}
      tone={toneOf(false, os.lagging > 0)}
      href={can.viewReplication(session.user) ? href('/replication') : ''}
    />
    <KpiTile
      icon={IconLock}
      label={t.dash.kLock}
      value={fmtPct(os.lock_coverage)}
      sub={t.dash.kVerify(fmtAgo(os.last_verify)) + (os.verify_failed ? ` · ${os.verify_failed} ${t.dash.failed_.toLowerCase()}` : '')}
      meter={os.lock_coverage}
      tone={toneOf(os.verify_failed > 0, os.lock_coverage !== null && os.lock_coverage < 1)}
    />
  </section>

  <div class="dash-grid">
    <section class="card span-8" aria-labelledby="c-jobs">
      <div class="card-head">
        <div><h2 id="c-jobs">{t.dash.jobsChart}</h2><div class="sub">{t.dash.jobsChartSub}</div></div>
        <a href={href('/jobs')}>{t.nav.jobs}</a>
      </div>
      <StackedBars data={jb.per_day} title={t.dash.jobsChart} />
    </section>
    <section class="card span-4" aria-labelledby="c-prot">
      <div class="card-head"><div><h2 id="c-prot">{t.dash.protChart}</h2><div class="sub">{t.dash.protChartSub}</div></div></div>
      <Ring
        title={t.dash.protChart}
        big={fmtPct(pr.objects ? pr.sla_ok / pr.objects : null, 0)}
        small={t.dash.slaOk}
        segments={[
          { value: pr.sla_ok, cls: 'ok', label: t.dash.slaOk },
          { value: pr.sla_breach, cls: 'bad', label: t.dash.slaBreach },
          { value: pr.never, cls: 'warn', label: t.dash.never },
          { value: notInGroup, cls: 'neutral', label: t.dash.unprotected },
        ]}
      />
    </section>

    <section class="card span-8" aria-labelledby="c-cap">
      <div class="card-head">
        <div><h2 id="c-cap">{t.dash.capChart}</h2><div class="sub">{t.dash.capChartSub}</div></div>
        {#if cap.forecast_full_days !== null}<span class="chip {cap.forecast_full_days < 90 ? 'warn' : 'plain'}">{t.dash.capFullIn(t.dash.kForecastDays(cap.forecast_full_days))}</span>{/if}
      </div>
      <TrendLine data={cap.per_day} total={cap.total} forecastDays={cap.forecast_full_days} title={t.dash.capChart} />
    </section>
    <section class="card span-4" aria-labelledby="c-red">
      <div class="card-head"><div><h2 id="c-red">{t.dash.redChart}</h2><div class="sub">{t.dash.redChartSub}</div></div></div>
      <Ring
        title={t.dash.redChart}
        big={fmtRatio(cap.reduction)}
        small={t.dash.total}
        fmt={fmtBytes}
        segments={[
          { value: cap.physical, cls: 'c1', label: t.dash.stored },
          { value: Math.max(0, cap.logical - cap.physical), cls: 'c2', label: t.dash.saved },
        ]}
      />
      <dl class="factors">
        <div><dt>{t.dash.logical}</dt><dd>{fmtBytes(cap.logical)}</dd></div>
        <div><dt>{t.dash.dedup}</dt><dd>{fmtRatio(cap.dedup)}</dd></div>
        <div><dt>{t.dash.compression}</dt><dd>{fmtRatio(cap.compression)}</dd></div>
      </dl>
    </section>

    <section class="card span-4" aria-labelledby="c-fail">
      <div class="card-head"><div><h2 id="c-fail">{t.dash.failChart}</h2><div class="sub">{t.dash.failChartSub(days)}</div></div></div>
      {#if jb.failed_by_kind.some((f) => f.failed > 0)}
        <HBars title={t.dash.failChart} items={jb.failed_by_kind.filter((f) => f.failed > 0).map((f) => ({ label: kindName(f.kind), value: f.failed }))} />
      {:else}
        <p class="empty">{t.dash.noFailures}</p>
      {/if}
    </section>
    <section class="card span-8" aria-labelledby="c-worst">
      <div class="card-head"><div><h2 id="c-worst">{t.dash.worst}</h2><div class="sub">{t.dash.worstSub}</div></div></div>
      {#if attention.length === 0}
        <p class="empty">{t.dash.allGood}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.dash.object}</th>
                {#if !session.user?.tenant}<th scope="col">{t.tenant}</th>{/if}
                <th scope="col">{t.dash.sourceKind}</th>
                <th scope="col">{t.dash.lastOk}</th>
                <th scope="col" class="num">{t.dash.rpo}</th>
                <th scope="col">{t.dash.sla}</th>
              </tr>
            </thead>
            <tbody>
              {#each attention as w (`${w.tenant}/${w.source}`)}
                <tr>
                  <td>{w.name}<div class="muted mono">{w.source}</div></td>
                  {#if !session.user?.tenant}<td>{w.tenant}</td>{/if}
                  <td>{worstKind(w.kind)}</td>
                  <td class="nowrap" title={fmtTime(w.last_ok)}>
                    <span class="age" class:bad={w.sla !== 'ok'}>{fmtAgo(w.last_ok)}</span>
                  </td>
                  <td class="num">{fmtDuration(w.rpo_s)}</td>
                  <td><span class="chip {slaCls[w.sla]}">{t.dash.slaChip[w.sla]}</span></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  </div>
{:else if !kpiError}
  <p class="muted" aria-busy="true">{t.loading}</p>
{/if}

{#if loaded}
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
                      <button type="button" class="small" onclick={() => backupNow(g)}><IconPlay aria-hidden="true" />{t.dash.runBackup}</button>
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
      <h2 id="fj">{t.dash.failedJobs} <a href={href('/jobs?state=failed')} class="muted">{t.nav.jobs}</a></h2>
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
      <h2 id="oa">{t.dash.openAlerts} <a href={href('/alerts')} class="muted">{t.nav.alerts}</a></h2>
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
