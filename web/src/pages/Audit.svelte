<script lang="ts">
  import { onMount } from 'svelte';
  import { get, errText, qs, API } from '../lib/api';
  import { fmtTime, fmtAgo } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { AuditEntry, AuditVerify, ForwardingStatus } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { href } from '../lib/router.svelte';

  // Phase 19b: tenant admins read the entries concerning their own tenant (the server forces the
  // filter); appliance-wide auditors may filter by tenant.
  const scoped = $derived(session.user?.role === 'tenant_admin');

  let entries: AuditEntry[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let more = $state(true);
  let verify: { ok: boolean; text: string } | null = $state(null);
  let verifying = $state(false);
  let fwd: ForwardingStatus | null = $state(null);
  // filter form (applied on submit) and the filters of the list shown
  let form = $state({ actor: '', action: '', target: '', tenant: '', from: '', to: '' });
  let applied = $state({ actor: '', action: '', target: '', tenant: '', from: '', to: '' });

  // dates of the form → unix seconds (local day boundaries)
  const day = (d: string, end: boolean) =>
    d ? Math.floor(new Date(`${d}T${end ? '23:59:59' : '00:00:00'}`).getTime() / 1000) : undefined;
  const filters = $derived({
    actor: applied.actor.trim(),
    action: applied.action.trim(),
    target: applied.target.trim(),
    tenant: applied.tenant.trim(),
    from: day(applied.from, false),
    to: day(applied.to, true),
  });
  const csvHref = $derived(`${API}/audit.csv${qs(filters)}`);

  const PAGE = 100;
  // Newest first; older pages via ?before=<oldest seq shown>.
  async function loadMore() {
    try {
      const q = qs({
        ...filters,
        limit: PAGE,
        ...(entries.length ? { before: entries[entries.length - 1].seq } : { order: 'desc' }),
      });
      const page = await get<AuditEntry[]>(`/audit${q}`);
      entries = [...entries, ...page];
      more = page.length === PAGE;
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  async function loadForwarding() {
    try {
      fwd = await get<ForwardingStatus>('/audit/forwarding');
    } catch {
      fwd = null; // the list is what matters here; the status is a bonus
    }
  }
  onMount(() => {
    loadMore();
    if (can.verifyAudit(session.user)) loadForwarding();
  });

  function apply(e?: SubmitEvent) {
    e?.preventDefault();
    applied = { ...form };
    entries = [];
    loaded = false;
    more = true;
    loadMore();
  }
  function clear() {
    form = { actor: '', action: '', target: '', tenant: '', from: '', to: '' };
    apply();
  }

  async function runVerify() {
    verifying = true;
    verify = null;
    try {
      const r = await get<AuditVerify>('/audit/verify');
      verify = r.ok
        ? { ok: true, text: t.audit.verifiedOk(r.entries) }
        : { ok: false, text: `${t.audit.verifiedBad}: ${r.error ?? ''}` };
    } catch (e) {
      verify = { ok: false, text: `${t.audit.verifiedBad}: ${errText(e)}` };
    } finally {
      verifying = false;
    }
  }

  const short = (h: string) => `${h.slice(0, 10)}…`;
  type Sink = ForwardingStatus['sinks'][number];
  const sinkState = (s: Sink, head: number) =>
    !s.enabled
      ? t.audit.fwd.off
      : s.failing_since
        ? t.audit.fwd.failing(fmtAgo(s.failing_since))
        : s.audit_seq >= head
          ? t.audit.fwd.caughtUp
          : t.audit.fwd.behind(head - s.audit_seq);
  const chip = (s: Sink, head: number) =>
    !s.enabled ? 'plain' : s.failing_since ? 'bad' : s.audit_seq >= head ? 'ok' : 'warn';
</script>

<div class="page-head">
  <h1>{t.audit.title}</h1>
  <div class="tools">
    <a class="button" href={csvHref} download="nexus-audit.csv" title={t.audit.exportHint}>{t.audit.exportCsv}</a>
    {#if can.verifyAudit(session.user)}
      <button type="button" class="primary" onclick={runVerify} disabled={verifying}>
        {verifying ? t.audit.verifying : t.audit.verify}
      </button>
    {/if}
  </div>
  <p class="lede">{t.audit.lede}</p>
</div>
{#if scoped && session.user?.tenant}<p class="muted">{t.audit.tenantScoped(session.user.tenant)}</p>{/if}

{#if verify}
  <div class="banner {verify.ok ? 'ok' : 'error'}" role="status">{verify.text}</div>
{/if}
<ErrorBanner {error} />

{#if fwd}
  <section class="card fwd" aria-labelledby="fwd-h">
    <h2 id="fwd-h">{t.audit.fwd.title}</h2>
    {#if fwd.sinks.length === 0}
      <p class="muted">{t.audit.fwd.none}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.audit.fwd.sink}</th>
              <th scope="col">{t.audit.fwd.dest}</th>
              <th scope="col">{t.state}</th>
              <th scope="col" class="num">{t.audit.fwd.delivered}</th>
              <th scope="col">{t.audit.fwd.lastOk}</th>
              <th scope="col">{t.audit.fwd.lastError}</th>
            </tr>
          </thead>
          <tbody>
            {#each fwd.sinks as s (s.sink)}
              <tr>
                <td>{s.sink === 'syslog' ? t.settings.fw.syslog : t.settings.fw.https}</td>
                <td class="mono">{s.dest}</td>
                <td><span class="chip {chip(s, fwd.head_seq)}">{sinkState(s, fwd.head_seq)}</span></td>
                <td class="num">#{s.audit_seq} / #{fwd.head_seq}</td>
                <td class="nowrap">{s.last_ok ? fmtAgo(s.last_ok) : '—'}</td>
                <td class="details">{s.last_error ?? '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{/if}

<form class="filters" role="search" aria-label={t.audit.filters} onsubmit={apply}>
  <div class="field">
    <label for="a-actor">{t.audit.actor}</label>
    <input id="a-actor" bind:value={form.actor} placeholder={t.audit.actorPh} spellcheck="false" />
  </div>
  <div class="field">
    <label for="a-action">{t.audit.action}</label>
    <input id="a-action" class="mono" bind:value={form.action} placeholder={t.audit.actionPh} spellcheck="false" />
  </div>
  <div class="field">
    <label for="a-target">{t.audit.target}</label>
    <input id="a-target" class="mono" bind:value={form.target} placeholder={t.audit.targetPh} spellcheck="false" />
  </div>
  {#if !scoped}
    <div class="field">
      <label for="a-tenant">{t.audit.tenant}</label>
      <input id="a-tenant" bind:value={form.tenant} placeholder={t.audit.tenantPh} spellcheck="false" />
    </div>
  {/if}
  <div class="field narrow">
    <label for="a-from">{t.audit.from}</label>
    <input id="a-from" type="date" bind:value={form.from} />
  </div>
  <div class="field narrow">
    <label for="a-to">{t.audit.to}</label>
    <input id="a-to" type="date" bind:value={form.to} />
  </div>
  <button type="submit" class="primary">{t.audit.apply}</button>
  <button type="button" onclick={clear}>{t.audit.clear}</button>
</form>

<div class="card">
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if entries.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col" class="num">{t.audit.seq}</th>
            <th scope="col">{t.time}</th>
            <th scope="col">{t.audit.actor}</th>
            <th scope="col">{t.audit.action}</th>
            <th scope="col">{t.audit.target}</th>
            <th scope="col">{t.audit.details}</th>
            <th scope="col">{t.audit.hash}</th>
          </tr>
        </thead>
        <tbody>
          {#each entries as e (e.seq)}
            <tr>
              <td class="num">{e.seq}</td>
              <td class="nowrap">{fmtTime(e.ts)}</td>
              <td>{e.actor}</td>
              <td class="mono">{e.action}</td>
              <td class="mono">
                <!-- jobs and approvals open from their entries -->
                {#if /^job\/\d+$/.test(e.target)}<a href={href(`/${e.target.replace('job/', 'jobs/')}`)}>{e.target}</a>
                {:else if /^quorum\/\d+$/.test(e.target)}<a href={href(`/quorum?id=${e.target.slice(7)}`)}>{e.target}</a
                  >
                {:else}{e.target}{/if}
              </td>
              <td class="mono details">
                {#if JSON.stringify(e.details).length > 120}
                  <details>
                    <summary>{JSON.stringify(e.details).slice(0, 110)}…</summary>
                    <pre class="audit-json">{JSON.stringify(e.details, null, 2)}</pre>
                  </details>
                {:else}{JSON.stringify(e.details)}{/if}
              </td>
              <td class="hash" title={`${e.hash}\nprev ${e.prev_hash}`}>{short(e.hash)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if loaded && more}
    <div class="form-actions"><button type="button" onclick={loadMore}>{t.audit.more}</button></div>
  {/if}
</div>

<style>
  .fwd {
    margin-bottom: 1rem;
  }
  .fwd h2 {
    margin-top: 0;
  }
  .filters .field.narrow {
    min-width: 150px;
  }
</style>
