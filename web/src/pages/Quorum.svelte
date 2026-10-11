<script lang="ts">
  import { askConfirm } from '../lib/confirm.svelte';
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { fmtAgo, fmtTime, fmtValue } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Activation, ApprovalsState, GcPending, QuorumRequest } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import ActivationCode from '../components/ActivationCode.svelte';

  let items: QuorumRequest[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let onlyPending = $state(true);

  let settings: ApprovalsState | null = $state(null);
  let gc: GcPending[] = $state([]);
  const isAdmin = $derived(session.user?.role === 'admin');

  async function load() {
    try {
      [items, settings, gc] = await Promise.all([
        get<QuorumRequest[]>('/quorum'),
        get<ApprovalsState>('/settings/approvals'),
        get<GcPending[]>('/gc/pending'),
      ]);
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(() => {
    load();
    const iv = setInterval(load, 15000);
    return () => clearInterval(iv);
  });

  const shown = $derived(items.filter((q) => !onlyPending || q.state === 'pending'));
  const stateCls: Record<string, string> = { pending: 'warn', approved: 'ok', executed: 'ok', rejected: 'bad', expired: '' };

  /** Flattens nested objects to dotted keys so a policy's gfs.daily etc. diff line by line. */
  function flat(v: unknown, prefix = '', out: Record<string, unknown> = {}): Record<string, unknown> {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      for (const [k, x] of Object.entries(v)) flat(x, prefix ? `${prefix}.${k}` : k, out);
    } else out[prefix] = v;
    return out;
  }
  // Update requests carry the new object with the previous one under `old`
  // (web-api: policy.update, group.update); everything else is shown as key/value.
  function diff(q: QuorumRequest) {
    const { old, ...next } = q.params ?? {};
    if (!old || typeof old !== 'object') return null;
    const a = flat(old);
    const b = flat(next);
    return Object.keys(b).map((k) => ({ k, before: a[k], after: b[k], changed: JSON.stringify(a[k]) !== JSON.stringify(b[k]) }));
  }
  const others = (q: QuorumRequest) => (q.params && 'old' in q.params ? [] : Object.entries(q.params ?? {}));
  const humanize = (a: string) => a.replace(/[_.]/g, ' ');

  async function decide(q: QuorumRequest, verb: 'approve' | 'reject') {
    // approving executes an irreversible or weakening action: never on a single misclick
    if (verb === 'approve' && !(await askConfirm(t.quorum.approveConfirm(q.id, humanize(q.action), q.requested_by)))) return;
    const ok = await act(
      post<{ activation?: Activation }>(`/quorum/${q.id}/${verb}`),
      verb === 'approve' ? t.quorum.approved : t.quorum.rejected,
    );
    // approving a privileged account's activation releases the second half of its code to the approver
    const a = ok && !ok.quorum ? ok.data.activation : undefined;
    if (a) {
      second = { name: a.name ?? String(q.params?.name ?? ''), activation: a };
      secondOpen = true;
    }
    if (ok) load();
  }

  let second = $state<{ name: string; activation: Activation | null }>({ name: '', activation: null });
  let secondOpen = $state(false);

  async function runGc(g: GcPending) {
    if (!(await askConfirm(t.quorum.gcConfirm(g.tenant)))) return;
    const ok = await act(post<{ job_id: number }>('/gc/approve-large', { tenant: g.tenant }), (d) => t.quorum.gcQueued(d.job_id));
    if (ok) load();
  }
</script>

<div class="page-head">
  <h1>{t.quorum.title}</h1>
  <div class="tools">
    {#if settings}
      <span class="chip {settings.enabled ? 'ok' : 'warn'}">{settings.enabled ? t.quorum.on : t.quorum.off}</span>
      <a href={href('/settings?tab=approvals')}>{t.quorum.settingsLink}</a>
    {/if}
    <label class="inline-check"><input type="checkbox" bind:checked={onlyPending} />{t.quorum.onlyPending}</label>
  </div>
  <p class="lede">{t.quorum.intro}</p>
</div>

<ErrorBanner {error} />

{#if gc.length}
  <section class="card" aria-labelledby="q-gc">
    <h2 id="q-gc">{t.quorum.gcTitle}</h2>
    <p class="muted">{t.quorum.gcIntro}</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.quorum.reason}</th>
            <th scope="col">{t.quorum.requested}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each gc as g (g.tenant)}
            <tr>
              <td><strong>{g.tenant}</strong></td>
              <td>{g.reason}</td>
              <td class="nowrap">{fmtTime(g.created)}</td>
              <td class="actions">
                {#if isAdmin}<button type="button" class="small danger" onclick={() => runGc(g)}>{t.quorum.gcRun}</button>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{/if}

{#if !loaded}
  <p class="muted" aria-busy="true">{t.loading}</p>
{:else if shown.length === 0}
  <div class="card"><p class="empty">{t.none}</p></div>
{:else}
  {#each shown as q (q.id)}
    {@const d = diff(q)}
    {@const own = q.requested_by === session.user?.name}
    <article class="card" aria-labelledby="q{q.id}">
      <h2 id="q{q.id}">
        <span>#{q.id} · {humanize(q.action)}</span>
        <span class="chip {stateCls[q.state] ?? ''}">{t.quorum.states[q.state] ?? q.state}</span>
      </h2>
      <dl class="kv">
        <dt>{t.quorum.requester}</dt>
        <dd><strong>{q.requested_by}</strong></dd>
        <dt>{t.quorum.requested}</dt>
        <dd>{fmtTime(q.created)} ({fmtAgo(q.created)})</dd>
        {#if q.state === 'pending' && q.expires}
          <dt>{t.quorum.expires}</dt>
          <dd>{fmtTime(q.expires)}</dd>
        {/if}
        {#if q.decided_by}
          <dt>{t.quorum.decided}</dt>
          <dd>{q.decided_by} · {fmtTime(q.decided_at)}</dd>
        {/if}
        {#each others(q) as [k, v] (k)}
          <dt>{k}</dt>
          <dd class="mono">{fmtValue(v)}</dd>
        {/each}
      </dl>
      {#if d}
        <h3>{t.quorum.change}</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.quorum.field}</th>
                <th scope="col">{t.quorum.before}</th>
                <th scope="col">{t.quorum.after}</th>
              </tr>
            </thead>
            <tbody>
              {#each d as row (row.k)}
                <tr class:changed={row.changed}>
                  <td class="mono">{row.k}{#if row.changed}<span class="visually-hidden"> (changed)</span>{/if}</td>
                  <td class="mono">{fmtValue(row.before)}</td>
                  <td class="mono"><strong>{fmtValue(row.after)}</strong></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      {#if q.state === 'pending' && can.decideQuorum(session.user)}
        {#if own}
          <p class="muted">{t.quorum.ownRequest}</p>
        {:else}
          <div class="form-actions">
            <button type="button" class="danger" onclick={() => decide(q, 'reject')}>{t.quorum.reject}</button>
            <button type="button" class="primary" onclick={() => decide(q, 'approve')}>{t.quorum.approve}</button>
          </div>
        {/if}
      {/if}
    </article>
  {/each}
{/if}

<ActivationCode bind:open={secondOpen} name={second.name} activation={second.activation} />
