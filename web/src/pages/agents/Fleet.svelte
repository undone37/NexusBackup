<script lang="ts">
  // Phase 24d: fleet secrets (admins), agents found by fleet scans (accept / reject), CSV bulk enrollment.
  import { onMount } from 'svelte';
  import { get, post, del, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { session } from '../../lib/session.svelte';
  import { can } from '../../lib/roles';
  import { copyText } from '../../lib/clipboard';
  import { notify } from '../../lib/notify.svelte';
  import { navigate } from '../../lib/router.svelte';
  import { fmtAgo, fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { Agent, Fleet, FleetCandidate, FleetCreated, Group, Source, Tenant } from '../../lib/types';
  import Modal from '../../components/Modal.svelte';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';

  let { tenants }: { tenants: Tenant[] } = $props();

  const admin = $derived(session.user?.role === 'admin');
  const writer = $derived(can.manageTenant(session.user));
  let fleets: Fleet[] = $state([]);
  let cands: FleetCandidate[] = $state([]);
  let groups: Group[] = $state([]);
  let sources: Source[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let now = $state(Date.now() / 1000);

  async function load() {
    try {
      [cands, groups, sources] = await Promise.all([
        get<FleetCandidate[]>('/fleet/candidates'),
        get<Group[]>('/groups'),
        get<Source[]>('/sources'),
      ]);
      if (admin) fleets = await get<Fleet[]>('/fleets');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    now = Date.now() / 1000;
    loaded = true;
  }
  onMount(load);

  /** template groups: protection groups of agent (linux) sources in the tenant */
  const linuxGroups = (tenant: string) =>
    groups.filter((g) => g.tenant === tenant && sources.find((s) => s.id === g.source_id)?.kind === 'linux');

  const fleetState = (f: Fleet) =>
    f.revoked ? 'revoked' : f.expires <= now ? 'expired' : f.max_uses !== null && f.uses >= f.max_uses ? 'used' : 'active';
  const stateCls: Record<string, string> = { active: 'ok', revoked: 'muted', expired: 'warn', used: 'warn' };
  const candCls: Record<string, string> = { awaiting: 'info', accepted: 'ok', rejected: 'muted' };

  // Create
  let open = $state(false);
  let f = $state({ name: '', tenant: '', days: 14, maxUses: '' as string | number, port: 7444, ranges: '', auto: false, group: '', rules: '' });
  function create() {
    f = { name: '', tenant: tenants[0]?.name ?? '', days: 14, maxUses: '', port: 7444, ranges: '', auto: false, group: '', rules: '' };
    open = true;
  }
  async function save(e: SubmitEvent) {
    e.preventDefault();
    const rules: { pattern: string; group: string }[] = [];
    for (const l of f.rules.split('\n').map((x) => x.trim()).filter(Boolean)) {
      const [pattern, group] = l.split('=').map((x) => x?.trim());
      if (!pattern || !group || l.split('=').length !== 2) {
        notify('error', t.fleet.rulesInvalid(l));
        return;
      }
      rules.push({ pattern, group });
    }
    const body = {
      name: f.name.trim(),
      tenant: f.tenant,
      expires_days: Number(f.days),
      max_uses: f.maxUses === '' || f.maxUses === null ? null : Number(f.maxUses),
      auto_accept: f.auto,
      port: Number(f.port),
      ranges: f.ranges.split('\n').map((x) => x.trim()).filter(Boolean),
      group: f.group || null,
      group_rules: rules,
    };
    const r = await act(post<FleetCreated>('/fleets', body), t.created);
    if (!r) return;
    open = false;
    if (!r.quorum && r.data.secret) {
      created = r.data;
      secOpen = true;
    }
    load();
  }

  // One-time secret: kept only while the dialog is open.
  let created: FleetCreated | null = $state(null);
  let secOpen = $state(false);
  $effect(() => {
    if (!secOpen) created = null;
  });

  async function revoke(x: Fleet) {
    if (!(await askConfirm(t.fleet.revokeConfirm(x.name)))) return;
    if (await act(del(`/fleets/${encodeURIComponent(x.id)}`), t.saved)) load();
  }
  async function scan(x: Fleet) {
    const r = await act(post<{ id: number }>(`/fleets/${encodeURIComponent(x.id)}/scan`), (d) => t.snap.jobStarted(d.id));
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }
  async function accept(c: FleetCandidate) {
    if (!(await askConfirm(t.fleet.acceptConfirm(c.hostname, c.host, c.tenant)))) return;
    if (await act(post<{ agent_id: string; job: number }>(`/fleet/candidates/${c.id}/accept`), (d) => t.fleet.accepted(d.agent_id))) load();
  }
  async function reject(c: FleetCandidate) {
    if (!(await askConfirm(t.fleet.rejectConfirm(c.hostname)))) return;
    if (await act(post(`/fleet/candidates/${c.id}/reject`), t.saved)) load();
  }

  // CSV bulk enrollment: the result (with tokens) lives only in this component until the page is left.
  let csv = $state('host,tenant,name,group\n');
  let bulk: { created: number; agents: Agent[]; csv: string } | null = $state(null);
  async function loadFile(e: Event) {
    const file = (e.currentTarget as HTMLInputElement).files?.[0];
    if (file) csv = await file.text();
  }
  async function submitBulk(e: SubmitEvent) {
    e.preventDefault();
    const r = await act(post<{ created: number; agents: Agent[]; csv: string }>('/agents/bulk', { csv }), (d) => t.fleet.bulkResult(d.created));
    if (r && !r.quorum) bulk = r.data;
  }
  function download() {
    if (!bulk) return;
    const url = URL.createObjectURL(new Blob([bulk.csv], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nexus-agent-tokens.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
</script>

<ErrorBanner {error} />

{#if admin}
  <section class="card">
    <div class="page-head">
      <h2>{t.fleet.secrets}</h2>
      <button type="button" class="primary" onclick={create}><IconPlus aria-hidden="true" />{t.fleet.new}</button>
    </div>
    {#if !loaded}
      <p class="muted" aria-busy="true">{t.loading}</p>
    {:else if fleets.length === 0}
      <p class="empty">{t.none}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.name}</th>
              <th scope="col">{t.tenant}</th>
              <th scope="col">{t.fleet.state}</th>
              <th scope="col">{t.fleet.expires}</th>
              <th scope="col">{t.fleet.uses}</th>
              <th scope="col">{t.fleet.ranges}</th>
              <th scope="col">{t.fleet.group}</th>
              <th scope="col">{t.fleet.lastScan}</th>
              <th scope="col">{t.fleet.awaiting}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each fleets as x (x.id)}
              {@const st = fleetState(x)}
              <tr>
                <td><strong>{x.name}</strong> <div class="muted mono">{x.id}</div></td>
                <td>{x.tenant}</td>
                <td>
                  <span class="chip {stateCls[st]}">{t.fleet.states[st]}</span>
                  {#if x.auto_accept}<div class="muted">{t.fleet.autoAccept}</div>{/if}
                </td>
                <td class="nowrap">{fmtTime(x.expires)}</td>
                <td>{t.fleet.usesOf(x.uses, x.max_uses)}</td>
                <td class="mono">{#each x.ranges as r (r)}<div>{r}</div>{:else}—{/each}<div class="muted">:{x.port}</div></td>
                <td>
                  {x.group ?? '—'}
                  {#each x.group_rules as r (r.pattern)}<div class="muted mono">{r.pattern} = {r.group}</div>{/each}
                </td>
                <td class="nowrap" title={fmtTime(x.last_scan)}>{fmtAgo(x.last_scan, now)}</td>
                <td>{x.awaiting}</td>
                <td class="actions">
                  {#if st === 'active'}
                    <button type="button" class="small" disabled={x.ranges.length === 0} onclick={() => scan(x)}>{t.fleet.scan}</button>
                  {/if}
                  {#if !x.revoked}
                    <button type="button" class="small danger" onclick={() => revoke(x)}>{t.fleet.revoke}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{:else}
  <p class="muted">{t.fleet.readOnly}</p>
{/if}

<section class="card">
  <h2>{t.fleet.candidates}</h2>
  <p class="muted">{t.fleet.candidatesIntro}</p>
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if cands.length === 0}
    <p class="empty">{t.none}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.fleet.hostname}</th>
            <th scope="col">{t.fleet.address}</th>
            <th scope="col">{t.agents.os} / {t.agents.version}</th>
            <th scope="col">{t.fleet.fleetCol}</th>
            <th scope="col">{t.tenant}</th>
            <th scope="col">{t.fleet.seen}</th>
            <th scope="col">{t.fleet.state}</th>
            <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each cands as c (c.id)}
            <tr>
              <td><strong>{c.hostname}</strong></td>
              <td class="mono">{c.host}:{c.port}</td>
              <td>{c.os} <div class="muted mono">{c.version}</div></td>
              <td>{c.fleet}</td>
              <td>{c.tenant}</td>
              <td class="nowrap" title={fmtTime(c.first_seen)}>{fmtAgo(c.last_seen, now)}</td>
              <td>
                <span class="chip {candCls[c.state]}">{t.fleet.candStates[c.state]}</span>
                {#if c.agent_id}<div class="muted mono">{c.agent_id}</div>{/if}
              </td>
              <td class="actions">
                {#if c.state === 'awaiting' && writer}
                  <button type="button" class="small primary" onclick={() => accept(c)}>{t.fleet.accept}</button>
                  <button type="button" class="small" onclick={() => reject(c)}>{t.fleet.reject}</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

{#if writer}
  <section class="card">
    <h2>{t.fleet.bulk}</h2>
    <p class="muted">{t.fleet.bulkIntro}</p>
    <form onsubmit={submitBulk}>
      <div class="field">
        <label for="fl-csv">{t.fleet.bulkCsv}</label>
        <textarea id="fl-csv" class="mono" bind:value={csv} rows="6" spellcheck="false" required></textarea>
      </div>
      <div class="field">
        <label for="fl-file">{t.fleet.bulkFile}</label>
        <input id="fl-file" type="file" accept=".csv,text/csv" onchange={loadFile} />
      </div>
      <div class="form-actions">
        <button type="submit" class="primary">{t.fleet.bulkSubmit}</button>
      </div>
    </form>
    {#if bulk}
      <p class="banner warn" role="alert">{t.fleet.bulkOnce}</p>
      <div class="form-actions">
        <button type="button" class="primary" onclick={download}>{t.fleet.bulkDownload}</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.name}</th>
              <th scope="col">{t.tenant}</th>
              <th scope="col">{t.agents.hostShort}</th>
              <th scope="col">ID</th>
            </tr>
          </thead>
          <tbody>
            {#each bulk.agents as a (a.id)}
              <tr>
                <td>{a.name}</td>
                <td>{a.tenant}</td>
                <td class="mono">{a.host}:{a.port}</td>
                <td class="mono">{a.id}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{/if}

<Modal bind:open title={t.fleet.newTitle} wide>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="f-name">{t.name}</label>
        <input id="f-name" bind:value={f.name} required maxlength="64" autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label for="f-tenant">{t.tenant}</label>
        <select id="f-tenant" bind:value={f.tenant} required onchange={() => (f.group = '')}>
          {#each tenants as tn (tn.name)}<option value={tn.name}>{tn.name}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="f-days">{t.fleet.expiresDays}</label>
        <input id="f-days" type="number" min="1" max="30" bind:value={f.days} required />
      </div>
      <div class="field">
        <label for="f-max">{t.fleet.maxUses}</label>
        <input id="f-max" type="number" min="1" bind:value={f.maxUses} />
      </div>
      <div class="field">
        <label for="f-port">{t.fleet.port}</label>
        <input id="f-port" type="number" min="1" max="65535" bind:value={f.port} required />
      </div>
      <div class="field">
        <label for="f-group">{t.fleet.group}</label>
        <select id="f-group" bind:value={f.group} aria-describedby="f-group-hint">
          <option value="">{t.fleet.groupNone}</option>
          {#each linuxGroups(f.tenant) as g (g.id)}<option value={g.name}>{g.name}</option>{/each}
        </select>
        <div class="hint" id="f-group-hint">{t.fleet.groupHint}</div>
      </div>
    </div>
    <div class="field">
      <label for="f-ranges">{t.fleet.ranges}</label>
      <textarea id="f-ranges" class="mono" bind:value={f.ranges} rows="3" spellcheck="false" aria-describedby="f-ranges-hint"></textarea>
      <div class="hint" id="f-ranges-hint">{t.fleet.rangesHint}</div>
    </div>
    <div class="field">
      <label for="f-rules">{t.fleet.rules}</label>
      <textarea id="f-rules" class="mono" bind:value={f.rules} rows="3" spellcheck="false" aria-describedby="f-rules-hint"></textarea>
      <div class="hint" id="f-rules-hint">{t.fleet.rulesHint}</div>
    </div>
    <div class="field">
      <label><input type="checkbox" bind:checked={f.auto} aria-describedby="f-auto-hint" /> {t.fleet.autoAccept}</label>
      <div class="hint" id="f-auto-hint">{t.fleet.autoAcceptHint}</div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={secOpen} title={t.fleet.secretTitle(created?.name ?? '')} wide>
  {#if created}
    {@const win = created.install.windows.replace('<secret>', created.secret)}
    <p class="banner warn" role="alert">{t.fleet.secretOnce}</p>
    <div class="field">
      <span class="muted">{t.fleet.secret}</span>
      <code class="secret">{created.secret}</code>
      <button type="button" class="small" onclick={() => copyText(created!.secret)}>{t.users.copy}</button>
    </div>
    <div class="field">
      <span class="muted">{t.fleet.installLinux}</span>
      <code class="secret">{created.install.linux}</code>
    </div>
    <div class="field">
      <span class="muted">{t.fleet.installFile}</span>
      <code class="secret">{created.install.linux_file}</code>
    </div>
    <div class="field">
      <span class="muted">{t.fleet.installWindows}</span>
      <code class="secret">{win}</code>
      <button type="button" class="small" onclick={() => copyText(win)}>{t.users.copy}</button>
    </div>
    <p class="muted">{t.fleet.expires}: {fmtTime(created.expires)}</p>
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (secOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>
