<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { get, put, post, act, errText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { fmtAgo, fmtTime } from '../../lib/format';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { t } from '../../lib/i18n';
  import type { NetConfig, NetIface, NetRole, NetworkState } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import Modal from '../../components/Modal.svelte';

  // Phase 22a (docs/control-plane.md "Network interfaces"): the configuration is edited as a
  // whole draft and requested in one go (approval `network.apply`); nexus-net applies it. A
  // change of the management interface is rolled back unless confirmed within 120 s.
  let cur = $state<NetworkState | null>(null);
  let error = $state<string | null>(null);
  let draft = $state<NetConfig | null>(null);
  let now = $state(Date.now() / 1000);
  const isAdmin = $derived(session.user?.role === 'admin');
  const canCheck = $derived(isAdmin || session.user?.role === 'operator');

  async function load() {
    try {
      cur = await get<NetworkState>('/network');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  let tick: ReturnType<typeof setInterval> | undefined;
  onMount(() => {
    load();
    // the countdown of a pending management change; reload when it ends
    tick = setInterval(() => {
      now = Date.now() / 1000;
      if (cur?.pending && cur.pending.deadline <= now) load();
    }, 1000);
  });
  onDestroy(() => clearInterval(tick));

  const cfg = $derived(draft ?? cur?.config ?? null);
  const dirty = $derived(!!draft && !!cur && JSON.stringify(draft) !== JSON.stringify(cur.config));
  const nics = $derived(cur?.devices.filter((d) => d.kind === 'nic') ?? []);
  const consoleMgmt = $derived(cur?.management?.source === 'console' ? cur.management.ifname : null);
  const remaining = $derived(cur?.pending ? Math.max(0, Math.round(cur.pending.deadline - now)) : 0);
  const roleCls: Record<string, string> = { management: 'accent', data: 'info', replication: 'ok' };
  const resCls: Record<string, string> = { ok: 'ok', mismatch: 'warn', no_reply: 'plain', no_route: 'plain' };
  const opCls: Record<string, string> = {
    done: 'ok',
    queued: 'plain',
    running: 'info',
    confirming: 'warn',
    refused: 'warn',
    error: 'bad',
    rolled_back: 'warn',
  };

  function live(name: string) {
    return cur?.devices.find((d) => d.name === name);
  }
  /** What uses a NIC in the draft (or the console's management interface). */
  function usedBy(nic: string, skip?: NetIface): string | null {
    for (const i of cfg?.interfaces ?? []) {
      if (i === skip) continue;
      if (i.kind === 'ethernet' && i.name === nic) return i.name;
      if (i.kind === 'bond' && i.ports.includes(nic)) return i.name;
    }
    const mgmtHere = cfg?.interfaces.some((i) => i.role === 'management');
    return !mgmtHere && nic === consoleMgmt ? t.net.consoleMgmt : null;
  }
  function describe(i: NetIface): string {
    if (i.kind === 'bond') return t.net.bondOf(i.ports, i.mode ?? '');
    if (i.kind === 'vlan') return t.net.vlanOn(i.vlan_id ?? 0, i.parent ?? '');
    return t.net.kinds.ethernet;
  }

  // ---- editor
  let open = $state(false);
  let idx = $state(-1);
  let ed = $state<NetIface | null>(null);
  let addrText = $state('');
  let dnsText = $state('');
  let routesText = $state('');
  let mtuText = $state('');
  let vlanText = $state('');

  function blank(): NetIface {
    return {
      name: '',
      kind: 'ethernet',
      ports: [],
      mode: 'active-backup',
      parent: null,
      vlan_id: null,
      role: null,
      mtu: null,
      dhcp: false,
      addresses: [],
      gateway: null,
      dns: [],
      routes: [],
    };
  }
  function edit(i: number) {
    idx = i;
    ed = structuredClone($state.snapshot(i < 0 ? blank() : cfg!.interfaces[i])) as NetIface;
    addrText = ed.addresses.join('\n');
    dnsText = ed.dns.join(', ');
    routesText = ed.routes.map((r) => (r.via ? `${r.to} via ${r.via}` : r.to)).join('\n');
    mtuText = ed.mtu ? String(ed.mtu) : '';
    vlanText = ed.vlan_id ? String(ed.vlan_id) : '';
    open = true;
  }
  const words = (s: string) =>
    s
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  const parents = $derived([
    ...nics
      .map((n) => n.name)
      .filter((n) => !(cfg?.interfaces ?? []).some((i) => i.kind === 'bond' && i.ports.includes(n))),
    ...(cfg?.interfaces ?? []).filter((i) => i.kind === 'bond').map((i) => i.name),
  ]);

  function saveIface(e: SubmitEvent) {
    e.preventDefault();
    if (!ed || !cfg) return;
    const i: NetIface = {
      ...ed,
      ports: ed.kind === 'bond' ? ed.ports : [],
      mode: ed.kind === 'bond' ? (ed.mode ?? 'active-backup') : null,
      parent: ed.kind === 'vlan' ? ed.parent : null,
      vlan_id: ed.kind === 'vlan' ? Number(vlanText) || null : null,
      mtu: Number(mtuText) || null,
      addresses: words(addrText),
      dns: words(dnsText),
      gateway: ed.role === 'management' && ed.gateway?.trim() ? ed.gateway.trim() : null,
      routes: routesText
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => {
          const [to, , via] = l.split(/\s+/);
          return { to, via: via ?? null };
        }),
    };
    if (i.kind === 'vlan' && !i.name.trim()) i.name = `${i.parent}.${i.vlan_id}`;
    const next = structuredClone($state.snapshot(cfg)) as NetConfig;
    // one interface per role: taking a role moves it
    if (i.role) for (const x of next.interfaces) if (x.role === i.role) x.role = null;
    if (idx < 0) next.interfaces.push(i);
    else next.interfaces[idx] = i;
    draft = next;
    open = false;
  }
  async function remove(i: number) {
    if (!cfg || !(await askConfirm(t.net.removeConfirm(cfg.interfaces[i].name)))) return;
    const next = structuredClone($state.snapshot(cfg)) as NetConfig;
    next.interfaces.splice(i, 1);
    draft = next;
  }
  function setOffsite(role: NetRole) {
    if (!cfg) return;
    draft = { ...(structuredClone($state.snapshot(cfg)) as NetConfig), offsite_role: role };
  }
  async function request() {
    if (!draft) return;
    if (await act(put('/network', { config: draft }), t.net.requested)) {
      draft = null;
      load();
    }
  }
  async function confirm(keep: boolean) {
    if (!cur?.pending) return;
    if (await act(post('/network/confirm', { id: cur.pending.id, keep }), keep ? t.net.kept : t.net.reverted)) load();
  }
  async function check() {
    if (await act(post('/network/mtu-check'), t.net.checkRequested)) setTimeout(load, 4000);
  }
</script>

<div class="settings-section">
  <p class="intro muted">{t.net.intro}</p>
  <ErrorBanner {error} />

  {#if !cur}
    {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
  {:else}
    {#if !cur.available}
      <p class="banner warn">{t.net.unavailable}</p>
    {:else if cur.stale}
      <p class="banner warn">{t.net.stale(fmtAgo(cur.scanned))}</p>
    {/if}
    {#if cur.pending}
      <div class="banner warn" role="alert">
        <p><strong>{t.net.pendingTitle(remaining)}</strong></p>
        <p>{t.net.pendingText(cur.pending.by, cur.client_ip)}</p>
        {#if isAdmin}
          <div class="form-actions">
            <button type="button" onclick={() => confirm(false)}>{t.net.revert}</button>
            <button type="button" class="primary" onclick={() => confirm(true)}>{t.net.keep}</button>
          </div>
        {/if}
      </div>
    {/if}
    {#if cur.reset}<p class="banner info">{t.net.wasReset(fmtTime(cur.reset))}</p>{/if}
    {#if cur.request_pending}
      <p><a class="chip warn" href={href('/quorum')}>{t.net.requestPending(cur.request_pending)}</a></p>
    {/if}

    <section class="card" aria-labelledby="net-ifs">
      <div class="card-head">
        <h2 id="net-ifs">{t.net.interfaces}</h2>
        {#if isAdmin && cur.available}
          <button type="button" class="small" onclick={() => edit(-1)}>{t.net.add}</button>
        {/if}
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.net.name}</th>
              <th scope="col">{t.net.kind}</th>
              <th scope="col">{t.net.role}</th>
              <th scope="col">{t.net.addresses}</th>
              <th scope="col" class="num">MTU</th>
              <th scope="col">{t.net.state}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#if consoleMgmt && !cfg?.interfaces.some((i) => i.role === 'management')}
              {@const d = live(consoleMgmt)}
              <tr>
                <td><code>{consoleMgmt}</code></td>
                <td>{t.net.kinds.ethernet}</td>
                <td><span class="chip accent">{t.net.roles.management}</span></td>
                <td class="wrap">{d?.addresses.join(', ') || '—'}</td>
                <td class="num">{d?.mtu ?? '—'}</td>
                <td><span class="chip {d?.state === 'up' ? 'ok' : 'plain'}">{d?.state ?? '?'}</span></td>
                <td class="wrap muted">{t.net.consoleHint}</td>
              </tr>
            {/if}
            {#each cfg?.interfaces ?? [] as i, n (i.name + n)}
              {@const d = live(i.name)}
              <tr>
                <td><code>{i.name}</code></td>
                <td class="wrap">{describe(i)}</td>
                <td>
                  {#if i.role}<span class="chip {roleCls[i.role]}">{t.net.roles[i.role]}</span>
                  {:else}<span class="muted">—</span>{/if}
                </td>
                <td class="wrap">
                  {#if i.dhcp}<span class="chip plain">DHCP</span>{/if}
                  {#each i.addresses as a (a)}<code class="chip">{a}</code>{/each}
                  {#if i.gateway}<div class="muted">{t.net.gatewayIs(i.gateway)}</div>{/if}
                  {#each i.routes as r (r.to)}<div class="muted">{t.net.routeIs(r.to, r.via)}</div>{/each}
                  {#if !i.dhcp && !i.addresses.length}<span class="muted">{t.net.noAddress}</span>{/if}
                </td>
                <td class="num">{i.mtu ?? d?.mtu ?? 1500}</td>
                <td>
                  {#if d}<span class="chip {d.state === 'up' ? 'ok' : 'warn'}">{d.state}</span>
                  {:else}<span class="chip plain">{t.net.notActive}</span>{/if}
                </td>
                <td class="actions">
                  {#if isAdmin}
                    <button type="button" class="small" onclick={() => edit(n)}>{t.edit}</button>
                    <button type="button" class="small" onclick={() => remove(n)}>{t.net.remove}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <div class="field offsite">
        <label for="net-offsite">{t.net.offsiteRole}</label>
        <select
          id="net-offsite"
          value={cfg?.offsite_role}
          disabled={!isAdmin}
          onchange={(e) => setOffsite((e.target as HTMLSelectElement).value as NetRole)}
        >
          {#each ['management', 'data', 'replication'] as r (r)}<option value={r}>{t.net.roles[r]}</option>{/each}
        </select>
        <p class="hint">{t.net.egressHint}</p>
      </div>
      {#if dirty}
        <div class="banner info">
          <p>{t.net.unsaved}</p>
          <div class="form-actions">
            <button type="button" onclick={() => (draft = null)}>{t.net.discard}</button>
            <button type="button" class="primary" onclick={request} disabled={!!cur.pending}>{t.net.request}</button>
          </div>
        </div>
      {/if}
      <p class="hint">{t.net.approvalHint}</p>
    </section>

    <section class="card" aria-labelledby="net-nics">
      <div class="card-head"><h2 id="net-nics">{t.net.nics}</h2></div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.net.name}</th>
              <th scope="col">MAC</th>
              <th scope="col">{t.net.link}</th>
              <th scope="col" class="num">MTU</th>
              <th scope="col">{t.net.addresses}</th>
              <th scope="col">{t.net.usedBy}</th>
            </tr>
          </thead>
          <tbody>
            {#each nics as d (d.name)}
              <tr>
                <td><code>{d.name}</code></td>
                <td><code>{d.mac}</code></td>
                <td>
                  <span class="chip {d.state === 'up' ? 'ok' : 'plain'}">{d.state}</span>
                  {#if d.speed}<span class="muted">{t.net.speed(d.speed)}</span>{/if}
                </td>
                <td class="num">{d.mtu}</td>
                <td class="wrap">{d.addresses.join(', ') || '—'}</td>
                <td>{usedBy(d.name) ?? '—'}</td>
              </tr>
            {:else}
              <tr><td colspan="6" class="empty">{t.net.noNics}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <section class="card" aria-labelledby="net-mtu">
      <div class="card-head">
        <h2 id="net-mtu">{t.net.mtuTitle}</h2>
        {#if canCheck && cur.available}<button type="button" class="small" onclick={check}>{t.net.checkNow}</button
          >{/if}
      </div>
      <p class="hint">{t.net.mtuHint}</p>
      {#if !cur.mtu}
        <p class="empty">{t.net.mtuNever}</p>
      {:else if cur.mtu.results.length === 0}
        <p class="empty">{t.net.mtuNone}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.net.destination}</th>
                <th scope="col">{t.net.role}</th>
                <th scope="col">{t.net.via}</th>
                <th scope="col">{t.net.result}</th>
              </tr>
            </thead>
            <tbody>
              {#each cur.mtu.results as r (r.role + r.addr)}
                <tr>
                  <td><code>{r.addr}</code></td>
                  <td>{t.net.roles[r.role] ?? r.role}</td>
                  <td>
                    <code>{r.dev ?? '—'}</code>
                    {#if r.expected_dev && r.dev && r.dev !== r.expected_dev}
                      <span class="chip warn">{t.net.wrongIface(r.expected_dev)}</span>
                    {/if}
                  </td>
                  <td class="wrap"
                    ><span class="chip {resCls[r.result]}">{t.net.results[r.result](r.mtu, r.path_mtu)}</span></td
                  >
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      {#if cur.mtu}<p class="hint">{t.net.mtuAsOf(fmtTime(cur.mtu.ts))}</p>{/if}
    </section>

    {#if cur.ops.length}
      <section class="card" aria-labelledby="net-ops">
        <div class="card-head"><h2 id="net-ops">{t.net.ops}</h2></div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.time}</th>
                <th scope="col">{t.net.op}</th>
                <th scope="col">{t.state}</th>
                <th scope="col">{t.net.by}</th>
                <th scope="col">{t.net.detail}</th>
              </tr>
            </thead>
            <tbody>
              {#each cur.ops.slice(0, 10) as o (o.id)}
                <tr>
                  <td>{fmtTime(o.created)}</td>
                  <td>{t.net.ops_[o.op] ?? o.op}</td>
                  <td><span class="chip {opCls[o.state] ?? 'plain'}">{t.net.opStates[o.state] ?? o.state}</span></td>
                  <td
                    >{o.by}{#if o.quorum_id}<span class="muted"> · #{o.quorum_id}</span>{/if}</td
                  >
                  <td class="wrap">{o.error ?? o.detail ?? ''}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {/if}
  {/if}
</div>

<Modal bind:open title={idx < 0 ? t.net.addTitle : t.net.editTitle(ed?.name ?? '')} wide>
  {#if ed && cur}
    <form onsubmit={saveIface}>
      <div class="grid">
        <div class="field">
          <label for="ni-kind">{t.net.kind}</label>
          <select id="ni-kind" bind:value={ed.kind}>
            {#each ['ethernet', 'bond', 'vlan'] as k (k)}<option value={k}>{t.net.kinds[k]}</option>{/each}
          </select>
        </div>
        {#if ed.kind === 'ethernet'}
          <div class="field">
            <label for="ni-nic">{t.net.nic}</label>
            <select id="ni-nic" bind:value={ed.name} required>
              <option value="" disabled>{t.net.choose}</option>
              {#each nics as d (d.name)}
                <option value={d.name} disabled={!!usedBy(d.name, idx >= 0 ? cfg?.interfaces[idx] : undefined)}
                  >{d.name} {d.state === 'up' ? '' : `(${d.state})`}</option
                >
              {/each}
            </select>
          </div>
        {:else}
          <div class="field">
            <label for="ni-name">{t.net.name}</label>
            <input
              id="ni-name"
              bind:value={ed.name}
              placeholder={ed.kind === 'bond' ? 'bond0' : t.net.vlanNameHint}
              maxlength="15"
              spellcheck="false"
              autocomplete="off"
              required={ed.kind === 'bond'}
            />
          </div>
        {/if}
        <div class="field">
          <label for="ni-role">{t.net.role}</label>
          <select id="ni-role" bind:value={ed.role}>
            <option value={null}>{t.net.noRole}</option>
            {#each ['management', 'data', 'replication'] as r (r)}<option value={r}>{t.net.roles[r]}</option>{/each}
          </select>
        </div>
        <div class="field">
          <label for="ni-mtu">MTU</label>
          <input id="ni-mtu" type="number" min="1280" max="9216" bind:value={mtuText} placeholder="1500" />
        </div>
      </div>
      {#if ed.kind === 'bond'}
        <fieldset>
          <legend>{t.net.ports}</legend>
          {#each nics as d (d.name)}
            {@const other = usedBy(d.name, idx >= 0 ? cfg?.interfaces[idx] : undefined)}
            <label class="inline-check">
              <input
                type="checkbox"
                value={d.name}
                bind:group={ed.ports}
                disabled={!!other && !ed.ports.includes(d.name)}
              />
              <code>{d.name}</code>{#if other}<span class="muted"> ({other})</span>{/if}
            </label>
          {/each}
        </fieldset>
        <div class="field">
          <label for="ni-mode">{t.net.mode}</label>
          <select id="ni-mode" bind:value={ed.mode}>
            <option value="active-backup">{t.net.modes['active-backup']}</option>
            <option value="802.3ad">{t.net.modes['802.3ad']}</option>
          </select>
        </div>
      {:else if ed.kind === 'vlan'}
        <div class="grid">
          <div class="field">
            <label for="ni-parent">{t.net.parent}</label>
            <select id="ni-parent" bind:value={ed.parent} required>
              <option value={null} disabled>{t.net.choose}</option>
              {#each parents as p (p)}<option value={p}>{p}</option>{/each}
            </select>
          </div>
          <div class="field">
            <label for="ni-vlan">{t.net.vlanId}</label>
            <input id="ni-vlan" type="number" min="1" max="4094" bind:value={vlanText} required />
          </div>
        </div>
      {/if}
      <label class="inline-check"><input type="checkbox" bind:checked={ed.dhcp} />{t.net.dhcp}</label>
      <div class="field">
        <label for="ni-addr">{t.net.addressesField}</label>
        <textarea
          id="ni-addr"
          rows="2"
          bind:value={addrText}
          spellcheck="false"
          autocapitalize="none"
          placeholder="10.0.20.5/24"></textarea>
      </div>
      {#if ed.role === 'management'}
        <div class="grid">
          <div class="field">
            <label for="ni-gw">{t.net.gateway}</label>
            <input id="ni-gw" bind:value={ed.gateway} spellcheck="false" autocomplete="off" />
          </div>
          <div class="field">
            <label for="ni-dns">{t.net.dns}</label>
            <input id="ni-dns" bind:value={dnsText} spellcheck="false" autocomplete="off" />
          </div>
        </div>
        <p class="banner warn">{t.net.mgmtWarn(cur.confirm_secs)}</p>
      {/if}
      <div class="field">
        <label for="ni-routes">{t.net.routes}</label>
        <textarea
          id="ni-routes"
          rows="3"
          bind:value={routesText}
          spellcheck="false"
          autocapitalize="none"
          placeholder="10.30.0.0/16 via 10.0.20.1"></textarea>
        <p class="hint">{t.net.routesHint}</p>
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
        <button type="submit" class="primary">{t.net.keepInDraft}</button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  td.wrap {
    max-width: 24rem;
    white-space: normal;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
    gap: 0 1rem;
  }
  .offsite {
    margin-top: 1rem;
    max-width: 28rem;
  }
  fieldset {
    border: 1px solid var(--border, #ccc);
    border-radius: 6px;
    margin: 0 0 1rem;
    padding: 0.5rem 0.75rem;
  }
</style>
