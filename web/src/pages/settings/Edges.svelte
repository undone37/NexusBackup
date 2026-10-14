<script lang="ts">
  import { jobLink } from '../../lib/jobs';
  // Phase 26: edge proxies for roaming agents (admins; docs/edge.md). Add an edge → one-time
  // token for its console, Connect (enrollment job), health / log from the control link.
  import { onMount } from 'svelte';
  import { get, post, del, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { copyText } from '../../lib/clipboard';
  import { navigate } from '../../lib/router.svelte';
  import { fmtAgo, fmtDuration, fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { Edge, EdgeToken } from '../../lib/types';
  import Modal from '../../components/Modal.svelte';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconPlus from '@lucide/svelte/icons/plus';

  let edges: Edge[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let now = $state(Date.now() / 1000);

  async function load() {
    try {
      edges = await get<Edge[]>('/edges');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    now = Date.now() / 1000;
    loaded = true;
  }
  onMount(load);

  const edgeState = (e: Edge) =>
    e.enrolled_at ? (e.online ? 'online' : 'offline') : e.token_expires && e.token_expires > now ? 'pending' : 'expired';
  const stateCls: Record<string, string> = { online: 'ok', offline: 'bad', pending: 'info', expired: 'warn' };

  // Add
  let open = $state(false);
  let f = $state({ name: '', host: '', port: 7445, publicHost: '', publicPort: 443 });
  function add() {
    f = { name: '', host: '', port: 7445, publicHost: '', publicPort: 443 };
    open = true;
  }
  async function save(e: SubmitEvent) {
    e.preventDefault();
    const body = { name: f.name.trim(), host: f.host.trim(), port: Number(f.port), public_host: f.publicHost.trim(), public_port: Number(f.publicPort) };
    const r = await act(post<Edge & EdgeToken>('/edges', body), t.created);
    if (!r) return;
    open = false;
    if (!r.quorum) showToken(r.data, r.data.name);
    load();
  }

  // One-time token: kept only while the dialog is open.
  let token: (EdgeToken & { edgeName: string }) | null = $state(null);
  let tokOpen = $state(false);
  $effect(() => {
    if (!tokOpen) token = null;
  });
  function showToken(x: EdgeToken, name: string) {
    token = { ...x, edgeName: name };
    tokOpen = true;
  }

  async function newToken(x: Edge) {
    const r = await act(post<EdgeToken>(`/edges/${encodeURIComponent(x.id)}/token`), t.saved);
    if (r && !r.quorum) showToken(r.data, x.name);
    load();
  }
  async function connect(x: Edge) {
    const r = await act(post<{ id: number }>(`/edges/${encodeURIComponent(x.id)}/enroll`), (d) => t.edges.connected(d.id), jobLink);
    if (r && !r.quorum) navigate(`/jobs/${r.data.id}`);
  }
  async function remove(x: Edge) {
    if (!(await askConfirm(t.edges.removeConfirm(x.name, x.agents)))) return;
    if (await act(del(`/edges/${encodeURIComponent(x.id)}`), t.edges.removed)) load();
  }

  let detail: Edge | null = $state(null);
  let detailOpen = $state(false);
</script>

<div class="settings-section">
  <p class="intro muted">{t.edges.intro}</p>
  <ErrorBanner {error} />
  <section class="card">
    <div class="page-head">
      <h2>{t.settings.tabs.edges}</h2>
      <button type="button" class="primary" onclick={add}><IconPlus aria-hidden="true" />{t.edges.add}</button>
    </div>
    {#if !loaded}
      <p class="muted" aria-busy="true">{t.loading}</p>
    {:else if edges.length === 0}
      <p class="empty">{t.edges.none}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.name}</th>
              <th scope="col">{t.edges.publicHost}</th>
              <th scope="col">{t.edges.state}</th>
              <th scope="col">{t.edges.version}</th>
              <th scope="col">{t.edges.lastSeen}</th>
              <th scope="col">{t.edges.agents}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each edges as x (x.id)}
              {@const st = edgeState(x)}
              <tr>
                <td><strong>{x.name}</strong> <div class="muted mono">{x.id}</div></td>
                <td class="mono">{x.public_host}:{x.public_port}<div class="muted" title={t.edges.host}>{x.host}:{x.port}</div></td>
                <td>
                  <span class="chip {stateCls[st]}">{t.edges.states[st]}</span>
                  {#if st === 'pending' || st === 'expired'}<div class="muted">{t.edges.expires}: {fmtTime(x.token_expires)}</div>{/if}
                </td>
                <td class="mono">{x.version ?? '—'}</td>
                <td class="nowrap" title={fmtTime(x.last_seen)}>{fmtAgo(x.last_seen, now)}</td>
                <td class="nowrap">{t.edges.agentsOnline(x.health?.agents_online.length ?? 0, x.agents)}</td>
                <td class="actions">
                  {#if x.enrolled_at}
                    <button type="button" class="small" onclick={() => ((detail = x), (detailOpen = true))}>{t.edges.details}</button>
                  {/if}
                  {#if st === 'pending'}
                    <button type="button" class="small primary" onclick={() => connect(x)}>{t.edges.connect}</button>
                  {/if}
                  <button type="button" class="small" onclick={() => newToken(x)}>{t.edges.newToken}</button>
                  <button type="button" class="small danger" onclick={() => remove(x)}>{t.edges.remove}</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

<Modal bind:open title={t.edges.addTitle} wide>
  <form onsubmit={save}>
    <div class="form-grid">
      <div class="field">
        <label for="ed-name">{t.name}</label>
        <input id="ed-name" bind:value={f.name} required maxlength="64" autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label for="ed-public">{t.edges.publicHost}</label>
        <input id="ed-public" class="mono" bind:value={f.publicHost} required maxlength="253" spellcheck="false" aria-describedby="ed-public-hint" />
        <div class="hint" id="ed-public-hint">{t.edges.publicHostHint}</div>
      </div>
      <div class="field">
        <label for="ed-pport">{t.edges.publicPort}</label>
        <input id="ed-pport" type="number" min="1" max="65535" bind:value={f.publicPort} required />
      </div>
      <div class="field">
        <label for="ed-host">{t.edges.host}</label>
        <input id="ed-host" class="mono" bind:value={f.host} required maxlength="253" spellcheck="false" aria-describedby="ed-host-hint" />
        <div class="hint" id="ed-host-hint">{t.edges.hostHint}</div>
      </div>
      <div class="field">
        <label for="ed-port">{t.edges.port}</label>
        <input id="ed-port" type="number" min="1" max="65535" bind:value={f.port} required />
      </div>
    </div>
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary">{t.create}</button>
    </div>
  </form>
</Modal>

<Modal bind:open={tokOpen} title={t.edges.tokenTitle(token?.edgeName ?? '')} wide>
  {#if token}
    <p class="banner warn" role="alert">{t.edges.tokenOnce}</p>
    <div class="field">
      <span class="muted">{t.edges.token}</span>
      <code class="secret">{token.token}</code>
      <button type="button" class="small" onclick={() => copyText(token!.token)}>{t.users.copy}</button>
    </div>
    <div class="field">
      <span class="muted">{t.edges.setup}</span>
      <code class="secret">{token.setup}</code>
    </div>
    <p class="muted">{t.edges.expires}: {fmtTime(token.expires)}</p>
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (tokOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>

<Modal bind:open={detailOpen} title={detail?.name ?? ''} wide>
  {#if detail}
    <dl class="kv-list">
      <dt>{t.edges.fingerprint}</dt>
      <dd class="mono">{detail.cert_sha256 ?? '—'}</dd>
      {#if detail.health}
        <dt>{t.edges.uptime}</dt>
        <dd>{fmtDuration(detail.health.uptime_secs)}</dd>
        <dt>{t.edges.connections}</dt>
        <dd>{detail.health.connections}</dd>
        <dt>{t.edges.relays}</dt>
        <dd>{detail.health.relays}</dd>
        <dt>{t.edges.refused}</dt>
        <dd>{detail.health.refused}</dd>
        <dt>{t.edges.rateLimited}</dt>
        <dd>{detail.health.rate_limited}</dd>
      {/if}
    </dl>
    <h3>{t.edges.log}</h3>
    {#if detail.log.length === 0}
      <p class="empty">{t.edges.logNone}</p>
    {:else}
      <pre class="log">{detail.log.join('\n')}</pre>
    {/if}
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (detailOpen = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>
