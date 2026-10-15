<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, act, errText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { href } from '../../lib/router.svelte';
  import { fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { FirewallService, FirewallState } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import Modal from '../../components/Modal.svelte';

  // Phase 16c (docs/control-plane.md "Inbound firewall"): per-service source lists. The server
  // validates and gates (approval for every change, lock-out guard for the web service).
  let cur: FirewallState | null = $state(null);
  let error: string | null = $state(null);
  const isAdmin = $derived(session.user?.role === 'admin');

  async function load() {
    try {
      cur = await get<FirewallState>('/firewall');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  // ---- edit dialog
  let open = $state(false);
  let svc = $state<FirewallService | null>(null);
  let text = $state('');
  let enabled = $state(true);
  let confirmIp = $state('');

  function edit(s: FirewallService) {
    svc = s;
    text = s.allow.join('\n');
    enabled = s.enabled;
    confirmIp = '';
    open = true;
  }

  const list = $derived(
    text
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean),
  );
  // client-side hints only; the server normalises and decides
  const problems = $derived.by(() => {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const c of list) {
      if (!cidrOk(c)) out.push(t.firewall.invalid(c));
      else if (seen.has(c.toLowerCase())) out.push(t.firewall.duplicate(c));
      seen.add(c.toLowerCase());
    }
    if (list.length > 64) out.push(t.firewall.tooMany);
    return out;
  });
  const lockout = $derived(!!svc?.lockout && list.length > 0 && !list.some((c) => covers(c, cur?.client_ip ?? '')));

  function cidrOk(c: string): boolean {
    const [a, p, extra] = c.split('/');
    if (extra !== undefined) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) {
      return (
        a.split('.').every((o) => Number(o) <= 255) && (p === undefined || (/^\d{1,2}$/.test(p) && Number(p) <= 32))
      );
    }
    return (
      /^[0-9a-fA-F:.]+$/.test(a) && a.includes(':') && (p === undefined || (/^\d{1,3}$/.test(p) && Number(p) <= 128))
    );
  }
  function covers(c: string, ip: string): boolean {
    const [net, p] = c.split('/');
    if (net === ip) return true;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(net ?? '') || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
    const n = (s: string) => s.split('.').reduce((a, x) => a * 256 + Number(x), 0);
    const size = 2 ** (32 - Number(p ?? 32));
    return Math.floor(n(net) / size) === Math.floor(n(ip) / size);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!svc) return;
    const body: Record<string, unknown> = { allow: list };
    if (svc.can_disable) body.enabled = enabled;
    if (lockout) Object.assign(body, { force: true, confirm: confirmIp.trim() });
    if (await act(put(`/firewall/inbound/${svc.id}`, body), t.firewall.saved)) {
      open = false;
      load();
    }
  }

  // `addr . tcp . 8006` (nft element) -> `addr:8006/tcp`
  function endpoint(x: string): string {
    const [a, proto, port] = x.split(' . ');
    if (!port) return x;
    return `${a.includes(':') ? `[${a}]` : a}:${port}/${proto}`;
  }
  const effective = (s: FirewallService) => (s.effective ? [...s.effective.v4, ...s.effective.v6] : null);
</script>

<div class="settings-section">
  <p class="intro muted">{t.firewall.intro}</p>
  <ErrorBanner {error} />

  {#if !cur}
    {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
  {:else}
    {#if cur.status_stale}
      <p class="banner warn">{t.firewall.stale}</p>
    {/if}
    <section class="card" aria-labelledby="fw-in">
      <div class="card-head"><h2 id="fw-in">{t.firewall.services}</h2></div>
      <p class="muted">{t.firewall.you(cur.client_ip, cur.client_allowed)}</p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.firewall.service}</th>
              <th scope="col">{t.firewall.port}</th>
              <th scope="col">{t.firewall.sources}</th>
              <th scope="col">{t.firewall.inEffect}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each cur.services as s (s.id)}
              {@const eff = effective(s)}
              <tr class:muted={!s.available}>
                <td class="wrap">
                  <strong>{t.firewall.names[s.id] ?? s.id}</strong>
                  <div class="muted">{t.firewall.descr[s.id] ?? ''}</div>
                </td>
                <td><code>{s.ports}</code></td>
                <td class="wrap">
                  {#if !s.available}
                    <span class="chip">{t.firewall.notRunning}</span>
                  {:else if !s.enabled}
                    <span class="chip">{t.firewall.off}</span>
                  {:else if s.allow.length === 0}
                    <span class="chip warn">{t.firewall.any}</span>
                  {:else}
                    <span class="chips"
                      >{#each s.allow as c (c)}<span class="chip info"><code>{c}</code></span>{/each}</span
                    >
                  {/if}
                  {#if s.pending}
                    <div><a class="chip warn" href={href('/quorum')}>{t.firewall.pending(s.pending)}</a></div>
                  {/if}
                </td>
                <td class="wrap">
                  {#if !s.available}
                    —
                  {:else if eff === null}
                    <span class="muted">{t.firewall.unknown}</span>
                  {:else if eff.length === 0}
                    {t.firewall.off}
                  {:else if eff.includes('0.0.0.0/0') && eff.includes('::/0')}
                    {t.firewall.any}
                  {:else}
                    <span class="chips"
                      >{#each eff as c (c)}<code class="chip">{c}</code>{/each}</span
                    >
                  {/if}
                </td>
                <td class="actions">
                  {#if isAdmin && s.available}
                    <button type="button" class="small" onclick={() => edit(s)}>{t.firewall.edit}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="hint">{t.firewall.fixed}</p>
      <p class="hint">{t.firewall.reset}</p>
      {#if cur.status_ts}<p class="hint">{t.firewall.asOf(fmtTime(cur.status_ts))}</p>{/if}
    </section>

    <section class="card" aria-labelledby="fw-drops">
      <div class="card-head"><h2 id="fw-drops">{t.firewall.drops}</h2></div>
      <p class="hint">{t.firewall.dropsHint}</p>
      {#if cur.drops.length === 0}
        <p class="empty">{t.firewall.noDrops}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t.firewall.source}</th>
                <th scope="col">{t.firewall.target}</th>
                <th scope="col">{t.firewall.lastSeen}</th>
                <th scope="col" class="num">{t.firewall.packets}</th>
              </tr>
            </thead>
            <tbody>
              {#each cur.drops as d (`${d.src}/${d.proto}/${d.port}`)}
                <tr>
                  <td><code>{d.src}</code></td>
                  <td>{d.port}/{d.proto}</td>
                  <td>{fmtTime(d.last_seen)}</td>
                  <td class="num">{d.packets}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section class="card" aria-labelledby="fw-out">
      <div class="card-head"><h2 id="fw-out">{t.firewall.outbound}</h2></div>
      <p class="hint">{t.firewall.outboundHint}</p>
      {#if cur.outbound}
        <dl class="fw-out">
          {#each [[t.firewall.endpoints, cur.outbound.endpoints], [t.firewall.dns, cur.outbound.dns], [t.firewall.nts, cur.outbound.nts]] as [label, items] (label)}
            <dt>{label}</dt>
            <dd>
              {#if (items as string[]).length === 0}<span class="muted">{t.firewall.none}</span>
              {:else}<span class="chips"
                  >{#each items as string[] as x (x)}<code class="chip">{endpoint(x)}</code>{/each}</span
                >{/if}
            </dd>
          {/each}
        </dl>
      {:else}
        <p class="muted">{t.firewall.unknown}</p>
      {/if}
    </section>
  {/if}
</div>

<Modal bind:open title={t.firewall.editTitle(svc ? (t.firewall.names[svc.id] ?? svc.id) : '')} wide>
  {#if svc && cur}
    <form onsubmit={save}>
      <p class="muted">{t.firewall.descr[svc.id] ?? ''}</p>
      {#if svc.can_disable}
        <label class="inline-check"><input type="checkbox" bind:checked={enabled} />{t.firewall.enabled}</label>
      {/if}
      <div class="field">
        <label for="fw-allow">{t.firewall.allowField}</label>
        <textarea
          id="fw-allow"
          rows="6"
          bind:value={text}
          spellcheck="false"
          autocapitalize="none"
          disabled={svc.can_disable && !enabled}></textarea>
      </div>
      {#each problems as p (p)}<p class="banner error" role="alert">{p}</p>{/each}
      {#if lockout}
        <p class="banner warn" role="alert">{t.firewall.lockout(cur.client_ip)}</p>
        <div class="field">
          <label for="fw-confirm">{t.firewall.confirm}</label>
          <input id="fw-confirm" bind:value={confirmIp} required autocomplete="off" spellcheck="false" />
        </div>
      {/if}
      <p class="hint">{t.firewall.approvalHint}</p>
      <div class="form-actions">
        <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={problems.length > 0}>{t.save}</button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  td.wrap {
    max-width: 26rem;
    white-space: normal;
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 0.25rem;
  }
  .fw-out {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.5rem 1rem;
    margin: 0;
  }
  .fw-out dd {
    margin: 0;
  }
</style>
