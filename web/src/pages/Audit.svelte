<script lang="ts">
  import { onMount } from 'svelte';
  import { get, errText } from '../lib/api';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { AuditEntry, AuditVerify } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';

  let entries: AuditEntry[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);
  let more = $state(true);
  let verify: { ok: boolean; text: string } | null = $state(null);
  let verifying = $state(false);

  const PAGE = 100;
  // Newest first; older pages via ?before=<oldest seq shown>.
  async function loadMore() {
    try {
      const q = entries.length ? `before=${entries[entries.length - 1].seq}` : 'order=desc';
      const page = await get<AuditEntry[]>(`/audit?${q}&limit=${PAGE}`);
      entries = [...entries, ...page];
      more = page.length === PAGE;
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(loadMore);

  async function runVerify() {
    verifying = true;
    verify = null;
    try {
      const r = await get<AuditVerify>('/audit/verify');
      verify = r.ok ? { ok: true, text: t.audit.verifiedOk(r.entries) } : { ok: false, text: `${t.audit.verifiedBad}: ${r.error ?? ''}` };
    } catch (e) {
      verify = { ok: false, text: `${t.audit.verifiedBad}: ${errText(e)}` };
    } finally {
      verifying = false;
    }
  }

  const short = (h: string) => `${h.slice(0, 10)}…`;
</script>

<div class="page-head">
  <h1>{t.audit.title}</h1>
  <button type="button" class="primary" onclick={runVerify} disabled={verifying}>
    {verifying ? t.audit.verifying : t.audit.verify}
  </button>
  <p class="lede">{t.audit.lede}</p>
</div>

{#if verify}
  <div class="banner {verify.ok ? 'ok' : 'error'}" role="status">{verify.text}</div>
{/if}
<ErrorBanner {error} />

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
              <td class="mono">{e.target}</td>
              <td class="mono details">{JSON.stringify(e.details)}</td>
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
