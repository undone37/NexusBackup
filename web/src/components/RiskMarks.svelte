<script lang="ts">
  // Phase 29: accounts marked by a privileged-activity risk signal (GET /risk; admins and security
  // officers). Marked accounts must step up (re-authenticate) before their first change in each
  // session; "Clear" (POST /users/{id}/risk/clear, audited) ends the mark early, never one's own.
  import { onMount } from 'svelte';
  import { get, post, act } from '../lib/api';
  import { askConfirm } from '../lib/confirm.svelte';
  import { session } from '../lib/session.svelte';
  import { fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { RiskMark } from '../lib/types';

  let { hideEmpty = false }: { hideEmpty?: boolean } = $props();
  let marks: RiskMark[] = $state([]);
  let loaded = $state(false);
  async function load() {
    marks = await get<RiskMark[]>('/risk').catch(() => []);
    loaded = true;
  }
  onMount(load);

  async function clear(m: RiskMark) {
    if (!(await askConfirm(t.p29.risk.clearConfirm(m.user)))) return;
    if (await act(post(`/users/${m.user_id}/risk/clear`), t.p29.risk.cleared(m.user))) load();
  }
</script>

{#if loaded && (marks.length || !hideEmpty)}
  <section class="card settings-section" aria-labelledby="risk-h">
    <div class="card-head"><h2 id="risk-h">{t.p29.risk.title}</h2></div>
    <p class="muted">{t.p29.risk.lede}</p>
    {#if !marks.length}
      <p class="empty">{t.none}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.p29.risk.account}</th>
              <th scope="col">{t.users.role}</th>
              <th scope="col">{t.p29.risk.reason}</th>
              <th scope="col">{t.p29.risk.since}</th>
              <th scope="col">{t.p29.risk.until}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each marks as m (m.user_id)}
              <tr>
                <td><strong>{m.user}</strong>{#if m.tenant}<div class="muted">{m.tenant}</div>{/if}</td>
                <td>{t.roles[m.role] ?? m.role}</td>
                <td>{m.reason}</td>
                <td class="nowrap" title={fmtTime(m.since)}>{fmtAgo(m.since)}</td>
                <td class="nowrap">{fmtTime(m.until)}</td>
                <td class="actions">
                  {#if m.user_id !== session.user?.id}
                    <button type="button" class="small" onclick={() => clear(m)} aria-label={t.p29.risk.clearLabel(m.user)}>{t.p29.risk.clear}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{/if}
