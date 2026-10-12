<script lang="ts">
  // "Back up now" (Phase 13b): the whole group, selected guests, or the guests that failed last time.
  import { post, act } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { t } from '../lib/i18n';
  import type { Group } from '../lib/types';
  import Modal from './Modal.svelte';

  let {
    open = $bindable(false),
    group,
    label = (g: number | string) => String(g),
  }: { open?: boolean; group: Group | null; label?: (g: number | string) => string } = $props();

  let mode: 'all' | 'some' | 'failed' = $state('all');
  let picked: (number | string)[] = $state([]);
  $effect(() => {
    if (open) {
      mode = 'all';
      picked = [];
    }
  });

  // auto-protect groups (13c): what the group covers now
  const guests = $derived(group?.resolved_guests ?? group?.guests ?? []);

  async function run(e: SubmitEvent) {
    e.preventDefault();
    const g = group;
    if (!g) return;
    if (mode === 'some' && !picked.length) {
      notify('error', t.runctl.noGuestSelected);
      return;
    }
    const params: Record<string, unknown> = { group_id: g.id };
    if (mode === 'some') params.guests = guests.filter((x) => picked.includes(x));
    if (mode === 'failed') params.failed_only = true;
    if (await act(post('/jobs', { kind: 'backup', tenant: g.tenant, params }), t.dash.backupQueued)) open = false;
  }
</script>

<Modal bind:open title={group ? t.runctl.backupTitle(group.name) : t.runctl.backupNow}>
  {#if group}
    <form onsubmit={run}>
      {#if group.blackout_active}<p class="banner warn" role="status">{t.runctl.blackoutWarn}</p>{/if}
      <fieldset class="field">
        <legend>{t.groups.guestsShort}</legend>
        <label class="inline-check"><input type="radio" name="bn-mode" value="all" bind:group={mode} />{t.runctl.allGuests}</label>
        {#if guests.length > 1}
          <label class="inline-check"><input type="radio" name="bn-mode" value="some" bind:group={mode} />{t.runctl.someGuests}</label>
          {#if mode === 'some'}
            <div class="guests">
              {#each guests as g (g)}
                <label class="inline-check mono"><input type="checkbox" value={g} bind:group={picked} />{label(g)}</label>
              {/each}
            </div>
          {/if}
        {/if}
        <label class="inline-check"><input type="radio" name="bn-mode" value="failed" bind:group={mode} />{t.runctl.failedOnly}</label>
      </fieldset>
      <div class="form-actions">
        <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
        <button type="submit" class="primary">{t.runctl.backupNow}</button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  .guests {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem 1rem;
    margin: 0 0 0.5rem 1.5rem;
  }
</style>
