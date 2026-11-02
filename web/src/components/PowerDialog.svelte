<script lang="ts">
  // Reboot or shut down the appliance (issue #179, the design of NexusStor #86): names the appliance, asks for a
  // reason and the delay, shows the jobs a reboot ends, what blocks it, and that a second person approves it.
  import Modal from './Modal.svelte';
  import { act, post } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { t } from '../lib/i18n';
  import { power, refreshPower, watchDown } from '../lib/power.svelte';
  import type { PowerAction } from '../lib/types';

  let { action = $bindable(null) }: { action?: PowerAction | null } = $props();

  const id = $props.id();
  const DELAYS = [0, 30, 60, 120, 300];
  let open = $state(false);
  let reason = $state('');
  let delay = $state(60);
  let force = $state(false);
  let busy = $state(false);

  const s = $derived(power.status);
  const label = $derived(action === 'poweroff' ? t.power.poweroff : t.power.reboot);
  const blocked = $derived((s?.blockers.length ?? 0) > 0);
  const ready = $derived(reason.trim().length >= 3 && (!blocked || force));

  $effect(() => {
    if (action) {
      open = true;
      reason = '';
      delay = 60;
      force = false;
      refreshPower();
    }
  });
  $effect(() => {
    if (!open) action = null;
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!action || !ready) return;
    const a = action;
    busy = true;
    const o = await act(
      post('/system/power', { action: a, reason: reason.trim(), delay_s: delay, force }),
      t.power.scheduled(label),
    );
    busy = false;
    if (!o) return;
    open = false;
    await refreshPower();
    if (!o.quorum && delay === 0) watchDown(a);
  }
</script>

<Modal bind:open title={t.power.title(label, s?.appliance ?? '')}>
  <form onsubmit={submit}>
    <p>{t.power.intro(s?.appliance ?? '')}</p>
    {#if action === 'poweroff'}
      <p class="banner error" role="alert">{t.power.poweroffWarn}</p>
    {/if}
    {#if s?.request_pending}
      <p class="banner warn" role="status">
        {t.power.waitingApproval(s.request_pending.id, s.request_pending.requested_by)}
        <a href={href(`/quorum?id=${s.request_pending.id}`)}>{t.openApproval(s.request_pending.id)}</a>
      </p>
    {/if}
    {#if s?.running_jobs}
      <p class="banner warn" role="alert">
        <span>
          <strong>{t.power.running(s.running_jobs)}</strong>
          {t.power.runningHint}
          <a href={href('/jobs?state=running')}>{t.power.runningLink}</a>
        </span>
      </p>
    {/if}
    {#if s && blocked}
      <div class="banner warn" role="alert">
        <div>
          <p>{t.power.blocked}</p>
          <ul>
            {#each s.blockers as b (b)}<li>{b}</li>{/each}
          </ul>
          <label class="check"><input type="checkbox" bind:checked={force} /> {t.power.force}</label>
          <p class="hint">{t.power.forceHint}</p>
        </div>
      </div>
    {/if}
    <div class="form-grid">
      <div class="field">
        <label for="{id}-delay">{t.power.delay}</label>
        <select id="{id}-delay" bind:value={delay} aria-describedby="{id}-delay-hint">
          {#each DELAYS as d (d)}<option value={d}>{t.power.delays[d]}</option>{/each}
        </select>
        <p id="{id}-delay-hint" class="hint">{t.power.delayHint}</p>
      </div>
      <div class="field">
        <label for="{id}-reason">{t.power.reason}</label>
        <input
          id="{id}-reason"
          bind:value={reason}
          minlength="3"
          maxlength="500"
          required
          autocomplete="off"
          aria-describedby="{id}-reason-hint"
        />
        <p id="{id}-reason-hint" class="hint">{t.power.reasonHint}</p>
      </div>
    </div>
    {#if s?.approval_required}
      <p class="hint">{t.power.approval}</p>
    {/if}
    <div class="form-actions">
      <!-- svelte-ignore a11y_autofocus -->
      <button type="button" onclick={() => (open = false)} autofocus>{t.cancel}</button>
      <button type="submit" class="danger" disabled={busy || !ready}>{t.power.submit(label)}</button>
    </div>
  </form>
</Modal>
