<script lang="ts">
  // Phase 22b: instant disk recovery — one disk of a VM snapshot attached to an existing
  // VM (a VM a group of the tenant protects; the scheduler checks it) through the instant
  // recovery overlay, optionally moved to real storage afterwards.
  import { onMount } from 'svelte';
  import { get, post, act } from '../lib/api';
  import { navigate } from '../lib/router.svelte';
  import { session } from '../lib/session.svelte';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Group, Snapshot } from '../lib/types';
  import Modal from './Modal.svelte';

  let { open = $bindable(false), snap, nodes = [] }: { open?: boolean; snap: Snapshot | null; nodes?: string[] } = $props();
  let groups: Group[] = $state([]);
  let node = $state('');
  let target = $state('');
  let disk = $state('scsi1');
  let key = $state('');
  let moveTo = $state('');
  let busy = $state(false);
  onMount(async () => {
    groups = await get<Group[]>('/groups').catch(() => []);
  });
  // VMs the tenant's groups protect (the only allowed targets)
  const targets = $derived(
    [
      ...new Set(
        groups
          .filter((g) => g.tenant === snap?.tenant)
          .flatMap((g) => (g.resolved_guests ?? g.guests ?? []) as unknown[])
          .filter((v): v is number => typeof v === 'number'),
      ),
    ].sort((a, b) => a - b),
  );
  $effect(() => {
    if (open && !node && nodes.length) node = nodes[0];
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!snap) return;
    busy = true;
    const params: Record<string, unknown> = {
      source: snap.source,
      time: snap.time,
      device: `drive-${disk.trim()}`,
      node,
      target: Number(target),
    };
    if (key.trim()) params.key = key.trim();
    if (moveTo.trim()) params.move_to = moveTo.trim();
    const r = await act(post<{ id?: number }>('/jobs', { kind: 'instant_disk', tenant: snap.tenant, params }), (d) =>
      d.id ? t.snap.jobStarted(d.id) : t.idr.requested,
    );
    busy = false;
    if (r) open = false;
    if (r && !r.quorum && r.data?.id) navigate(`/jobs/${r.data.id}`);
  }
</script>

<Modal bind:open title={snap ? t.idr.title(snap.source) : ''}>
  {#if snap}
    <form onsubmit={submit}>
      <p class="muted">{snap.tenant} · {fmtTime(snap.time)}</p>
      <p class="banner info">{t.idr.intro}</p>
      <div class="form-grid">
        <div class="field">
          <label for="idr-disk">{t.idr.disk}</label>
          <input id="idr-disk" class="mono" bind:value={disk} required list="idr-disks" pattern="(scsi|virtio|sata|ide)[0-9]{'{1,3}'}" aria-describedby="idr-disk-hint" />
          <datalist id="idr-disks">{#each ['scsi0', 'scsi1', 'scsi2', 'virtio0', 'virtio1', 'sata0'] as d (d)}<option value={d}></option>{/each}</datalist>
          <div class="hint" id="idr-disk-hint">{t.idr.diskHint}</div>
        </div>
        <div class="field">
          <label for="idr-node">{t.snap.node}</label>
          <input id="idr-node" bind:value={node} list="idr-nodes" required autocomplete="off" />
          <datalist id="idr-nodes">{#each nodes as n (n)}<option value={n}></option>{/each}</datalist>
        </div>
        <div class="field">
          <label for="idr-target">{t.idr.target}</label>
          <input id="idr-target" type="number" min="100" max="999999999" bind:value={target} required list="idr-targets" aria-describedby="idr-target-hint" />
          <datalist id="idr-targets">{#each targets as v (v)}<option value={v}></option>{/each}</datalist>
          <div class="hint" id="idr-target-hint">{t.idr.targetHint}</div>
        </div>
        <div class="field">
          <label for="idr-key">{t.idr.key}</label>
          <input id="idr-key" class="mono" bind:value={key} placeholder={t.idr.keyAuto} pattern="(scsi|virtio|sata|ide)[0-9]{'{1,3}'}" />
        </div>
        <div class="field">
          <label for="idr-move">{t.idr.moveTo}</label>
          <input id="idr-move" bind:value={moveTo} placeholder="local-lvm" aria-describedby="idr-move-hint" />
          <div class="hint" id="idr-move-hint">{t.idr.moveToHint}</div>
        </div>
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={busy}>{session.vault ? t.vault.requestRestore : t.idr.attach}</button>
      </div>
    </form>
  {/if}
</Modal>
