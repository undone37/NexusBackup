<script lang="ts">
  // Phase 33: synthetic (clean-file) restore of an agent, NAS or share snapshot: the newest clean
  // version of each file, as a download or onto a host (same confirmation as Restore files).
  import { get, post, act, qs } from '../lib/api';
  import { navigate } from '../lib/router.svelte';
  import { hostAgentId } from '../lib/jobs';
  import { absHostPath, fmtAgo, fmtTime } from '../lib/format';
  import { can } from '../lib/roles';
  import { t } from '../lib/i18n';
  import { session } from '../lib/session.svelte';
  import type { Agent, Overwrite, Snapshot } from '../lib/types';
  import Modal from './Modal.svelte';
  import InfectedNotice from './InfectedNotice.svelte';

  let {
    open = $bindable(false),
    tenant,
    source,
    time,
    agents,
  }: { open?: boolean; tenant: string; source: string; time: number; agents: Agent[] } = $props();

  const id = $props.id();
  const OVERWRITE: Overwrite[] = ['never', 'if_older', 'always'];
  const candidates = $derived(
    agents
      .filter((a) => a.tenant === tenant)
      .sort(
        (a, b) =>
          Number(b.enrolled_at !== null) - Number(a.enrolled_at !== null) || (b.last_seen ?? 0) - (a.last_seen ?? 0),
      ),
  );
  const own = $derived(hostAgentId(source));
  const mayDownload = $derived(can.download(session.user));
  let mode = $state<'download' | 'host'>('download');
  let format = $state<'tar' | 'zip'>('tar');
  let below = $state('/');
  let depth = $state(30);
  let target = $state('');
  let overwrite: Overwrite = $state('never');
  let agentId = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let snap: Snapshot | null = $state(null);

  let wasOpen = false;
  $effect(() => {
    if (open && !wasOpen) {
      mode = mayDownload ? 'download' : 'host';
      format = 'tar';
      below = '/';
      depth = 30;
      agentId = '';
      target = '';
      overwrite = 'never';
      confirm = '';
      snap = null;
      get<Snapshot[]>('/snapshots' + qs({ tenant, source }))
        .then((xs) => (snap = xs.find((x) => x.time === time) ?? null))
        .catch(() => {});
    }
    wasOpen = open;
  });
  $effect(() => {
    if (!open || agentId) return;
    const enrolled = candidates.filter((a) => a.enrolled_at !== null);
    agentId = enrolled.find((a) => a.id === own)?.id ?? enrolled[0]?.id ?? '';
  });

  const agent = $derived(candidates.find((a) => a.id === agentId) ?? null);
  const production = $derived(mode === 'host' && (target.trim() === '/' || overwrite !== 'never'));
  function isolatePath() {
    overwrite = 'never';
    if (target.trim() === '/') target = '';
    document.getElementById(`${id}-target`)?.focus();
  }
  const belowOk = $derived(absHostPath(below));
  const depthOk = $derived(Number.isInteger(Number(depth)) && Number(depth) >= 1 && Number(depth) <= 100);
  const ready = $derived(
    belowOk &&
      depthOk &&
      !busy &&
      (mode === 'download' ? mayDownload : !!agent && absHostPath(target) && confirm === agent.name),
  );

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!ready) return;
    busy = true;
    const base = { source, time, paths: [below.trim()], depth: Number(depth), mode };
    const params =
      mode === 'download' ? { ...base, format } : { ...base, target, overwrite, confirm, agent_id: agent!.id };
    const r = await act(post<{ id: number }>('/jobs', { kind: 'synthetic_restore', tenant, params }), (d) =>
      t.synth.started(d.id),
    );
    busy = false;
    if (!r) return;
    open = false;
    if (!r.quorum) navigate(`/jobs/${r.data.id}`);
  }
</script>

<Modal bind:open title={t.synth.title(source)} wide>
  <form onsubmit={submit}>
    <p class="muted">{tenant} · {fmtTime(time)}</p>
    <p>{t.synth.intro}</p>
    <p class="banner info">{t.synth.unscannedNote}</p>
    <div class="form-grid">
      <div class="field">
        <label for="{id}-below">{t.synth.below}</label>
        <input
          id="{id}-below"
          class="mono"
          bind:value={below}
          required
          autocomplete="off"
          spellcheck="false"
          aria-describedby="{id}-below-hint"
        />
        <div class="hint" id="{id}-below-hint">{t.synth.belowHint}</div>
      </div>
      <div class="field">
        <label for="{id}-depth">{t.synth.depth}</label>
        <input
          id="{id}-depth"
          type="number"
          min="1"
          max="100"
          bind:value={depth}
          required
          aria-describedby="{id}-depth-hint"
        />
        <div class="hint" id="{id}-depth-hint">{t.synth.depthHint}</div>
      </div>
    </div>
    <fieldset>
      <legend>{t.synth.mode}</legend>
      {#each ['download', 'host'] as m (m)}
        <label class="inline-check">
          <input
            type="radio"
            name="{id}-mode"
            value={m}
            bind:group={mode}
            disabled={m === 'download' && !mayDownload}
          />{t.synth.modes[m]}
        </label>
      {/each}
    </fieldset>
    {#if mode === 'download'}
      <div class="field">
        <label for="{id}-fmt">{t.synth.format}</label>
        <select id="{id}-fmt" bind:value={format}>
          <option value="tar">tar</option>
          <option value="zip">zip</option>
        </select>
      </div>
    {:else}
      <p class="banner warn">{t.restoreFiles.intro}</p>
      <div class="form-grid">
        <div class="field">
          <label for="{id}-target">{t.restoreFiles.target}</label>
          <input
            id="{id}-target"
            class="mono"
            bind:value={target}
            required
            pattern="/.*"
            placeholder="/srv/restore"
            autocomplete="off"
            spellcheck="false"
            aria-describedby="{id}-target-hint"
          />
          <div class="hint" id="{id}-target-hint">{t.restoreFiles.targetHint}</div>
        </div>
        <div class="field">
          <label for="{id}-ow">{t.restoreFiles.overwrite}</label>
          <select id="{id}-ow" bind:value={overwrite}>
            {#each OVERWRITE as o (o)}<option value={o}>{t.restoreFiles.overwriteOpts[o]}</option>{/each}
          </select>
        </div>
      </div>
      <div class="field">
        <label for="{id}-agent">{t.restoreFiles.agent}</label>
        <select id="{id}-agent" bind:value={agentId} required>
          {#each candidates as a (a.id)}
            <option value={a.id} disabled={a.enrolled_at === null}
              >{a.name} ({a.host}) — {a.enrolled_at === null
                ? t.restoreFiles.notEnrolled
                : t.restoreFiles.lastSeen(fmtAgo(a.last_seen))}</option
            >
          {/each}
        </select>
        {#if !agent}<div class="hint">{t.restoreFiles.noAgent}</div>{/if}
      </div>
      <InfectedNotice {snap} {production} onisolatePath={isolatePath} />
      {#if agent}
        <div class="field">
          <label for="{id}-confirm">{t.restoreFiles.confirm}</label>
          <input
            id="{id}-confirm"
            class="mono"
            bind:value={confirm}
            required
            autocomplete="off"
            autocapitalize="none"
            spellcheck="false"
            aria-describedby="{id}-confirm-hint"
          />
          <div class="hint" id="{id}-confirm-hint">{t.restoreFiles.confirmHint(agent.name)}</div>
        </div>
      {/if}
    {/if}
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={!ready}
        >{session.vault ? t.vault.requestRestore : t.synth.start}</button
      >
    </div>
  </form>
</Modal>
