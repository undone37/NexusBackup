<script lang="ts">
  import { get, post, act, qs } from '../lib/api';
  import { navigate } from '../lib/router.svelte';
  import { hostAgentId } from '../lib/jobs';
  import { absHostPath, fmtAgo, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import { session } from '../lib/session.svelte';
  import type { Agent, Overwrite, Snapshot } from '../lib/types';
  import type { Snippet } from 'svelte';
  import Modal from './Modal.svelte';
  import ScanFirst from './ScanFirst.svelte';
  import InfectedNotice from './InfectedNotice.svelte';

  // Restore files of a snapshot (host, NAS share / TrueNAS dataset, plugin file tree, or
  // VM/CT files through the restore micro-VM) onto a path of an agent of the same tenant.
  // The user has to type the target agent's name; the server checks it too.
  let {
    open = $bindable(false),
    tenant,
    source,
    time,
    paths,
    agents,
    children,
  }: {
    open?: boolean;
    tenant: string;
    source: string;
    time: number;
    paths: string[];
    agents: Agent[];
    /** shown above the form (Phase 21a: the flagged-snapshot notice) */
    children?: Snippet;
  } = $props();

  const id = $props.id();
  const OVERWRITE: Overwrite[] = ['never', 'if_older', 'always'];

  // agents of the snapshot's tenant; enrolled ones first, most recently seen first
  const candidates = $derived(
    agents
      .filter((a) => a.tenant === tenant)
      .sort((a, b) => Number(b.enrolled_at !== null) - Number(a.enrolled_at !== null) || (b.last_seen ?? 0) - (a.last_seen ?? 0)),
  );
  const own = $derived(hostAgentId(source));
  let target = $state('');
  let overwrite: Overwrite = $state('never');
  let agentId = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let scanFirst: '' | 'refuse' = $state('');

  // Reset the form each time the dialog opens; default target agent = the snapshot's own host.
  let wasOpen = false;
  $effect(() => {
    if (open && !wasOpen) {
      agentId = '';
      target = '';
      overwrite = 'never';
      confirm = '';
      scanFirst = '';
      // Phase 29: is the snapshot flagged (a production restore of it needs approval)?
      snap = null;
      get<Snapshot[]>('/snapshots' + qs({ tenant, source }))
        .then((xs) => (snap = xs.find((x) => x.time === time) ?? null))
        .catch(() => {});
    }
    wasOpen = open;
  });
  let snap: Snapshot | null = $state(null);
  // Phase 29: original paths or overwriting = a production restore
  const production = $derived(target.trim() === '/' || overwrite !== 'never');
  function isolatePath() {
    overwrite = 'never';
    if (target.trim() === '/') target = '';
    document.getElementById(`${id}-target`)?.focus();
  }
  // (Also runs when the agent list arrives after the dialog opened.)
  $effect(() => {
    if (!open || agentId) return;
    const enrolled = candidates.filter((a) => a.enrolled_at !== null);
    agentId = enrolled.find((a) => a.id === own)?.id ?? enrolled[0]?.id ?? '';
  });

  const agent = $derived(candidates.find((a) => a.id === agentId) ?? null);
  // owners are mapped only when the files go back onto the host they came from
  const otherHost = $derived(!!agent && agent.id !== own);
  const targetOk = $derived(absHostPath(target));
  const ready = $derived(!!agent && targetOk && confirm === agent.name && paths.length > 0 && !busy);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!ready || !agent) return;
    busy = true;
    const params = { source, time, paths, target, overwrite, confirm, agent_id: agent.id, ...(scanFirst ? { scan_first: scanFirst } : {}) };
    const r = await act(post<{ id: number }>('/jobs', { kind: 'restore_files', tenant, params }), (d) =>
      t.snap.jobStarted(d.id),
    );
    busy = false;
    if (!r) return;
    open = false;
    if (!r.quorum) navigate(`/jobs/${r.data.id}`);
  }
</script>

<Modal bind:open title={t.restoreFiles.title(source)} wide>
  <form onsubmit={submit}>
    <p class="muted">{tenant} · {fmtTime(time)}</p>
    {@render children?.()}
    <p class="banner warn">{t.restoreFiles.intro}</p>
    <div class="field">
      <span class="muted" id="{id}-paths">{t.restoreFiles.paths}</span>
      <ul class="mono" aria-labelledby="{id}-paths">
        {#each paths as p (p)}<li>{p}</li>{/each}
      </ul>
    </div>
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
          aria-invalid={target !== '' && !targetOk}
          aria-describedby="{id}-target-hint"
        />
        <div class="hint" id="{id}-target-hint">
          {target !== '' && !targetOk ? t.restoreFiles.targetInvalid : t.restoreFiles.targetHint}
        </div>
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
      <select id="{id}-agent" bind:value={agentId} required aria-describedby="{id}-agent-hint">
        {#each candidates as a (a.id)}
          <option value={a.id} disabled={a.enrolled_at === null}
            >{a.name} ({a.host}) — {a.enrolled_at === null
              ? t.restoreFiles.notEnrolled
              : t.restoreFiles.lastSeen(fmtAgo(a.last_seen))}</option
          >
        {/each}
      </select>
      <div class="hint" id="{id}-agent-hint">
        {agent ? (own ? t.restoreFiles.agentHint : t.restoreFiles.agentHintOther) : t.restoreFiles.noAgent}
      </div>
    </div>
    {#if otherHost}<p class="banner info">{t.restoreFiles.otherHost}</p>{/if}
    <InfectedNotice {snap} {production} onisolatePath={isolatePath} />
    <ScanFirst bind:value={scanFirst} />
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
    <div class="form-actions">
      <button type="button" onclick={() => (open = false)}>{t.cancel}</button>
      <button type="submit" class="primary" disabled={!ready}>{session.vault ? t.vault.requestRestore : t.restoreFiles.start}</button>
    </div>
  </form>
</Modal>
