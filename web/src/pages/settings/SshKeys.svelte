<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { session } from '../../lib/session.svelte';
  import { copyText } from '../../lib/clipboard';
  import { fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { SshKey } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconCopy from '@lucide/svelte/icons/copy';
  import IconRotate from '@lucide/svelte/icons/rotate-cw';
  import IconKey from '@lucide/svelte/icons/key-round';

  const admin = $derived(session.user?.role === 'admin');
  let keys: SshKey[] = $state([]);
  let error: string | null = $state(null);
  let loaded = $state(false);

  async function load() {
    try {
      keys = await get<SshKey[]>('/ssh-keys');
      error = null;
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  onMount(load);

  // One card per key name. The old key after a rotation arrives as `previous`; a server that lists
  // both keys as separate entries of the same name is handled too (newest = current).
  const byName = $derived.by(() => {
    const m = new Map<string, SshKey[]>();
    for (const k of keys) m.set(k.name, [...(m.get(k.name) ?? []), k]);
    return [...m.values()].map((xs) => {
      const [cur, ...older] = [...xs].sort((a, b) => b.created - a.created);
      const prev = cur.previous ?? older[0] ?? null;
      return { cur, prev };
    });
  });

  async function rotate(k: SshKey) {
    if (!(await askConfirm(t.settings.ssh.rotateConfirm(k.name)))) return;
    if (await act(post(`/ssh-keys/${encodeURIComponent(k.name)}/rotate`), t.settings.ssh.rotated)) load();
  }
  async function retire(k: SshKey) {
    if (!(await askConfirm(t.settings.ssh.retireConfirm(k.name)))) return;
    if (await act(post(`/ssh-keys/${encodeURIComponent(k.name)}/retire`), t.settings.ssh.retired)) load();
  }
</script>

<div class="settings-section">
  <p class="intro muted">{t.settings.ssh.intro}</p>
  <ErrorBanner {error} />
  {#if !loaded}
    <p class="muted" aria-busy="true">{t.loading}</p>
  {:else if byName.length === 0}
    <div class="card"><p class="empty">{t.settings.ssh.none}</p></div>
  {:else}
    {#each byName as { cur, prev } (cur.name)}
      <section class="card" aria-labelledby="ssh-{cur.name}">
        <div class="card-head">
          <div class="row">
            <IconKey aria-hidden="true" />
            <h2 id="ssh-{cur.name}" class="mono">{cur.name}</h2>
            <span class="muted">{cur.purpose}</span>
          </div>
          {#if admin}
            <div class="row">
              {#if prev}<button type="button" class="small danger" onclick={() => retire(cur)}>{t.settings.ssh.retire}</button>{/if}
              <button type="button" class="small" onclick={() => rotate(cur)} disabled={!!prev}><IconRotate aria-hidden="true" />{t.settings.ssh.rotate}</button>
            </div>
          {/if}
        </div>
        {#snippet keyBlock(k: { public_key: string; fingerprint: string; created: number }, title: string)}
          <div class="key-card">
            <dl class="kv-list">
              <dt>{t.settings.ssh.fingerprint}</dt>
              <dd class="mono">{k.fingerprint}</dd>
              <dt>{t.settings.ssh.created}</dt>
              <dd>{fmtTime(k.created)}</dd>
            </dl>
            <div class="copyline">
              <code>{k.public_key}</code>
              <button type="button" class="small" onclick={() => copyText(k.public_key)} aria-label="{t.users.copy}: {title} {cur.name}"
                ><IconCopy aria-hidden="true" />{t.users.copy}</button
              >
            </div>
          </div>
        {/snippet}
        {#if prev}<h3>{t.settings.ssh.current}</h3>{/if}
        {@render keyBlock(cur, t.settings.ssh.current)}
        {#if prev}
          <h3 class="prev-title"><span class="chip warn">{t.settings.ssh.previous}</span></h3>
          {@render keyBlock(prev, t.settings.ssh.previous)}
        {/if}
      </section>
    {/each}
  {/if}
</div>

<style>
  .prev-title {
    margin-top: 1rem;
  }
</style>
