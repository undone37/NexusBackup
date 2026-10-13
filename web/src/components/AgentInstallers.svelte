<script lang="ts">
  // Phase 27: signed installers of an agent release, downloaded through a one-time
  // download token (POST /agent-releases/{version}/download, then GET /downloads/{token}).
  import { post, act } from '../lib/api';
  import { downloadUrl } from '../lib/jobs';
  import { fmtBytes } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { AgentDownload, AgentRelease } from '../lib/types';

  /** download-only and package kinds offered for installation (not the raw update binary) */
  const INSTALL_KINDS = ['deb', 'rpm', 'msi', 'bundle', 'desktop-deb', 'desktop-rpm', 'exe'];
  let { release, all = false }: { release: AgentRelease | null; all?: boolean } = $props();
  const items = $derived(
    (release?.artifacts ?? [])
      .filter((a) => all || INSTALL_KINDS.includes(a.kind))
      .sort((a, b) => INSTALL_KINDS.indexOf(a.kind) - INSTALL_KINDS.indexOf(b.kind) || a.name.localeCompare(b.name)),
  );
  const base = (n: string) => n.split('/').pop() ?? n;
  let busy = $state('');

  async function download(name: string) {
    if (!release) return;
    busy = name;
    const r = await act(
      post<AgentDownload>(`/agent-releases/${encodeURIComponent(release.version)}/download`, { artifact: name }),
      (d) => d.name,
    );
    busy = '';
    if (!r || r.quorum) return;
    const a = document.createElement('a');
    a.href = downloadUrl(r.data.token);
    a.download = base(r.data.name);
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
</script>

{#if !release || !release.signed || items.length === 0}
  <p class="muted">{t.agentUpd.installersNone}</p>
{:else}
  <p class="hint">{t.agentUpd.installersIntro(release.version)}</p>
  <div class="table-wrap">
    <table class="installers">
      <thead>
        <tr>
          <th scope="col">{t.agentUpd.artifacts}</th>
          <th scope="col">SHA-256</th>
          <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
        </tr>
      </thead>
      <tbody>
        {#each items as a (a.name)}
          <tr>
            <td>
              {t.agentUpd.kinds[a.kind] ?? a.kind} <span class="muted">({a.os} {a.arch})</span>
              <div class="mono muted">{base(a.name)} · {fmtBytes(a.size)}</div>
            </td>
            <td><div class="mono sha">{a.sha256}</div></td>
            <td class="actions">
              <button type="button" class="small" disabled={busy === a.name} aria-label={t.agentUpd.downloadLabel(base(a.name))} onclick={() => download(a.name)}
                >{t.agentUpd.download}</button
              >
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .sha {
    width: 16rem;
    word-break: break-all;
    font-size: 0.8em;
  }
</style>
