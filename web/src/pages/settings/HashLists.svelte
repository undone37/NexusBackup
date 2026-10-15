<script lang="ts">
  import { onMount } from 'svelte';
  import { get, put, del, act, errText } from '../../lib/api';
  import { askConfirm } from '../../lib/confirm.svelte';
  import { fmtBytes, fmtTime } from '../../lib/format';
  import { t } from '../../lib/i18n';
  import type { HashList } from '../../lib/types';
  import ErrorBanner from '../../components/ErrorBanner.svelte';
  import IconTrash from '@lucide/svelte/icons/trash-2';

  // Phase 28: IOC hash lists (SHA-256 of known-bad files) for the hash hunt. Admins and
  // security officers upload and delete them; the server parses and normalises the text.
  const MAX_FILE = 16 * 1024 * 1024;
  let lists = $state<HashList[] | null>(null);
  let error: string | null = $state(null);
  let name = $state('');
  let text = $state('');
  let busy = $state(false);
  const nameOk = $derived(/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$/.test(name));
  const total = $derived((lists ?? []).reduce((n, l) => n + l.count, 0));

  async function load() {
    try {
      lists = await get<HashList[]>('/hash-lists');
      error = null;
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(load);

  async function pick(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!f) return;
    if (f.size > MAX_FILE) {
      error = t.threat.tooLarge(fmtBytes(MAX_FILE));
      return;
    }
    text = await f.text();
    if (!name)
      name = f.name
        .replace(/\.(txt|csv)$/i, '')
        .replace(/[^A-Za-z0-9._-]/g, '_')
        .replace(/^\.+/, '')
        .slice(0, 64);
  }

  async function upload(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    const r = await act(
      put<{ count: number; skipped: number }>(`/hash-lists/${encodeURIComponent(name)}`, { text }),
      (d) => t.threat.uploaded(name, d.count, d.skipped),
    );
    busy = false;
    if (r) {
      name = '';
      text = '';
      load();
    }
  }

  async function remove(l: HashList) {
    if (!(await askConfirm(t.threat.deleteConfirm(l.name)))) return;
    if (await act(del(`/hash-lists/${encodeURIComponent(l.name)}`), t.threat.deleted(l.name))) load();
  }
</script>

<ErrorBanner {error} />
<section class="card settings-section" aria-labelledby="hl-h">
  <div class="card-head">
    <h2 id="hl-h">{t.settings.tabs.iocHashes}</h2>
    {#if lists}<span class="chip {lists.length ? 'ok' : 'warn'}"
        >{lists.length ? t.threat.listCount(lists.length) : t.threat.noLists}</span
      >{/if}
  </div>
  <p>{t.threat.listsIntro}</p>
  <p class="muted">{t.threat.listsLimits}</p>
  {#if lists === null}
    {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
  {:else if lists.length}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t.threat.listName}</th>
            <th scope="col" class="num">{t.threat.hashes}</th>
            <th scope="col">SHA-256</th>
            <th scope="col">{t.scan.uploadedBy}</th>
            <th scope="col"><span class="sr-only">{t.actions}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each lists as l (l.name)}
            <tr>
              <td class="mono">{l.name}</td>
              <td class="num">{l.count.toLocaleString()}</td>
              <td class="mono" title={l.sha256}>{l.sha256.slice(0, 16)}…</td>
              <td>{l.uploaded_by} <span class="muted">{fmtTime(l.uploaded_at)}</span></td>
              <td class="actions">
                <button
                  type="button"
                  class="small danger"
                  onclick={() => remove(l)}
                  aria-label={t.scan.deleteLabel(l.name)}><IconTrash aria-hidden="true" />{t.delete}</button
                >
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="hint">{t.threat.hashes}: {total.toLocaleString()}</p>
  {/if}
  <form onsubmit={upload}>
    <h3>{t.threat.upload}</h3>
    <div class="form-grid">
      <div class="field">
        <label for="hl-file">{t.threat.listFile}</label>
        <input id="hl-file" type="file" accept=".txt,.csv,text/plain,text/csv" onchange={pick} />
      </div>
      <div class="field">
        <label for="hl-name">{t.threat.listName}</label>
        <input
          id="hl-name"
          class="mono"
          bind:value={name}
          required
          maxlength="64"
          aria-invalid={name !== '' && !nameOk}
          aria-describedby="hl-name-hint"
        />
        <div class="hint" id="hl-name-hint">{t.scan.fileNameHint}</div>
      </div>
    </div>
    <div class="field">
      <label for="hl-text">{t.threat.listText}</label>
      <textarea id="hl-text" class="mono" rows="8" bind:value={text} required spellcheck="false"></textarea>
    </div>
    <div class="form-actions">
      <button type="submit" class="primary" disabled={busy || !nameOk || !text.trim()}>{t.threat.upload}</button>
    </div>
  </form>
</section>
