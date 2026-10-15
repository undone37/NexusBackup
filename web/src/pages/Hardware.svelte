<script lang="ts">
  import { rowClick } from '../lib/rowlink';
  import { onMount } from 'svelte';
  import { get, post, act, errText } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { can } from '../lib/roles';
  import { fmtAgo, fmtBytes, fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Hardware, HwArray, HwDisk } from '../lib/types';
  import ErrorBanner from '../components/ErrorBanner.svelte';
  import Modal from '../components/Modal.svelte';
  import IconRefresh from '@lucide/svelte/icons/refresh-cw';
  import IconPlus from '@lucide/svelte/icons/plus';
  import IconInfo from '@lucide/svelte/icons/info';

  // Configuration → Hardware (Phase 16a/b): what nexus-disks reports, SMART self-tests,
  // and the data-array layout requests (approval + typed serial numbers; the server decides).
  let hw = $state<Hardware | null>(null);
  let error: string | null = $state(null);
  const admin = $derived(can.manageHardware(session.user));

  async function load() {
    try {
      hw = await get<Hardware>('/hardware');
      error = null;
    } catch (e) {
      error = `${t.hw.loadFailed} (${errText(e)})`;
    }
  }
  // follow running operations and rebuilds closely, otherwise once a minute
  const busy = $derived(
    !!hw &&
      (hw.ops.some((o) => o.state === 'queued' || o.state === 'running') ||
        hw.arrays.some((a) => a.action) ||
        hw.disks.some((d) => d.smart?.self_test?.running)),
  );
  onMount(() => {
    load();
    let last = 0;
    const iv = setInterval(() => {
      const n = Date.now();
      if (busy || n - last >= 60000) {
        last = n;
        load();
      }
    }, 5000);
    return () => clearInterval(iv);
  });

  const sevCls: Record<string, string> = { info: 'info', warning: 'warn', critical: 'bad' };
  const roleCls: Record<string, string> = {
    system: 'plain',
    data: 'accent',
    metadata: 'accent',
    in_use: 'plain',
    empty: 'ok',
  };
  const stateCls: Record<string, string> = {
    clean: 'ok',
    degraded: 'bad',
    failed: 'bad',
    inactive: 'bad',
    recovering: 'info',
    resyncing: 'info',
    reshaping: 'info',
  };
  const memberCls: Record<string, string> = {
    active: 'ok',
    spare: 'plain',
    rebuilding: 'info',
    faulty: 'bad',
    removed: 'bad',
  };
  const opCls: Record<string, string> = { queued: 'info', running: 'info', done: 'ok', refused: 'warn', error: 'bad' };
  const sumCls: Record<string, string> = { ok: 'ok', warning: 'warn', critical: 'bad', unknown: 'plain' };

  function health(d: HwDisk): { cls: string; text: string } {
    const s = d.smart;
    if (!s || !s.available) return { cls: 'plain', text: t.hw.healths.none };
    if (s.health === 'failed') return { cls: 'bad', text: t.hw.healths.failed };
    if (s.standby) return { cls: 'plain', text: t.hw.healths.standby };
    return { cls: d.issues.some((i) => i.severity !== 'info') ? 'warn' : 'ok', text: t.hw.healths.passed };
  }
  function keyAttrs(d: HwDisk): string {
    const s = d.smart;
    if (!s?.available) return '—';
    if (d.type === 'nvme') return t.hw.attrNvme(s.percentage_used, s.media_errors);
    return t.hw.attrAta(s.reallocated, s.pending, s.offline_uncorrectable);
  }
  function lastTest(d: HwDisk): string {
    const st = d.smart?.self_test;
    if (!st) return '—';
    if (st.running) return t.hw.testRunning(st.remaining);
    if (!st.last) return t.hw.never;
    return `${st.last.type}: ${st.last.passed ? t.hw.testPassed : t.hw.testFailed}`;
  }
  async function rescan() {
    if (await act(post('/hardware/scan'), t.hw.rescanned)) setTimeout(load, 1500);
  }

  // ---- SMART drawer
  let detail = $state<HwDisk | null>(null);
  let detailOpen = $state(false);
  function openDetail(d: HwDisk) {
    detail = d;
    detailOpen = true;
  }
  // keep the open drawer in step with the polled status
  $effect(() => {
    if (hw && detail) {
      const fresh = hw.disks.find((d) => d.name === detail!.name);
      if (fresh && fresh !== detail) detail = fresh;
    }
  });
  async function selfTest(d: HwDisk, type: 'short' | 'long') {
    if (await act(post('/hardware/selftest', { disk: d.serial, type }), t.hw.testStarted)) setTimeout(load, 1500);
  }

  // ---- layout requests
  type OpKind = 'spare' | 'replace' | 'grow';
  let opOpen = $state(false);
  let opKind = $state<OpKind>('spare');
  let opArray = $state<HwArray | null>(null);
  let opDisk = $state('');
  let opFailed = $state('');
  let opConfirm = $state('');
  let sending = $state(false);
  const fitting = (a: HwArray | null) =>
    (hw?.disks ?? []).filter((d) => d.role === 'empty' && d.serial && (!a?.used_dev_size || d.size >= a.used_dev_size));
  const diskLabel = (d: HwDisk) => t.hw.diskOption(d.name, d.model ?? '?', d.serial ?? '?', fmtBytes(d.size));
  const managed = (a: HwArray) => a.role === 'data' || a.role === 'metadata';
  const growable = (a: HwArray) => (a.level === 'raid5' || a.level === 'raid6') && a.state === 'clean' && !a.degraded;
  function openOp(kind: OpKind, a: HwArray) {
    opKind = kind;
    opArray = a;
    opDisk = fitting(a)[0]?.serial ?? '';
    opFailed =
      kind === 'replace' ? (a.members.find((m) => m.state === 'faulty' || m.state === 'removed')?.serial ?? '') : '';
    opConfirm = '';
    opOpen = true;
  }
  const opConfirmOk = $derived(!!opDisk && opConfirm.trim() === opDisk);
  async function submitOp(e: Event) {
    e.preventDefault();
    if (!opArray || !opConfirmOk) return;
    sending = true;
    const body: Record<string, unknown> = { disk: opDisk, confirm: opConfirm.trim() };
    if (opKind === 'replace') body.failed = opFailed || null;
    const r = await act(post(`/hardware/arrays/${encodeURIComponent(opArray.name)}/${opKind}`, body), t.hw.requested);
    sending = false;
    if (r) {
      opOpen = false;
      load();
    }
  }

  // ---- create the data array
  const LEVELS = ['raid6', 'raid5', 'raid10', 'raid1'];
  let createOpen = $state(false);
  let level = $state('raid6');
  let picked: string[] = $state([]);
  let createConfirm = $state('');
  const hasData = $derived(!!hw?.arrays.some((a) => a.role === 'data'));
  const storeEmpty = $derived(hw?.store.empty === true);
  function openCreate() {
    level = 'raid6';
    picked = [];
    createConfirm = '';
    createOpen = true;
  }
  const pickedDisks = $derived((hw?.disks ?? []).filter((d) => d.serial && picked.includes(d.serial)));
  const minSize = $derived(pickedDisks.length ? Math.min(...pickedDisks.map((d) => d.size)) : 0);
  const capacity = $derived.by(() => {
    const n = pickedDisks.length;
    if (!n) return 0;
    if (level === 'raid1') return minSize;
    if (level === 'raid5') return (n - 1) * minSize;
    if (level === 'raid6') return (n - 2) * minSize;
    return Math.floor(n / 2) * minSize;
  });
  const levelProblem = $derived.by(() => {
    const min = t.hw.minDisks[level] ?? 2;
    if (pickedDisks.length < min) return t.hw.tooFew(level.toUpperCase(), min);
    if (level === 'raid10' && pickedDisks.length % 2) return t.hw.even;
    return null;
  });
  const typed = $derived(new Set(createConfirm.split(/[\s,]+/).filter(Boolean)));
  const createConfirmOk = $derived(typed.size === picked.length && picked.every((s) => typed.has(s)));
  async function submitCreate(e: Event) {
    e.preventDefault();
    if (levelProblem || !createConfirmOk || !storeEmpty) return;
    sending = true;
    const r = await act(
      post('/hardware/arrays', { role: 'data', level, disks: picked, confirm: createConfirm.trim() }),
      t.hw.requested,
    );
    sending = false;
    if (r) {
      createOpen = false;
      load();
    }
  }
</script>

<div class="page-head">
  <h1>{t.hw.title}</h1>
  {#if hw?.scanned}<span class="stamp" title={fmtTime(hw.scanned)}
      >{t.hw.scanned(fmtAgo(hw.scanned), fmtAgo(hw.smart_scanned))}</span
    >{/if}
  <p class="lede">{t.hw.lede}</p>
</div>
<ErrorBanner {error} />

{#if !hw}
  {#if !error}<p class="muted" aria-busy="true">{t.loading}</p>{/if}
{:else}
  {#if !hw.available}
    <p class="banner warn" role="status">{t.hw.unavailable}</p>
  {:else if hw.stale}
    <p class="banner warn" role="status">{t.hw.stale(fmtAgo(hw.scanned))}</p>
  {/if}
  {#if hw.available && !hw.tools.smartctl}<p class="banner warn" role="status">{t.hw.noSmartctl}</p>{/if}

  <section class="card" aria-labelledby="hw-disks-h">
    <div class="card-head">
      <div>
        <h2 id="hw-disks-h">{t.hw.disks}</h2>
        <div class="sub">
          <span class="chip {sumCls[hw.summary.state]}"
            >{hw.summary.state === 'ok'
              ? t.hw.summary.ok
              : hw.summary.state === 'unknown'
                ? t.hw.summary.unknown
                : [
                    hw.summary.critical ? t.hw.summary.critical(hw.summary.critical) : '',
                    hw.summary.warnings ? t.hw.summary.warning(hw.summary.warnings) : '',
                  ]
                    .filter(Boolean)
                    .join(' · ')}</span
          >
          {t.hw.summaryLine(hw.summary.disks, hw.summary.arrays)}
        </div>
      </div>
      {#if can.scanHardware(session.user)}
        <button
          type="button"
          onclick={rescan}
          disabled={busy && hw.ops.some((o) => o.op === 'scan' && o.state !== 'done')}
          ><IconRefresh aria-hidden="true" />{t.hw.rescan}</button
        >
      {/if}
    </div>
    {#if hw.disks.length === 0}
      <p class="empty">{t.none}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.hw.device}</th>
              <th scope="col">{t.hw.model}</th>
              <th scope="col">{t.hw.serial}</th>
              <th scope="col" class="num">{t.hw.size}</th>
              <th scope="col">{t.hw.role}</th>
              <th scope="col">{t.hw.health}</th>
              <th scope="col" class="num">{t.hw.temp}</th>
              <th scope="col">{t.hw.keyAttrs}</th>
              <th scope="col">{t.hw.selfTest}</th>
              <th scope="col"><span class="visually-hidden">{t.actions}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each hw.disks as d (d.name)}
              {@const h = health(d)}
              <tr use:rowClick={() => openDetail(d)}>
                <td class="nowrap"
                  ><span class="mono">{d.name}</span>
                  <div class="muted small">
                    {t.hw.types[d.type] ?? d.type}{d.transport ? ` · ${d.transport}` : ''}
                  </div></td
                >
                <td>{d.model ?? '—'}</td>
                <td class="mono">{d.serial ?? '—'}</td>
                <td class="num nowrap">{fmtBytes(d.size)}</td>
                <td>
                  <span class="chip {roleCls[d.role] ?? 'plain'}" title={t.hw.roleHints[d.role]}
                    >{t.hw.roles[d.role] ?? d.role}</span
                  >
                  {#if d.array}<div class="muted small mono">{d.array}</div>{/if}
                  {#if d.why}<div class="muted small">{d.why}</div>{/if}
                </td>
                <td><span class="chip {h.cls}">{h.text}</span></td>
                <td class="num nowrap">{d.smart?.temperature != null ? t.hw.celsius(d.smart.temperature) : '—'}</td>
                <td class="small nowrap">{keyAttrs(d)}</td>
                <td class="small">{lastTest(d)}</td>
                <td class="actions">
                  <button
                    type="button"
                    class="small"
                    onclick={() => openDetail(d)}
                    aria-label={t.hw.detailsLabel(d.name)}><IconInfo aria-hidden="true" />{t.hw.details}</button
                  >
                </td>
              </tr>
              {#if d.issues.length}
                <tr class="issues-row">
                  <td></td>
                  <td colspan="9">
                    <div class="issues">
                      {#each d.issues as i, n (n)}<span class="chip {sevCls[i.severity]}">{i.message}</span>{/each}
                    </div>
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <section class="card" aria-labelledby="hw-arrays-h">
    <div class="card-head">
      <div>
        <h2 id="hw-arrays-h">{t.hw.arrays}</h2>
        <div class="sub">{hw.store.array ? t.hw.storeOn(hw.store.array) : t.hw.storeRoot}</div>
      </div>
      {#if admin && hw.available && !hasData}
        <button type="button" class="primary" onclick={openCreate}
          ><IconPlus aria-hidden="true" />{t.hw.createData}</button
        >
      {/if}
    </div>
    {#if hw.arrays.length === 0}
      <p class="empty">{t.hw.noArrays}</p>
    {:else}
      <div class="arrays">
        {#each hw.arrays as a (a.name)}
          <article class="array" aria-labelledby="hw-a-{a.name}">
            <div class="array-head">
              <h3 id="hw-a-{a.name}">
                <span class="mono">{a.name}</span>{#if a.md_name}<span class="muted">&nbsp;· {a.md_name}</span>{/if}
              </h3>
              <span class="chip plain">{(a.level ?? '?').toUpperCase()}</span>
              {#if a.role}<span class="chip {roleCls[a.role] ?? 'plain'}">{t.hw.roles[a.role] ?? a.role}</span>{/if}
              <span class="chip {stateCls[a.state] ?? 'plain'}" title={a.state_detail ?? undefined}
                >{t.hw.states[a.state] ?? a.state}</span
              >
              <span class="muted small"
                >{t.hw.devices(a.active_devices, a.raid_devices)}{a.size ? ` · ${fmtBytes(a.size)}` : ''}</span
              >
            </div>
            {#if a.action && a.progress !== null}
              <div class="progress-line">
                <div
                  class="bar"
                  role="progressbar"
                  aria-valuemin="0"
                  aria-valuemax="100"
                  aria-valuenow={Math.round(a.progress)}
                  aria-label={t.hw.actions[a.action] ?? a.action}
                >
                  <span style:width="{Math.max(0, Math.min(100, a.progress))}%"></span>
                </div>
                <span class="small nowrap"
                  >{t.hw.progress(t.hw.actions[a.action] ?? a.action, a.progress, a.finish_minutes)}</span
                >
              </div>
            {/if}
            <dl class="kv">
              <dt>{t.hw.members}</dt>
              <dd class="members">
                {#each a.members as m, i (i)}
                  <span class="chip {memberCls[m.state] ?? 'plain'}" title={m.serial ?? undefined}
                    ><span class="mono">{m.dev ?? '—'}</span>&nbsp;{t.hw.memberStates[m.state] ?? m.state}</span
                  >
                {/each}
              </dd>
              {#if a.mounts.length}<dt>{t.hw.mount}</dt>
                <dd class="mono">{a.mounts.join(', ')}</dd>{/if}
              {#if a.fs}
                <dt>{t.hw.fs}</dt>
                <dd>
                  {a.fs.type}{a.fs.size ? ` · ${t.hw.fsUsage(fmtBytes(a.fs.used ?? 0), fmtBytes(a.fs.size))}` : ''}
                </dd>
              {/if}
            </dl>
            {#if a.issues.length}
              <div class="issues">
                {#each a.issues as i, n (n)}<span class="chip {sevCls[i.severity]}">{i.message}</span>{/each}
              </div>
            {/if}
            {#if managed(a) && admin}
              <div class="form-actions start">
                <button type="button" onclick={() => openOp('replace', a)}>{t.hw.replace}</button>
                <button type="button" onclick={() => openOp('spare', a)}>{t.hw.addSpare}</button>
                <button type="button" onclick={() => openOp('grow', a)} disabled={!growable(a)} title={t.hw.growHint}
                  >{t.hw.grow}</button
                >
              </div>
            {:else if a.role === 'system'}
              <p class="muted small">{t.hw.systemArray}</p>
            {/if}
          </article>
        {/each}
      </div>
    {/if}
    <p class="muted small">{t.hw.metadataNote}</p>
  </section>

  <section class="card" aria-labelledby="hw-ops-h">
    <div class="card-head"><h2 id="hw-ops-h">{t.hw.ops}</h2></div>
    {#if hw.ops.length === 0}
      <p class="empty">{t.hw.noOps}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t.hw.op}</th>
              <th scope="col">{t.state}</th>
              <th scope="col">{t.hw.by}</th>
              <th scope="col">{t.time}</th>
              <th scope="col">{t.hw.result}</th>
            </tr>
          </thead>
          <tbody>
            {#each hw.ops as o (o.id)}
              <tr>
                <td class="nowrap">{t.hw.opNames[o.op] ?? o.op}</td>
                <td><span class="chip {opCls[o.state] ?? 'plain'}">{t.hw.opStates[o.state] ?? o.state}</span></td>
                <td class="nowrap"
                  >{o.by}{#if o.quorum_id}<div class="muted small">{t.hw.quorumRef(o.quorum_id)}</div>{/if}</td
                >
                <td class="nowrap" title={fmtTime(o.finished ?? o.created)}>{fmtAgo(o.finished ?? o.created)}</td>
                <td class="detail">{o.error ?? o.detail ?? '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{/if}

<Modal bind:open={detailOpen} title={detail ? t.hw.smartTitle(detail.name, detail.model ?? '?') : ''} wide>
  {#if detail}
    {@const s = detail.smart}
    {@const h = health(detail)}
    <dl class="kv">
      <dt>{t.hw.serial}</dt>
      <dd class="mono">{detail.serial ?? '—'}</dd>
      <dt>{t.hw.fields.path}</dt>
      <dd class="mono">{detail.path}</dd>
      <dt>{t.hw.size}</dt>
      <dd>
        {fmtBytes(detail.size)} · {t.hw.types[detail.type] ?? detail.type}{detail.transport
          ? ` · ${detail.transport}`
          : ''}
      </dd>
      {#if detail.wwn}<dt>{t.hw.fields.wwn}</dt>
        <dd class="mono">{detail.wwn}</dd>{/if}
      <dt>{t.hw.role}</dt>
      <dd>
        {t.hw.roles[detail.role] ?? detail.role}{detail.array ? ` · ${detail.array}` : ''}{detail.why
          ? ` · ${detail.why}`
          : ''}
      </dd>
      <dt>{t.hw.fields.health}</dt>
      <dd><span class="chip {h.cls}">{h.text}</span></dd>
      {#if s?.available}
        {#each ['temperature', 'power_on_hours', 'reallocated', 'pending', 'offline_uncorrectable', 'percentage_used', 'media_errors', 'critical_warning', 'available_spare'] as k (k)}
          {@const v = (s as unknown as Record<string, number | null>)[k]}
          {#if v !== null && v !== undefined}
            <dt>{t.hw.fields[k]}</dt>
            <dd>
              {k === 'temperature'
                ? t.hw.celsius(v)
                : k === 'power_on_hours'
                  ? t.hw.hours(v)
                  : k === 'percentage_used' || k === 'available_spare'
                    ? `${v} %`
                    : v}
            </dd>
          {/if}
        {/each}
        <dt>{t.hw.fields.checked}</dt>
        <dd title={fmtTime(s.checked)}>{fmtAgo(s.checked)}</dd>
      {/if}
    </dl>
    {#if s?.error}<p class="banner warn" role="status">{s.error}</p>{/if}
    {#if detail.issues.length}
      <h3>{t.hw.issues}</h3>
      <div class="issues">
        {#each detail.issues as i, n (n)}<span class="chip {sevCls[i.severity]}">{i.message}</span>{/each}
      </div>
    {/if}
    <h3>{t.hw.selfTests}</h3>
    <p class="muted small">
      {s?.self_test ? lastTest(detail) : t.hw.noSelfTest}{#if s?.self_test?.last?.hours != null}
        · {s.self_test.last.status} ({s.self_test.last.hours} h){/if}
    </p>
    {#if admin}
      <p class="muted small">{t.hw.selfTestHint}</p>
      <div class="form-actions start">
        <button
          type="button"
          onclick={() => selfTest(detail!, 'short')}
          disabled={!s?.available || !!s?.self_test?.running || !detail.serial}>{t.hw.runShort}</button
        >
        <button
          type="button"
          onclick={() => selfTest(detail!, 'long')}
          disabled={!s?.available || !!s?.self_test?.running || !detail.serial}>{t.hw.runLong}</button
        >
      </div>
    {/if}
    {#if s?.available}
      <h3>{t.hw.attributes}</h3>
      {#if s.attributes.length === 0}
        <p class="empty">{t.hw.noAttributes}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                {#if detail.type !== 'nvme'}<th scope="col" class="num">{t.hw.attrId}</th>{/if}
                <th scope="col">{t.hw.attrName}</th>
                {#if detail.type !== 'nvme'}
                  <th scope="col" class="num">{t.hw.attrValue}</th>
                  <th scope="col" class="num">{t.hw.attrWorst}</th>
                  <th scope="col" class="num">{t.hw.attrThresh}</th>
                {/if}
                <th scope="col" class="num">{t.hw.attrRaw}</th>
              </tr>
            </thead>
            <tbody>
              {#each s.attributes as a, n (n)}
                <tr>
                  {#if detail.type !== 'nvme'}<td class="num">{a.id ?? ''}</td>{/if}
                  <td class="mono"
                    >{a.name}{#if a.failing}&nbsp;<span class="chip bad">{t.hw.attrFailing}</span>{/if}</td
                  >
                  {#if detail.type !== 'nvme'}
                    <td class="num">{a.value ?? ''}</td>
                    <td class="num">{a.worst ?? ''}</td>
                    <td class="num">{a.thresh ?? ''}</td>
                  {/if}
                  <td class="num mono">{a.raw}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {/if}
  {/if}
</Modal>

<Modal bind:open={opOpen} title={opArray ? t.hw.opTitles[opKind](opArray.name) : ''} wide>
  {#if opArray}
    {@const disks = fitting(opArray)}
    <form onsubmit={submitOp}>
      <p class="muted">{t.hw.opIntro[opKind]}</p>
      {#if opKind === 'replace'}
        <div class="field">
          <label for="hw-old">{t.hw.oldMember}</label>
          <select id="hw-old" bind:value={opFailed}>
            <option value="">{t.hw.anyFailed}</option>
            {#each opArray.members.filter((m) => m.serial && m.state !== 'spare') as m (m.serial)}
              <option value={m.serial}
                >{t.hw.memberOption(m.dev ?? '?', m.serial ?? '?', t.hw.memberStates[m.state] ?? m.state)}</option
              >
            {/each}
          </select>
        </div>
      {/if}
      <div class="field">
        <label for="hw-new">{t.hw.newDisk}</label>
        {#if disks.length === 0}
          <p class="banner warn" role="status">{t.hw.noEmpty}</p>
        {:else}
          <select id="hw-new" bind:value={opDisk} required>
            {#each disks as d (d.serial)}<option value={d.serial}>{diskLabel(d)}</option>{/each}
          </select>
        {/if}
      </div>
      <p class="banner warn" role="note">{t.hw.overwrite}</p>
      <div class="field">
        <label for="hw-confirm">{t.hw.confirmOne}</label>
        <input
          id="hw-confirm"
          class="mono"
          bind:value={opConfirm}
          autocomplete="off"
          spellcheck="false"
          placeholder={opDisk}
          aria-invalid={opConfirm !== '' && !opConfirmOk}
        />
        {#if opConfirm !== '' && !opConfirmOk}<div class="hint bad">{t.hw.confirmMismatch}</div>{/if}
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (opOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={!opConfirmOk || sending}>{t.hw.request}</button>
      </div>
    </form>
  {/if}
</Modal>

<Modal bind:open={createOpen} title={t.hw.createTitle} wide>
  {#if hw}
    <form onsubmit={submitCreate}>
      <p class="muted">{t.hw.createIntro}</p>
      {#if !storeEmpty}<p class="banner error" role="alert">{t.hw.storeNotEmpty}</p>{/if}
      <div class="field">
        <label for="hw-level">{t.hw.level}</label>
        <select id="hw-level" bind:value={level}>
          {#each LEVELS as l (l)}<option value={l}>{t.hw.levelHints[l]}</option>{/each}
        </select>
      </div>
      <fieldset class="disk-pick">
        <legend>{t.hw.selectDisks}</legend>
        {#each hw.disks as d (d.name)}
          <label class:disabled={d.role !== 'empty' || !d.serial}>
            <input type="checkbox" value={d.serial} bind:group={picked} disabled={d.role !== 'empty' || !d.serial} />
            <span>{diskLabel(d)}</span>
            {#if d.role !== 'empty'}<span class="muted small"
                >— {t.hw.unusable(t.hw.roles[d.role] ?? d.role, d.why)}</span
              >{/if}
          </label>
        {/each}
      </fieldset>
      {#if picked.length}
        <p class="muted">{levelProblem ?? t.hw.capacity(fmtBytes(capacity))}</p>
      {/if}
      <p class="banner warn" role="note">{t.hw.overwrite}</p>
      <div class="field">
        <label for="hw-cconfirm">{t.hw.confirmMany}</label>
        <input
          id="hw-cconfirm"
          class="mono"
          bind:value={createConfirm}
          autocomplete="off"
          spellcheck="false"
          aria-invalid={createConfirm !== '' && !createConfirmOk}
        />
        {#if createConfirm !== '' && !createConfirmOk}<div class="hint bad">{t.hw.confirmMismatch}</div>{/if}
      </div>
      <div class="form-actions">
        <button type="button" onclick={() => (createOpen = false)}>{t.cancel}</button>
        <button type="submit" class="primary" disabled={!!levelProblem || !createConfirmOk || !storeEmpty || sending}
          >{t.hw.request}</button
        >
      </div>
    </form>
  {/if}
</Modal>

<style>
  .issues-row td {
    padding-top: 0;
    border-top: none;
  }
  .issues,
  .members {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
  }
  .arrays {
    display: grid;
    gap: 1rem;
  }
  .array {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.85rem 1rem;
  }
  .array-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }
  .array-head h3 {
    margin: 0;
    font-size: 1rem;
  }
  .progress-line {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 0.25rem 0 0.75rem;
  }
  .bar {
    flex: 1;
    max-width: 28rem;
    height: 0.5rem;
    border-radius: 999px;
    background: var(--border);
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 0.4s ease;
  }
  .form-actions.start {
    justify-content: flex-start;
  }
  .detail {
    min-width: 16rem;
  }
  .disk-pick {
    display: grid;
    gap: 0.35rem;
    margin: 0 0 0.75rem;
  }
  .disk-pick label {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
  }
  .disk-pick label.disabled {
    opacity: 0.6;
  }
  h3 {
    margin-top: 1.1rem;
  }
  @media (prefers-reduced-motion: reduce) {
    .bar span {
      transition: none;
    }
  }
</style>
