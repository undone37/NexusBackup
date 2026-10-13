<script lang="ts">
  // "New tenant" onboarding (Phase 23a): tenant + soft quota + policy tier + first tenant admin
  // (activation code) + optional offsite target, as the existing calls one after the other:
  // POST /tenants, PUT …/quota, PUT …/policies (policies of the tier; one from the tier template
  // if none exists), POST /users. Each step reports its own result; a failed step stops the rest.
  import { get, post, put, errText } from '../lib/api';
  import { notify } from '../lib/notify.svelte';
  import { t } from '../lib/i18n';
  import type { Activation, Policy, SftpRemote, S3Remote, TenantOffsite, Tier } from '../lib/types';
  import Modal from './Modal.svelte';
  import ActivationCode from './ActivationCode.svelte';

  let { open = $bindable(false), ondone }: { open?: boolean; ondone: () => void } = $props();

  const id = $props.id();
  const GIB = 2 ** 30;
  const STEPS = $derived([t.sp.wiz.stepTenant, t.sp.wiz.stepPlan, t.sp.wiz.stepAdmin, t.sp.wiz.stepOffsite, t.sp.wiz.stepReview]);
  let step = $state(1);
  let f = $state({
    name: '',
    quota: null as number | null,
    tier: 'silver' as Tier | '',
    admin: '',
    kind: 'none' as 'none' | 'sftp' | 's3',
    sftp: { host: '', port: 23, user: '', key_file: '', host_key: '' },
    s3: { endpoint: '', region: '', bucket: '', access_key: '', secret_key: '', lock: true },
  });
  type Done = { label: string; ok: boolean | null; detail?: string };
  let log: Done[] = $state([]);
  let running = $state(false);
  let activation: Activation | null = $state(null);
  let codeOpen = $state(false);

  $effect(() => {
    if (open) {
      step = 1;
      log = [];
      activation = null;
      f = {
        name: '',
        quota: null,
        tier: 'silver',
        admin: '',
        kind: 'none',
        sftp: { host: '', port: 23, user: '', key_file: '', host_key: '' },
        s3: { endpoint: '', region: '', bucket: '', access_key: '', secret_key: '', lock: true },
      };
    }
  });

  function offsite(): TenantOffsite {
    if (f.kind === 'sftp') {
      const r: SftpRemote = { type: 'sftp', ...f.sftp, host: f.sftp.host.trim(), user: f.sftp.user.trim(), port: Number(f.sftp.port) || 23 };
      return { remote: r, uploaders: 4 };
    }
    if (f.kind === 's3') {
      const r: S3Remote = { type: 's3', ...f.s3, endpoint: f.s3.endpoint.trim(), bucket: f.s3.bucket.trim(), path_style: false };
      return { remote: r, uploaders: 4 };
    }
    return {};
  }

  function next(e: SubmitEvent) {
    e.preventDefault();
    if (step < STEPS.length) step += 1;
    else create();
  }

  async function stepRun(label: string, fn: () => Promise<string | undefined>): Promise<boolean> {
    const row: Done = { label, ok: null };
    log.push(row);
    const i = log.length - 1;
    try {
      log[i].detail = await fn();
      log[i].ok = true;
      return true;
    } catch (e) {
      log[i] = { ...log[i], ok: false, detail: errText(e) };
      return false;
    }
  }

  async function create() {
    running = true;
    log = [];
    const name = f.name.trim();
    const path = `/tenants/${encodeURIComponent(name)}`;
    let ok = await stepRun(t.sp.wiz.doTenant(name), async () => {
      await post('/tenants', { name, offsite: offsite() });
      return f.kind === 'none' ? undefined : t.sp.wiz.withOffsite;
    });
    if (ok && f.quota) ok = await stepRun(t.sp.wiz.doQuota, async () => void (await put(`${path}/quota`, { quota_bytes: Math.round(f.quota! * GIB) })));
    if (ok && f.tier) {
      ok = await stepRun(t.sp.wiz.doTier(t.tiers.names[f.tier]), async () => {
        let ids = (await get<Policy[]>('/policies')).filter((p) => p.tier === f.tier).map((p) => p.id);
        if (!ids.length) ids = [((await post<Policy>('/policies/templates', { tier: f.tier })).data as Policy).id];
        await put(`${path}/policies`, { policy_ids: ids });
        return t.sp.wiz.assignedN(ids.length);
      });
    }
    if (ok && f.admin.trim()) {
      ok = await stepRun(t.sp.wiz.doAdmin(f.admin.trim()), async () => {
        const r = await post<{ activation?: Activation }>('/users', { name: f.admin.trim(), role: 'tenant_admin', tenant: name });
        activation = r.data.activation ?? null;
        return r.quorum ? t.quorumPending(r.quorumId) : undefined;
      });
    }
    running = false;
    if (ok) notify('ok', t.sp.wiz.done(name));
    if (activation) codeOpen = true;
    ondone();
  }
</script>

<Modal bind:open wide title={t.sp.wiz.title}>
  <ol class="steps">
    {#each STEPS as s, i (s)}<li aria-current={step === i + 1 ? 'step' : undefined}>{s}</li>{/each}
  </ol>
  <form onsubmit={next}>
    {#if step === 1}
      <div class="field">
        <label for="{id}-name">{t.name}</label>
        <input id="{id}-name" bind:value={f.name} required pattern="[a-z0-9][a-z0-9-]{'{0,62}'}" autocomplete="off" aria-describedby="{id}-name-hint" />
        <div class="hint" id="{id}-name-hint">{t.sp.wiz.nameHint}</div>
      </div>
    {:else if step === 2}
      <div class="field">
        <label for="{id}-quota">{t.storage.quotaField}</label>
        <input id="{id}-quota" class="narrow" type="number" min="0" step="any" bind:value={f.quota} aria-describedby="{id}-quota-hint" />
        <div class="hint" id="{id}-quota-hint">{t.storage.quotaHint}</div>
      </div>
      <fieldset class="field">
        <legend>{t.sp.wiz.tier}</legend>
        {#each ['bronze', 'silver', 'gold'] as Tier[] as tier (tier)}
          <label class="inline-check"><input type="radio" name="{id}-tier" value={tier} bind:group={f.tier} />{t.tiers.names[tier]}</label>
        {/each}
        <label class="inline-check"><input type="radio" name="{id}-tier" value="" bind:group={f.tier} />{t.sp.wiz.noTier}</label>
        <p class="hint">{t.sp.wiz.tierHint}</p>
      </fieldset>
    {:else if step === 3}
      <div class="field">
        <label for="{id}-admin">{t.sp.wiz.admin}</label>
        <input id="{id}-admin" bind:value={f.admin} autocomplete="off" aria-describedby="{id}-admin-hint" />
        <div class="hint" id="{id}-admin-hint">{t.sp.wiz.adminHint}</div>
      </div>
    {:else if step === 4}
      <fieldset class="field">
        <legend>{t.tenants.target}</legend>
        {#each ['none', 'sftp', 's3'] as k (k)}
          <label class="inline-check"><input type="radio" name="{id}-kind" value={k} bind:group={f.kind} />{t.tenants.targets[k]}</label>
        {/each}
      </fieldset>
      {#if f.kind === 'sftp'}
        <div class="form-grid">
          <div class="field"><label for="{id}-h">{t.tenants.host}</label><input id="{id}-h" bind:value={f.sftp.host} required /></div>
          <div class="field"><label for="{id}-p">{t.tenants.port}</label><input id="{id}-p" type="number" class="narrow" bind:value={f.sftp.port} /></div>
          <div class="field"><label for="{id}-u">{t.tenants.user}</label><input id="{id}-u" bind:value={f.sftp.user} required /></div>
          <div class="field">
            <label for="{id}-k">{t.tenants.keyFile}</label><input id="{id}-k" class="mono" bind:value={f.sftp.key_file} required />
          </div>
        </div>
        <div class="field"><label for="{id}-hk">{t.tenants.hostKey}</label><input id="{id}-hk" class="mono" bind:value={f.sftp.host_key} required /></div>
      {:else if f.kind === 's3'}
        <div class="form-grid">
          <div class="field"><label for="{id}-e">{t.tenants.endpoint}</label><input id="{id}-e" type="url" bind:value={f.s3.endpoint} required /></div>
          <div class="field"><label for="{id}-r">{t.tenants.region}</label><input id="{id}-r" bind:value={f.s3.region} required /></div>
          <div class="field"><label for="{id}-b">{t.tenants.bucket}</label><input id="{id}-b" bind:value={f.s3.bucket} required /></div>
          <div class="field"><label for="{id}-a">{t.tenants.accessKey}</label><input id="{id}-a" bind:value={f.s3.access_key} required /></div>
          <div class="field">
            <label for="{id}-s">{t.tenants.secretKey}</label><input id="{id}-s" type="password" bind:value={f.s3.secret_key} required autocomplete="new-password" />
          </div>
        </div>
        <label class="inline-check"><input type="checkbox" bind:checked={f.s3.lock} />{t.tenants.lock}</label>
      {/if}
      <p class="hint">{t.sp.wiz.offsiteHint}</p>
    {:else}
      <dl class="review">
        <dt>{t.name}</dt><dd><strong>{f.name}</strong></dd>
        <dt>{t.storage.quota}</dt><dd>{f.quota ? `${f.quota} GiB` : t.storage.noQuota}</dd>
        <dt>{t.sp.wiz.tier}</dt><dd>{f.tier ? t.tiers.names[f.tier] : t.sp.wiz.noTier}</dd>
        <dt>{t.sp.wiz.admin}</dt><dd>{f.admin.trim() || '—'}</dd>
        <dt>{t.tenants.target}</dt><dd>{t.tenants.targets[f.kind]}</dd>
      </dl>
      {#if log.length}
        <ul class="wiz-log" aria-live="polite">
          {#each log as l, i (i)}
            <li>
              <span class="chip {l.ok === null ? 'plain' : l.ok ? 'ok' : 'bad'}">{l.ok === null ? '…' : l.ok ? t.sp.wiz.ok : t.sp.wiz.failed}</span>
              {l.label}{#if l.detail}<span class="muted"> — {l.detail}</span>{/if}
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
    <div class="form-actions">
      {#if step > 1 && !log.length}<button type="button" onclick={() => (step -= 1)}>{t.sp.wiz.back}</button>{/if}
      {#if log.length && !running}
        <button type="button" class="primary" onclick={() => (open = false)}>{t.close}</button>
      {:else}
        <button type="submit" class="primary" disabled={running}>{step < STEPS.length ? t.sp.wiz.next : t.sp.wiz.create}</button>
      {/if}
    </div>
  </form>
</Modal>

<ActivationCode bind:open={codeOpen} name={f.admin.trim()} {activation} />

<style>
  .review {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
  }
  .review dt {
    color: var(--muted);
  }
  .review dd {
    margin: 0;
  }
  .wiz-log {
    list-style: none;
    padding: 0;
    display: grid;
    gap: 0.35rem;
  }
</style>
