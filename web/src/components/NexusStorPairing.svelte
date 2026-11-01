<script lang="ts">
  // Source form part for `plugin:nexusstor` (docs/nexusstor-design.md): the pairing token from NexusStor
  // (previewed here, decoded again by the server) and the name NexusStor shows for this NexusBackup.
  import { t } from '../lib/i18n';
  import { decodeToken, groupHex } from '../lib/nexusstor';
  import { fmtTime } from '../lib/format';
  import type { NexusStorConfig } from '../lib/types';

  let {
    token = $bindable(''),
    appliance = $bindable(''),
    stored = null,
    error = '',
  }: { token: string; appliance: string; stored?: NexusStorConfig | null; error?: string } = $props();

  const decoded = $derived(token.trim() ? decodeToken(token) : null);
  const expired = $derived(!!decoded && decoded.expires * 1000 <= Date.now());
  const desc = $derived(error || (token.trim() && !decoded) ? 'nst-token-err' : 'nst-token-hint');
</script>

<fieldset class="field">
  <legend>{t.nexusstor.pairing}</legend>
  <ol class="hint">
    {#each t.nexusstor.steps as s, i (i)}<li>{s}</li>{/each}
  </ol>
  {#if stored?.host}
    <dl class="kv-list">
      <dt>{t.nexusstor.pairedWith}</dt>
      <dd><code>{stored.host}:{stored.port ?? 8443}</code></dd>
      <dt>{t.nexusstor.fingerprint}</dt>
      <dd><code>{groupHex(stored.fingerprint ?? '')}</code></dd>
    </dl>
  {/if}
  <div class="field">
    <label for="nst-token">{stored?.host ? t.nexusstor.newToken : t.nexusstor.token}</label>
    <textarea
      id="nst-token"
      bind:value={token}
      required={!stored?.host}
      rows="3"
      spellcheck="false"
      autocomplete="off"
      placeholder="nst1.…"
      aria-invalid={!!error || (!!token.trim() && !decoded)}
      aria-describedby={desc}></textarea>
    {#if error}<div class="hint bad" id="nst-token-err">{error}</div>
    {:else if token.trim() && !decoded}<div class="hint bad" id="nst-token-err">{t.nexusstor.notAToken}</div>
    {:else}<div class="hint" id="nst-token-hint">
        {stored?.host ? t.nexusstor.newTokenHint : t.nexusstor.tokenHint}
      </div>{/if}
  </div>
  {#if decoded}
    <dl class="kv-list" aria-live="polite">
      <dt>{t.nexusstor.address}</dt>
      <dd><code>{decoded.host}:{decoded.port}</code></dd>
      <dt>{t.nexusstor.fingerprint}</dt>
      <dd><code>{groupHex(decoded.fingerprint)}</code></dd>
      <dt>{t.nexusstor.expires}</dt>
      <dd>
        {fmtTime(decoded.expires)}{#if expired}&nbsp;<span class="hint bad">{t.nexusstor.expired}</span>{/if}
      </dd>
    </dl>
    <p class="hint">{t.nexusstor.compare}</p>
  {/if}
  <div class="field">
    <label for="nst-name">{t.nexusstor.appliance}</label>
    <input id="nst-name" bind:value={appliance} maxlength="64" aria-describedby="nst-name-hint" />
    <div class="hint" id="nst-name-hint">{t.nexusstor.applianceHint}</div>
  </div>
</fieldset>
