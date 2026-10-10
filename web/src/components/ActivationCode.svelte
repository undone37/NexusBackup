<script lang="ts">
  import { notify } from '../lib/notify.svelte';
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Activation } from '../lib/types';
  import Modal from './Modal.svelte';

  // One-time activation code (or one half of it). Shown once; the server keeps only a hash.
  let { open = $bindable(false), name, activation }: { open?: boolean; name: string; activation: Activation | null } =
    $props();

  const link = $derived(activation ? location.origin + activation.path : '');
  const label = $derived(
    activation && activation.parts > 1 ? t.users.activationPartLabel(activation.part, activation.parts) : t.users.activationCode,
  );

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      notify('ok', t.users.copied);
    } catch {
      /* clipboard unavailable (non-secure context): the text is selectable */
    }
  }
</script>

<Modal bind:open title={t.users.activationTitle(name)}>
  {#if activation}
    {#if activation.parts > 1 && activation.part === 1}
      <p class="banner pending">{t.users.activationPart1}</p>
    {:else if activation.parts > 1}
      <p class="banner pending">{t.users.activationPart2}</p>
    {:else}
      <p>{t.users.activationHand}</p>
    {/if}
    <p class="muted">{t.users.activationOnce}</p>
    <div class="field">
      <span class="muted">{label}</span>
      <code class="secret">{activation.code}</code>
      <button type="button" class="small" onclick={() => copy(activation!.code)}>{t.users.copy}</button>
    </div>
    <div class="field">
      <span class="muted">{t.users.activationLink}</span>
      <code class="secret">{link}</code>
      <button type="button" class="small" onclick={() => copy(link)}>{t.users.copy}</button>
    </div>
    {#if activation.expires}
      <p class="muted">{t.users.pendingUntil(fmtTime(activation.expires))}</p>
    {/if}
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (open = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>
