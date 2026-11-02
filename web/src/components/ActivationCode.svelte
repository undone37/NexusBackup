<script lang="ts">
  import { fmtTime } from '../lib/format';
  import { t } from '../lib/i18n';
  import type { Activation } from '../lib/types';
  import Modal from './Modal.svelte';
  import CopyField from './CopyField.svelte';

  // One-time activation code (or one half of it). Shown once; the server keeps only a hash.
  let {
    open = $bindable(false),
    name,
    activation,
  }: { open?: boolean; name: string; activation: Activation | null } = $props();

  const link = $derived(activation ? location.origin + activation.path : '');
  const label = $derived(
    activation && activation.parts > 1
      ? t.users.activationPartLabel(activation.part, activation.parts)
      : t.users.activationCode,
  );
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
    <CopyField value={activation.code} {label} secret />
    <CopyField value={link} label={t.users.activationLink} secret />
    {#if activation.expires}
      <p class="muted">{t.users.pendingUntil(fmtTime(activation.expires))}</p>
    {/if}
    <div class="form-actions">
      <button type="button" class="primary" onclick={() => (open = false)}>{t.close}</button>
    </div>
  {/if}
</Modal>
