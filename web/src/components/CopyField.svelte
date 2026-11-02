<script lang="ts">
  // A value to paste elsewhere (token, install command, key, link) with a copy button. `secret`: shown once,
  // the frame is amber so it reads as "copy this now".
  import { copyText } from '../lib/clipboard';
  import { t } from '../lib/i18n';
  import IconCopy from '@lucide/svelte/icons/copy';
  import IconCheck from '@lucide/svelte/icons/check';

  let { value, label = '', secret = false }: { value: string; label?: string; secret?: boolean } = $props();
  const id = $props.id();
  let done = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  async function copy() {
    await copyText(value);
    done = true;
    clearTimeout(timer);
    timer = setTimeout(() => (done = false), 1600);
  }
</script>

<div class="cf">
  {#if label}<span class="cf-label" id="{id}-l">{label}</span>{/if}
  <div class="cf-box" class:once={secret}>
    <code aria-labelledby={label ? `${id}-l` : undefined}>{value}</code>
    <button
      type="button"
      class="icon cf-btn"
      aria-label={label ? t.ux.copyWhat(label) : t.ux.copy}
      title={t.ux.copy}
      onclick={copy}
    >
      {#if done}<IconCheck aria-hidden="true" />{:else}<IconCopy aria-hidden="true" />{/if}
    </button>
  </div>
</div>

<style>
  .cf {
    display: grid;
    gap: 0.2rem;
    min-width: 0;
    margin-bottom: 0.6rem;
  }
  .cf-label {
    font-size: 0.8rem;
    color: var(--muted);
  }
  .cf-box {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    min-width: 0;
    padding: 0.25rem 0.25rem 0.25rem 0.6rem;
    border-radius: var(--radius-s);
    background: var(--surface-2);
    box-shadow: inset 0 0 0 1px var(--border);
  }
  .cf-box.once {
    box-shadow: inset 0 0 0 1px var(--c-warn);
  }
  code {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
    font-family: var(--mono);
    font-size: 0.82rem;
  }
  .cf-btn {
    flex: none;
    width: 28px;
    height: 28px;
    min-height: 28px;
  }
</style>
