<script lang="ts">
  import { t } from '../lib/i18n';
  import type { ChecksForm } from '../lib/rtest';

  // Restore-test checks (Phase 25): boot timeout for everyone; guest agent, ports and a
  // custom command for VMs only (containers have no guest agent).
  let { value = $bindable(), ct = false, id }: { value: ChecksForm; ct?: boolean; id: string } = $props();
</script>

<div class="form-grid">
  <div class="field">
    <label for="{id}-boot">{t.rtest.bootTimeout}</label>
    <input
      id="{id}-boot"
      type="number"
      min="30"
      max="3600"
      placeholder="600"
      bind:value={value.boot}
      aria-describedby="{id}-boot-hint"
    />
    <div class="hint" id="{id}-boot-hint">{t.rtest.bootTimeoutHint}</div>
  </div>
  {#if !ct}
    <div class="field">
      <label for="{id}-ports">{t.rtest.ports}</label>
      <input
        id="{id}-ports"
        bind:value={value.ports}
        placeholder="22, 443"
        disabled={!value.agent}
        aria-describedby="{id}-ports-hint"
      />
      <div class="hint" id="{id}-ports-hint">{t.rtest.portsHint}</div>
    </div>
    <div class="field">
      <label for="{id}-cmd">{t.rtest.command}</label>
      <input
        id="{id}-cmd"
        class="mono"
        bind:value={value.command}
        spellcheck="false"
        disabled={!value.agent}
        aria-describedby="{id}-cmd-hint"
      />
      <div class="hint" id="{id}-cmd-hint">{t.rtest.commandHint}</div>
    </div>
    <div class="field">
      <label for="{id}-exit">{t.rtest.expectExit}</label>
      <input
        id="{id}-exit"
        type="number"
        min="-1"
        max="255"
        bind:value={value.expect}
        disabled={!value.agent || !value.command.trim()}
      />
    </div>
  {/if}
</div>
{#if ct}
  <p class="hint">{t.rtest.ctHint}</p>
{:else}
  <label class="inline-check"><input type="checkbox" bind:checked={value.agent} />{t.rtest.agent}</label>
{/if}
