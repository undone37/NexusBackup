<script lang="ts">
  import { t } from '../lib/i18n';

  let { state }: { state: string } = $props();
  const cls: Record<string, string> = { ok: 'ok', failed: 'bad', running: 'info', queued: '', cancelled: 'warn' };
</script>

<span class="chip {cls[state] ?? ''}">{t.jobs.states[state] ?? state}</span>
