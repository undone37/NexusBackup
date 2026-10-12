<script lang="ts">
  import { t } from '../lib/i18n';

  let { level }: { level: string | null | undefined } = $props();
  const l = $derived(level ?? 'unknown');
  const cls = $derived({ application: 'ok', crash: 'info', inconsistent: 'warn' }[l] ?? 'plain');
</script>

<span class="chip {cls}" title={t.cons.hints[l] ?? ''}>{t.cons.levels[l] ?? l}</span>
