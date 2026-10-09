<script lang="ts">
  import { t } from '../lib/i18n';

  let { on, title = '' }: { on: unknown; title?: string } = $props();
</script>

<span class="check" class:yes={!!on} class:no={!on} title={title || undefined}>
  <span aria-hidden="true">{on ? '✓' : '–'}</span>
  <span class="visually-hidden">{on ? t.yes : t.no}</span>
</span>
