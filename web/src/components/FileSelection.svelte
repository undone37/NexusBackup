<!-- Include roots + regex excludes of an agent or share source (Phase 15e). -->
<script lang="ts">
  import { t } from '../lib/i18n';

  let {
    include = $bindable(''),
    regex = $bindable(''),
    share = false,
  }: { include: string; regex: string; share: boolean } = $props();
  const id = $derived(share ? 'n' : 's');
</script>

<div class="field">
  <label for="{id}-incl">{share ? t.sources.includeShare : t.sources.include}</label>
  <textarea
    id="{id}-incl"
    bind:value={include}
    spellcheck="false"
    placeholder={share ? '/projects/a' : '/home\n/etc'}
    aria-describedby="{id}-incl-hint"></textarea>
  <div class="hint" id="{id}-incl-hint">{share ? t.sources.includeShareHint : t.sources.includeHint}</div>
</div>
<div class="field">
  <label for="{id}-rx">{t.sources.regex}</label>
  <textarea
    id="{id}-rx"
    bind:value={regex}
    spellcheck="false"
    placeholder={'\\.bak$\n/cache(/|$)'}
    aria-describedby="{id}-rx-hint"></textarea>
  <div class="hint" id="{id}-rx-hint">{t.sources.regexHint}</div>
</div>
