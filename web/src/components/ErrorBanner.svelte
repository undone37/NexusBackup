<script lang="ts">
  let { error }: { error: string | null } = $props();
</script>

{#if error}
  <div class="banner error" role="alert">{error}</div>
{/if}
