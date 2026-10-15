<script lang="ts">
  // Result of a settings test call: `{ channel: "ok" | "ok: detail" | "error: …" }`.
  let { result, label = (k: string) => k }: { result: Record<string, string>; label?: (k: string) => string } =
    $props();
  const rows = $derived(Object.entries(result).map(([k, v]) => ({ k, v: String(v), ok: /^ok\b/i.test(String(v)) })));
</script>

<div class="test-result" role="status">
  {#each rows as r (r.k)}
    <div class="row">
      <span class="chip {r.ok ? 'ok' : 'bad'}">{label(r.k)}</span>
      <span class:muted={r.ok}>{r.v}</span>
    </div>
  {/each}
</div>
