<script lang="ts">
  import { qrEncode, qrPath } from '../lib/qr';

  let { text, label }: { text: string; label: string } = $props();

  const m = $derived(qrEncode(text));
  const n = $derived(m.length + 8);
</script>

<svg class="qr" viewBox="0 0 {n} {n}" role="img" aria-label={label} shape-rendering="crispEdges">
  <rect class="qr-bg" width={n} height={n} />
  <path class="qr-fg" d={qrPath(m)} />
</svg>
