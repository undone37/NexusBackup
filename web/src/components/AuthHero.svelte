<script lang="ts">
  import { t } from '../lib/i18n';
  import Logo from './Logo.svelte';
</script>

<!-- left half of the sign-in / activation screens (decorative: hidden from screen readers) -->
<aside class="hero" aria-hidden="true">
  <div class="brand"><Logo />{t.app}</div>
  <div>
    <h2>{t.login.heroTitle}</h2>
    <p>{t.login.heroText}</p>
  </div>
  <footer>{t.login.heroFoot}</footer>
  <!-- backdrop: a lattice of linked nodes, the motif of the logo -->
  <svg class="lattice" viewBox="0 0 200 200" fill="none" stroke="currentColor" stroke-width="1.2">
    <path d="M20 180V100l60 60V60l60 60V20l40 40" stroke-linecap="round" stroke-linejoin="round" />
    <path d="M20 100l60-40 60 60 40-60M80 160l60-40" stroke-linecap="round" opacity="0.6" />
    <g fill="currentColor" stroke="none">
      <circle cx="20" cy="180" r="3" /><circle cx="20" cy="100" r="3" /><circle cx="80" cy="160" r="3" /><circle
        cx="80"
        cy="60"
        r="3"
      />
      <circle cx="140" cy="120" r="3" /><circle cx="140" cy="20" r="4.5" /><circle cx="180" cy="60" r="3" />
    </g>
  </svg>
</aside>
