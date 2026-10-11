<script lang="ts">
  // static mark: no props
</script>

<!-- NexusBackup mark: an "N" drawn as one connected path (two nodes joined by a link) with the
     newest copy as a solid point. Replace this file + src/favicon.svg to rebrand. -->
<svg viewBox="0 0 32 32" aria-hidden="true" focusable="false">
  <rect width="32" height="32" rx="8" class="logo-bg" />
  <path d="M9.5 22.5v-13l13 13v-13" class="logo-n" />
  <circle cx="22.5" cy="9.5" r="2.6" class="logo-dot" />
</svg>

<style>
  .logo-bg {
    fill: rgb(255 255 255 / 7%);
  }
  .logo-n {
    fill: none;
    stroke: var(--teal-bright);
    stroke-width: 3.2;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .logo-dot {
    fill: #ffffff;
  }
  :global(.topbar) .logo-bg,
  :global(.login .pane) .logo-bg {
    fill: #0d1b2e;
  }
</style>
