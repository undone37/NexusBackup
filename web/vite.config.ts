import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { mockApi } from './mock/api.ts';

// Same policy the web-api sends (docs/control-plane.md). Applied to `vite preview`
// so the built bundle can be checked against it; the dev server cannot run under
// it (HMR injects inline styles).
export const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
  "frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

// NEXUS_API=https://appliance:8443 npm run dev  -> proxy /api to a real web-api instead of the mock.
const backend = process.env.NEXUS_API;

export default defineConfig(({ command }) => ({
  // The mock is a dev/preview server middleware only; it is never part of the build.
  plugins: [svelte(), command === 'serve' && !backend ? mockApi() : null],
  server: backend ? { proxy: { '/api': { target: backend, changeOrigin: true, secure: false } } } : undefined,
  preview: {
    headers: {
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    // No data: URIs for fonts/scripts and no inline polyfill script.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
}));
