import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { wailsRuntimeFix } from './scripts/wails-runtime-fix.mjs';

export default defineConfig({
  // wailsRuntimeFix: frameless drag on ARM64 WebKitGTK (see the script).
  plugins: [wailsRuntimeFix(), svelte()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Fonts stay separate files rather than data: URIs.
    assetsInlineLimit: 0,
  },
});
