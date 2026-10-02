import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

export default defineConfig({
  resolve: {
    alias: {
      // Use the library source directly so edits hot-reload without rebuilding it.
      '@madauth/web': fileURLToPath(new URL('../../packages/web/src/index.ts', import.meta.url)),
    },
  },
});
