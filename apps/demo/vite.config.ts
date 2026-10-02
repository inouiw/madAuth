import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

// The madAuth server (npm run dev:server). Proxying keeps it on the demo's origin, so its cookies are first-party.
const madauthServer = 'http://localhost:8787';

export default defineConfig({
  resolve: {
    alias: {
      // Use the library source directly so edits hot-reload without rebuilding it.
      '@madauth/web': fileURLToPath(new URL('../../packages/web/src/index.ts', import.meta.url)),
    },
  },
  server: {
    // The demo's Google client allows the origins http://localhost:3000 and http://localhost.
    port: 3000,
    strictPort: true,
    proxy: {
      '/auth': madauthServer,
      '/.well-known': madauthServer,
    },
  },
});
