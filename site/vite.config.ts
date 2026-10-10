import { defineConfig } from 'vite';

// The madauth.com landing page. The demo is built on its own (DEMO_BASE=/demo/) and deployed under /demo/.
export default defineConfig({
  server: {
    port: 3001,
    strictPort: true,
  },
});
