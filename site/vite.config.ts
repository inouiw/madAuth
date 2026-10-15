import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { posts } from './generator/plugin';

// The madauth.com landing page and the blog under /posts/. The demo is built on its own (DEMO_BASE=/demo/) and
// deployed under /demo/.
export default defineConfig({
  appType: 'mpa',
  plugins: [posts(fileURLToPath(new URL('.', import.meta.url)))],
  server: {
    port: 3001,
    strictPort: true,
  },
});
