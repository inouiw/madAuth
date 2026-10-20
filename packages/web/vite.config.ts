import { fileURLToPath } from 'node:url';
import { defineConfig, normalizePath } from 'vite';

/** The package's own sources (the path above it may contain `src` too), with the slashes Rollup's ids have. */
const src = normalizePath(fileURLToPath(new URL('src/', import.meta.url)));

export default defineConfig({
  build: {
    lib: {
      // Two entries: `index` is the client with the dialog, `client` the client alone, so an app with its own
      // login screen ships neither the dialog nor Lit. What they share goes to a chunk of its own.
      entry: { index: 'src/index.ts', client: 'src/client.ts' },
      formats: ['es'],
      fileName: (_format, entryName) => `${entryName}.js`,
    },
    rollupOptions: {
      // Let the consuming app dedupe lit instead of bundling a second copy; uqr and zxcvbn-ts are dependencies
      // like it. zxcvbn-ts is imported dynamically, so the app's bundler puts it in a chunk of its own.
      external: [/^lit/, 'uqr', /^@zxcvbn-ts\//],
      output: {
        // The client the two entries share is `core.js` (`client.js` only re-exports it); Rollup would name it
        // after its first module otherwise, with a hash.
        chunkFileNames: '[name].js',
        manualChunks: (id) => (id.startsWith(src) && !['index.ts', 'client.ts', 'madauth-login.ts'].includes(id.slice(src.length)) ? 'core' : undefined),
      },
    },
  },
});
