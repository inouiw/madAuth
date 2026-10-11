import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    lib: {
      entry: 'src/index.ts',
      formats: ['es'],
      fileName: 'index',
    },
    rollupOptions: {
      // Let the consuming app dedupe lit instead of bundling a second copy; uqr and zxcvbn-ts are dependencies
      // like it. zxcvbn-ts is imported dynamically, so the app's bundler puts it in a chunk of its own.
      external: [/^lit/, 'uqr', /^@zxcvbn-ts\//],
    },
  },
});
