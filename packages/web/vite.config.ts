import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    lib: {
      entry: 'src/index.ts',
      formats: ['es'],
      fileName: 'index',
    },
    rollupOptions: {
      // Let the consuming app dedupe lit instead of bundling a second copy.
      external: [/^lit/],
    },
  },
});
