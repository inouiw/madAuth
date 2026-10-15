import { defineConfig } from 'vitest/config';

// Not merged with vite.config.ts: its blog plugin writes the pages to posts/ whenever the config loads.
export default defineConfig({
  test: {
    include: ['generator/**/*.test.ts'],
  },
});
