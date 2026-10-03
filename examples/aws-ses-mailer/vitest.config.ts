import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    // Use the server's source, so the tests run without building it first.
    alias: { '@madauth/server/webhook': fileURLToPath(new URL('../../packages/server/src/webhook.ts', import.meta.url)) },
  },
  test: { include: ['src/**/*.test.ts'], environment: 'node' },
});
