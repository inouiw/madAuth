import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  // The tests run against the sources of @madauth/google-identity, so they need no build of it (tsconfig.json has the same path).
  resolve: { alias: { '@madauth/google-identity': fileURLToPath(new URL('../google-identity/src/index.ts', import.meta.url)) } },
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'happy-dom',
    environmentOptions: {
      happyDOM: {
        url: 'https://app.example.com/page',
        // Never fetch scripts (e.g. Google's GIS); report them as loaded so tests can provide window.google.
        settings: { disableJavaScriptFileLoading: true, handleDisabledFileLoadingAsSuccess: true },
      },
    },
  },
});
