import { defineConfig } from 'vitest/config';

export default defineConfig({
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
