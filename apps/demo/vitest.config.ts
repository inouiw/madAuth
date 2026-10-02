import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      include: ['src/**/*.test.ts'],
      environment: 'happy-dom',
      environmentOptions: {
        happyDOM: {
          url: 'http://localhost:3000/',
          // Never fetch scripts (e.g. Google's GIS); report them as loaded so tests can provide window.google.
          settings: { disableJavaScriptFileLoading: true, handleDisabledFileLoadingAsSuccess: true },
        },
      },
    },
  }),
);
