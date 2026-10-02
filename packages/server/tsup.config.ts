import { defineConfig } from 'tsup';

export default defineConfig([
  // The npm package: library entry points, dependencies stay external.
  {
    entry: {
      index: 'src/index.ts',
      verify: 'src/verify.ts',
      bin: 'src/bin.ts',
      'entry/node': 'src/entry/node.ts',
      'entry/lambda': 'src/entry/lambda.ts',
      'entry/azure': 'src/entry/azure.ts',
    },
    format: 'esm',
    target: 'node20',
    dts: { entry: ['src/index.ts', 'src/verify.ts', 'src/entry/node.ts', 'src/entry/lambda.ts', 'src/entry/azure.ts'] },
    clean: true,
  },
  // Self-contained bundles to deploy without node_modules: Docker, Lambda and Azure Functions.
  {
    entry: {
      main: 'src/main.ts',
      lambda: 'src/entry/lambda.ts',
      azure: 'src/entry/azure.ts',
    },
    outDir: 'dist/standalone',
    // One file per target, so each can be deployed on its own.
    splitting: false,
    format: 'esm',
    target: 'node20',
    platform: 'node',
    // Bundle every dependency except @azure/functions-core, which the Azure Functions worker provides.
    noExternal: [/^(?!@azure\/functions-core$)/],
    external: ['@azure/functions-core'],
    outExtension: () => ({ js: '.mjs' }),
    // Some bundled CommonJS code calls require(); give ESM bundles one.
    banner: { js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" },
  },
]);
