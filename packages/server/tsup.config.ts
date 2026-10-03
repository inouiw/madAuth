import { defineConfig, type Options } from 'tsup';

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** A self-contained bundle to deploy without node_modules. `external` lists the packages the host provides. */
function standalone(entry: Record<string, string>, external: string[]): Options {
  return {
    entry,
    outDir: 'dist/standalone',
    // One file per target, so each can be deployed on its own.
    splitting: false,
    format: 'esm',
    target: 'node20',
    platform: 'node',
    // Bundle every dependency except the ones in `external`.
    noExternal: [external.length ? new RegExp(`^(?!(${external.map(escapeRegExp).join('|')})$)`) : /^/],
    external,
    outExtension: () => ({ js: '.mjs' }),
    // Some bundled CommonJS code calls require(); give ESM bundles one.
    banner: { js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" },
  };
}

export default defineConfig([
  // The npm package: library entry points, dependencies stay external.
  {
    entry: {
      index: 'src/index.ts',
      verify: 'src/verify.ts',
      sqlite: 'src/store/sqlite.ts',
      dynamodb: 'src/store/dynamodb.ts',
      testing: 'src/testing.ts',
      webhook: 'src/webhook.ts',
      bin: 'src/bin.ts',
      'entry/node': 'src/entry/node.ts',
      'entry/lambda': 'src/entry/lambda.ts',
      'entry/azure': 'src/entry/azure.ts',
    },
    format: 'esm',
    target: 'node20',
    dts: {
      entry: [
        'src/index.ts',
        'src/verify.ts',
        'src/store/sqlite.ts',
        'src/store/dynamodb.ts',
        'src/testing.ts',
        'src/webhook.ts',
        'src/entry/node.ts',
        'src/entry/lambda.ts',
        'src/entry/azure.ts',
      ],
    },
    clean: true,
  },
  // Docker: the image has no node_modules, so the AWS SDK for DATABASE_URL=dynamodb: is bundled as well.
  standalone({ main: 'src/main.ts' }, []),
  // AWS Lambda: its Node.js runtimes contain the AWS SDK.
  standalone({ lambda: 'src/entry/lambda.ts' }, ['@aws-sdk/client-dynamodb']),
  // Azure Functions: the worker provides @azure/functions-core; the AWS SDK is only needed for DATABASE_URL=dynamodb:.
  standalone({ azure: 'src/entry/azure-main.ts' }, ['@azure/functions-core', '@aws-sdk/client-dynamodb']),
]);
