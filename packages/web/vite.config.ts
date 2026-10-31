import { fileURLToPath } from 'node:url';
import { defineConfig, normalizePath } from 'vite';

/** The package's own sources (the path above it may contain `src` too), with the slashes Rollup's ids have. */
const src = normalizePath(fileURLToPath(new URL('src/', import.meta.url)));
const clientEntry = `${src}client.ts`;

/** The ids of the modules `entry` imports, directly or through others; `entry` itself included. */
function reachableFrom(entry: string, getModuleInfo: (id: string) => { importedIds: readonly string[] } | null): Set<string> {
  const seen = new Set<string>();
  const visit = (id: string): void => {
    if (seen.has(id)) return;
    seen.add(id);
    for (const imported of getModuleInfo(id)?.importedIds ?? []) visit(imported);
  };
  visit(entry);
  return seen;
}

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
      // Let the consuming app dedupe lit instead of bundling a second copy; uqr, zxcvbn-ts and @madauth/google-identity
      // are dependencies like it. zxcvbn-ts is imported dynamically, so the app's bundler puts it in a chunk of its own.
      external: [/^lit/, 'uqr', /^@zxcvbn-ts\//, '@madauth/google-identity'],
      output: {
        // What the client entry reaches is `core.js` (`client.js` only re-exports it); what only the dialog
        // reaches stays in `index.js`. Rollup would name the shared chunk after its first module otherwise, with a hash.
        chunkFileNames: '[name].js',
        manualChunks: (id, { getModuleInfo }) => (id !== clientEntry && reachableFrom(clientEntry, getModuleInfo).has(id) ? 'core' : undefined),
      },
    },
  },
});
