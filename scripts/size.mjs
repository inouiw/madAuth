// What @madauth/web adds to an app: bundles two small apps against packages/web/dist with esbuild (minified,
// with code splitting) and prints the gzipped and Brotli sizes of what loads with the page, and of what loads
// later (zxcvbn-ts and its password list, imported on first use). The numbers the README, the @madauth/web README
// and the landing page name come from here: run `npm run size` and update them when they move.
// `npm run size -- --check` (CI runs it) fails when a size in kB in those files is more than 1 kB off every measured one.
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, gzipSync } from 'node:zlib';
import { build } from 'esbuild';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = join(root, 'packages/web/dist/');
/** The files that name the sizes, checked by --check. */
const claimFiles = ['README.md', 'packages/web/README.md', 'site/index.html'];
/** How far a size named in those files may be from a measured one. */
const TOLERANCE_KB = 1;
const check = process.argv.includes('--check');
const providers = 'GoogleFedcm, GitHub, Password, Passkey, Authenticator, EmailLink';
const providerList = 'new GoogleFedcm(), new GitHub(), new Password(), new Passkey(), new Authenticator(), new EmailLink()';

const apps = [
  {
    name: '@madauth/web: the dialog and every sign-in method',
    source: `import { Madauth, ${providers} } from '${join(dist, 'index.js')}';
Madauth.initialize({ providers: [${providerList}] });
document.body.onclick = () => Madauth.showSignInDialog();`,
  },
  {
    name: '@madauth/web/client: every sign-in method, no dialog',
    source: `import { Madauth, ${providers} } from '${join(dist, 'client.js')}';
Madauth.initialize({ providers: [${providerList}], ui: 'custom' });
document.body.onclick = () => Madauth.password.signIn({ email: 'a@example.com', password: 'b' });`,
  },
];

if (!existsSync(join(dist, 'index.js')) || !existsSync(join(dist, 'client.js'))) {
  console.error('packages/web/dist is missing: run `npm run build -w packages/web` first (`npm run size` does).');
  process.exit(1);
}

const kB = (bytes) => `${(bytes / 1000).toFixed(1)} kB`;

/** The outputs `entry` loads with the page: itself and what it imports statically, directly or through others. */
function loadedWithPage(entry, outputs) {
  const seen = new Set();
  const visit = (path) => {
    if (seen.has(path)) return;
    seen.add(path);
    for (const imported of outputs[path].imports) if (imported.kind === 'import-statement') visit(imported.path);
  };
  visit(entry);
  return seen;
}

/** Bundles `source` and sums the compressed sizes of the files loaded with the page and of those loaded later. */
async function measure(dir, source) {
  const entry = join(dir, 'app.js');
  writeFileSync(entry, source);
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    minify: true,
    splitting: true,
    format: 'esm',
    absWorkingDir: dir,
    outdir: join(dir, 'out'),
    write: false,
    metafile: true,
    logLevel: 'error',
  });
  const outputs = result.metafile.outputs;
  const entryOutput = Object.keys(outputs).find((path) => outputs[path].entryPoint !== undefined);
  const initial = loadedWithPage(entryOutput, outputs);
  const sizes = { initial: { gzip: 0, brotli: 0 }, later: { gzip: 0, brotli: 0 } };
  for (const file of result.outputFiles) {
    // The metafile names the outputs relative to absWorkingDir.
    const part = initial.has(relative(dir, file.path)) ? sizes.initial : sizes.later;
    part.gzip += gzipSync(file.contents, { level: 9 }).length;
    part.brotli += brotliCompressSync(file.contents).length;
  }
  return sizes;
}

// The real path: on macOS the temporary directory is behind a symlink, and esbuild names its outputs by the real one.
const dir = realpathSync(mkdtempSync(join(tmpdir(), 'madauth-size-')));
// The directory goes away even when a build fails.
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
const measured = [];
for (const app of apps) {
  const { initial, later } = await measure(dir, app.source);
  console.log(app.name);
  console.log(`  with the page:   ${kB(initial.gzip)} gzip, ${kB(initial.brotli)} brotli`);
  console.log(`  on first use:    ${kB(later.gzip)} gzip, ${kB(later.brotli)} brotli (zxcvbn-ts, on a new-password screen)`);
  measured.push(initial.gzip / 1000, later.gzip / 1000);
}

/** Every size in kB the file names (`49 kB`, `18&nbsp;kB`), with its line. */
function claimsIn(file) {
  const lines = readFileSync(join(root, file), 'utf8').split('\n');
  return lines.flatMap((line, index) => [...line.matchAll(/(\d+(?:\.\d+)?)(?:\s|&nbsp;)kB\b/g)].map((match) => ({ file, line: index + 1, kB: Number(match[1]) })));
}

if (check) {
  const claims = claimFiles.flatMap(claimsIn);
  const off = claims.filter((claim) => measured.every((size) => Math.abs(size - claim.kB) > TOLERANCE_KB));
  for (const claim of off) console.error(`${claim.file}:${claim.line}: ${claim.kB} kB is more than ${TOLERANCE_KB} kB off every measured size`);
  if (off.length > 0) {
    console.error(`Update the sizes in ${claimFiles.join(', ')} to the numbers above.`);
    process.exit(1);
  }
  console.log(`All ${claims.length} sizes in ${claimFiles.join(', ')} are within ${TOLERANCE_KB} kB of the measured ones.`);
}
