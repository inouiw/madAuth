import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative } from 'node:path';
import type { Plugin } from 'vite';
import { renderOgImage, type OgFonts } from './og-image';
import { parsePosts, renderPages, renderSitemap, ROBOTS, type Page, type Post, type Result, type SourceFile } from './posts';

/**
 * Builds the blog: reads content/posts/<id>/<language>.md, writes the pages to posts/ (generated, git-ignored)
 * and hands them to Vite as entries, so their CSS and scripts are bundled like the landing page's. The build
 * adds every page's link-preview image (og.png next to its index.html), sitemap.xml and robots.txt. In dev, a
 * changed Markdown file rewrites the pages, and the images are drawn when they are asked for.
 */
export function posts(siteRoot: string): Plugin {
  const contentDir = join(siteRoot, 'content/posts');
  const outDir = join(siteRoot, 'posts');
  let current: Post[] = [];
  let pages: Page[] = [];

  const generate = (): Result<string[]> => {
    const parsed = parsePosts(readSources(contentDir));
    if (!parsed.isSuccess) return parsed;
    current = parsed.value;
    pages = renderPages(current);
    rmSync(outDir, { recursive: true, force: true });
    for (const page of pages) {
      const file = join(siteRoot, page.file);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, page.html);
    }
    return { isSuccess: true, value: pages.map((page) => page.file) };
  };

  return {
    name: 'madauth-posts',
    config() {
      const generated = generate();
      if (!generated.isSuccess) throw new Error(`The blog has errors:\n${generated.errors.join('\n')}`);
      const entries = ['index.html', ...generated.value];
      return {
        build: { rollupOptions: { input: Object.fromEntries(entries.map((file) => [file, join(siteRoot, file)])) } },
      };
    },
    configureServer(server) {
      server.watcher.add(contentDir);
      server.watcher.on('all', (_event, file) => {
        if (relative(contentDir, file).startsWith('..')) return;
        // The rewritten pages reload the browser like any changed HTML file.
        const generated = generate();
        if (!generated.isSuccess) server.config.logger.error(`The blog has errors:\n${generated.errors.join('\n')}`);
      });
      // The dev server has no sitemap.xml of its own to serve.
      server.middlewares.use('/sitemap.xml', (_req, res) => {
        res.setHeader('Content-Type', 'application/xml');
        res.end(renderSitemap(current));
      });
      server.middlewares.use((req, res, next) => {
        const page = pages.find((p) => `/${p.image.file}` === req.url?.split('?')[0]);
        if (!page) return next();
        renderOgImage(page.image.card, loadFonts()).then((png) => {
          res.setHeader('Content-Type', 'image/png');
          res.end(png);
        }, next);
      });
    },
    async generateBundle() {
      const fonts = loadFonts();
      const images = await Promise.all(pages.map(async (page) => ({ page, png: await renderOgImage(page.image.card, fonts) })));
      for (const { page, png } of images) this.emitFile({ type: 'asset', fileName: page.image.file, source: png });
      this.emitFile({ type: 'asset', fileName: 'sitemap.xml', source: renderSitemap(current) });
      this.emitFile({ type: 'asset', fileName: 'robots.txt', source: ROBOTS });
    },
  };
}

const require = createRequire(import.meta.url);

/** Public Sans from @fontsource/public-sans, the font of the site. */
function loadFonts(): OgFonts {
  const file = (weight: number) =>
    readFileSync(require.resolve(`@fontsource/public-sans/files/public-sans-latin-${weight}-normal.woff`));
  return { regular: file(400), bold: file(700) };
}

function readSources(contentDir: string): SourceFile[] {
  if (!existsSync(contentDir)) return [];
  return readdirSync(contentDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .flatMap((dir) =>
      readdirSync(join(contentDir, dir.name))
        .filter((name) => name.endsWith('.md'))
        .map((name) => ({
          id: dir.name,
          language: name.slice(0, -'.md'.length),
          text: readFileSync(join(contentDir, dir.name, name), 'utf8'),
        })),
    );
}
