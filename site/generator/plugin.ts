import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative } from 'node:path';
import type { Plugin } from 'vite';
import { renderIcon, renderOgImage, type OgFonts } from './og-image';
import {
  ICONS,
  LANDING_IMAGE,
  parsePosts,
  renderLandingJsonLd,
  renderLatestPosts,
  renderPages,
  renderSitemap,
  ROBOTS,
  type Page,
  type Post,
  type Result,
  type SourceFile,
} from './posts';

/**
 * Builds the blog: reads content/posts/<id>/<language>.md, writes the pages to posts/ (generated, git-ignored)
 * and hands them to Vite as entries, so their CSS and scripts are bundled like the landing page's. The build
 * adds every page's link-preview image (og.png next to its index.html, and the landing page's), the PNG icons
 * drawn from public/favicon.svg, sitemap.xml and robots.txt, and puts the newest posts on the landing page. In
 * dev, a changed Markdown file rewrites the pages, and the images are drawn when they are asked for.
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

  /** The images drawn rather than copied: each one's path under the site root, and how to draw it. */
  // The files are read when the first image is drawn, not for every request.
  const icon = () => readFileSync(join(siteRoot, 'public', ICONS.svg), 'utf8');
  const drawn = (): { file: string; draw: () => Promise<Buffer> }[] => [
    ...[...pages.map((page) => page.image), LANDING_IMAGE].map((image) => ({
      file: image.file,
      draw: () => renderOgImage(image.card, loadFonts()),
    })),
    { file: ICONS.appleTouch, draw: async () => renderIcon(icon(), 180) },
    { file: ICONS.logo, draw: async () => renderIcon(icon(), 512) },
  ];

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
        const path = req.url?.split('?')[0] ?? '';
        const image = path.endsWith('.png') ? drawn().find((d) => `/${d.file}` === path) : undefined;
        if (!image) return next();
        image.draw().then((png) => {
          res.setHeader('Content-Type', 'image/png');
          res.end(png);
        }, next);
      });
    },
    transformIndexHtml: {
      order: 'pre',
      handler(html, ctx) {
        return ctx.filename === join(siteRoot, 'index.html')
          ? html.replace('<!-- latest-posts -->', renderLatestPosts(current)).replace('<!-- structured-data -->', renderLandingJsonLd())
          : html;
      },
    },
    async generateBundle() {
      const images = await Promise.all(drawn().map(async (d) => ({ file: d.file, png: await d.draw() })));
      for (const { file, png } of images) this.emitFile({ type: 'asset', fileName: file, source: png });
      this.emitFile({ type: 'asset', fileName: 'sitemap.xml', source: renderSitemap(current) });
      this.emitFile({ type: 'asset', fileName: 'robots.txt', source: ROBOTS });
    },
  };
}

const require = createRequire(import.meta.url);

let fonts: OgFonts | undefined;

/** Public Sans from @fontsource/public-sans, the font of the site; read once. */
function loadFonts(): OgFonts {
  const file = (weight: number) =>
    readFileSync(require.resolve(`@fontsource/public-sans/files/public-sans-latin-${weight}-normal.woff`));
  fonts ??= { regular: file(400), bold: file(700) };
  return fonts;
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
