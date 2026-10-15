import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import type { Plugin } from 'vite';
import { parsePosts, renderPages, renderSitemap, ROBOTS, type Post, type Result, type SourceFile } from './posts';

/**
 * Builds the blog: reads content/posts/<id>/<language>.md, writes the pages to posts/ (generated, git-ignored)
 * and hands them to Vite as entries, so their CSS and scripts are bundled like the landing page's. The build
 * adds sitemap.xml and robots.txt. In dev, a changed Markdown file rewrites the pages and reloads the browser.
 */
export function posts(siteRoot: string): Plugin {
  const contentDir = join(siteRoot, 'content/posts');
  const outDir = join(siteRoot, 'posts');
  let current: Post[] = [];

  const generate = (): Result<string[]> => {
    const parsed = parsePosts(readSources(contentDir));
    if (!parsed.isSuccess) return parsed;
    current = parsed.value;
    rmSync(outDir, { recursive: true, force: true });
    const pages = renderPages(current);
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
        const generated = generate();
        if (generated.isSuccess) server.ws.send({ type: 'full-reload' });
        else server.config.logger.error(`The blog has errors:\n${generated.errors.join('\n')}`);
      });
      // The dev server has no sitemap.xml of its own to serve.
      server.middlewares.use('/sitemap.xml', (_req, res) => {
        res.setHeader('Content-Type', 'application/xml');
        res.end(renderSitemap(current));
      });
    },
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'sitemap.xml', source: renderSitemap(current) });
      this.emitFile({ type: 'asset', fileName: 'robots.txt', source: ROBOTS });
    },
  };
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
