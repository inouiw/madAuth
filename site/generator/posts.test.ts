import { describe, expect, it } from 'vitest';
import { parseFrontMatter, parsePosts, renderPages, renderSitemap, type Post, type SourceFile } from './posts';

const source = (id: string, language: string, fields: Record<string, string>, body = 'Text.'): SourceFile => ({
  id,
  language,
  text: `---\n${Object.entries(fields)
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n')}\n---\n${body}\n`,
});

const fields = (slug: string) => ({ slug, title: `Title ${slug}`, description: `About ${slug}`, published: '2026-10-15' });

const parsed = (files: SourceFile[]): Post[] => {
  const result = parsePosts(files);
  if (!result.isSuccess) throw new Error(result.errors.join('\n'));
  return result.value;
};

describe('parseFrontMatter', () => {
  it('splits the fields from the body', () => {
    expect(parseFrontMatter('---\ntitle: A: B\nslug: a\n---\n# Body\n')).toEqual({
      isSuccess: true,
      value: { fields: { title: 'A: B', slug: 'a' }, body: '# Body\n' },
    });
  });

  it('refuses a file without front matter', () => {
    expect(parseFrontMatter('# Body').isSuccess).toBe(false);
  });
});

describe('parsePosts', () => {
  it('renders the Markdown', () => {
    expect(parsed([source('p', 'en', fields('p-en'), '## Head\n\n`code`')])[0].html).toBe(
      '<h2>Head</h2>\n<p><code>code</code></p>\n',
    );
  });

  it('names every error of every file', () => {
    const result = parsePosts([
      source('a', 'fr', fields('a')),
      source('b', 'en', { ...fields('B b'), published: '15.10.2026', author: 'x' }),
    ]);
    expect(result.isSuccess).toBe(false);
    if (result.isSuccess) return;
    expect(result.errors).toEqual([
      'content/posts/a/fr.md: unknown language "fr" (known: en, de)',
      'content/posts/b/en.md: unknown field "author"',
      'content/posts/b/en.md: slug "B b" must be lowercase words joined by "-", and not a language code',
      'content/posts/b/en.md: "published" must be YYYY-MM-DD',
    ]);
  });

  it('refuses a language code as slug, and a slug used twice', () => {
    expect(parsePosts([source('a', 'en', fields('de'))]).isSuccess).toBe(false);
    expect(parsePosts([source('a', 'en', fields('same')), source('a', 'de', fields('same'))])).toEqual({
      isSuccess: false,
      errors: ['slug "same" is used twice'],
    });
  });
});

describe('links between posts', () => {
  it('must lead to a page', () => {
    const files = [
      source('a', 'en', fields('a'), 'See [b](/posts/b/), [the list](/posts/) and [c](/posts/c/#part).'),
      source('b', 'en', fields('b')),
    ];
    expect(parsePosts(files)).toEqual({
      isSuccess: false,
      errors: ['content/posts/a/en.md: the link to /posts/c/ leads to no page'],
    });
    expect(parsePosts(files.slice(0, 1).concat(source('b', 'en', fields('b')), source('c', 'en', fields('c')))).isSuccess).toBe(true);
  });

  it('cannot lead to the list of a language without posts', () => {
    expect(parsePosts([source('a', 'en', fields('a'), '[German](/posts/de/)')]).isSuccess).toBe(false);
  });
});

describe('renderPages', () => {
  const posts = parsed([
    source('passkeys', 'en', fields('passkeys-explained')),
    source('passkeys', 'de', { ...fields('passkeys-erklaert'), title: 'Passkeys <erklärt>' }),
    source('only-en', 'en', { ...fields('only-english'), published: '2026-10-16' }),
  ]);
  const pages = renderPages(posts);
  const page = (file: string) => pages.find((p) => p.file === file)!.html;

  it('writes a page per post and language, and a list per language', () => {
    expect(pages.map((p) => p.file)).toEqual([
      'posts/index.html',
      'posts/de/index.html',
      'posts/passkeys-explained/index.html',
      'posts/passkeys-erklaert/index.html',
      'posts/only-english/index.html',
    ]);
  });

  it('links the language versions of a post to each other', () => {
    const html = page('posts/passkeys-erklaert/index.html');
    expect(html).toContain('<html lang="de">');
    expect(html).toContain('<link rel="canonical" href="https://madauth.com/posts/passkeys-erklaert/" />');
    expect(html).toContain('<link rel="alternate" hreflang="en" href="https://madauth.com/posts/passkeys-explained/" />');
    expect(html).toContain('<link rel="alternate" hreflang="de" href="https://madauth.com/posts/passkeys-erklaert/" />');
    expect(html).toContain('<link rel="alternate" hreflang="x-default" href="https://madauth.com/posts/passkeys-explained/" />');
    expect(html).toContain(
      '<option value="/posts/passkeys-explained/" lang="en">English</option><option value="/posts/passkeys-erklaert/" lang="de" selected>Deutsch</option>',
    );
    expect(html).toContain('<h1>Passkeys &lt;erklärt&gt;</h1>');
    expect(html).toContain('15. Oktober 2026');
  });

  it('shows no language select for a post in one language', () => {
    const html = page('posts/only-english/index.html');
    expect(html).not.toContain('<select');
    expect(html).toContain('hreflang="x-default" href="https://madauth.com/posts/only-english/"');
  });

  it('lists a language\'s posts, newest first', () => {
    const html = page('posts/index.html');
    expect(html.indexOf('/posts/only-english/')).toBeLessThan(html.indexOf('/posts/passkeys-explained/'));
    expect(page('posts/de/index.html')).not.toContain('/posts/only-english/');
  });

  it('keeps the JSON-LD from ending its script element', () => {
    const html = page('posts/passkeys-erklaert/index.html');
    expect(html).toContain('"headline":"Passkeys \\u003cerklärt>"');
  });

  it('puts the language versions into the sitemap', () => {
    const sitemap = renderSitemap(posts);
    expect(sitemap).toContain(
      '<loc>https://madauth.com/posts/passkeys-erklaert/</loc>\n    <lastmod>2026-10-15</lastmod>\n    <xhtml:link rel="alternate" hreflang="en" href="https://madauth.com/posts/passkeys-explained/" />',
    );
    expect(sitemap).toContain('<loc>https://madauth.com/posts/de/</loc>');
    expect(sitemap).toContain('<loc>https://madauth.com/posts/only-english/</loc>\n    <lastmod>2026-10-16</lastmod>\n  </url>');
  });
});
