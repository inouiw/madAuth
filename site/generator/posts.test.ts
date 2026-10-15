import { describe, expect, it } from 'vitest';
import { headingId, parseFrontMatter, parsePosts, renderLatestPosts, renderPages, renderSitemap, type Post, type SourceFile } from './posts';

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
  it('renders the Markdown, with an id on every h2 and h3', () => {
    const [post] = parsed([source('p', 'en', fields('p-en'), '## Head\n\n`code`\n\n### Head\n\n## Über `uns` & Co')]);
    expect(post.html).toBe(
      '<h2 id="head">Head</h2>\n<p><code>code</code></p>\n<h3 id="head-2">Head</h3>\n<h2 id="ueber-uns-co">Über <code>uns</code> &amp; Co</h2>\n',
    );
    expect(post.headings).toEqual([
      { id: 'head', html: 'Head' },
      { id: 'ueber-uns-co', html: 'Über <code>uns</code> &amp; Co' },
    ]);
  });

  it('makes ids of German and accented headings', () => {
    expect(headingId('Warum ein Datenleck viel weniger kostet')).toBe('warum-ein-datenleck-viel-weniger-kostet');
    expect(headingId('Größe &amp; Café')).toBe('groesse-cafe');
    expect(headingId('Résumé of the naïve flow')).toBe('resume-of-the-naive-flow');
  });

  it('refuses a title or description too long for search results', () => {
    const long = 'A title that is much too long to be shown in full in the search results';
    expect(parsePosts([source('a', 'en', { ...fields('a'), title: long, description: 'd'.repeat(161) })])).toEqual({
      isSuccess: false,
      errors: [
        'content/posts/a/en.md: the title in search results has 71 characters, more than the 60 they show: add a shorter "seoTitle"',
        'content/posts/a/en.md: "description" has 161 characters, more than the 160 search results show',
      ],
    });
    expect(parsePosts([source('a', 'en', { ...fields('a'), title: long, seoTitle: 'Short' })]).isSuccess).toBe(true);
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

  it('names the link-preview image of every page', () => {
    expect(pages.map((p) => p.image.file)).toEqual([
      'posts/og.png',
      'posts/de/og.png',
      'posts/passkeys-explained/og.png',
      'posts/passkeys-erklaert/og.png',
      'posts/only-english/og.png',
    ]);
    expect(pages[3].image.card).toEqual({ kicker: 'Blog', title: 'Passkeys <erklärt>', byline: 'David Neuy · 15. Oktober 2026' });
    const html = page('posts/passkeys-erklaert/index.html');
    expect(html).toContain('<meta property="og:image" content="https://madauth.com/posts/passkeys-erklaert/og.png" />');
    expect(html).toContain('<meta property="og:image:alt" content="Passkeys &lt;erklärt&gt;" />');
    expect(html).toContain('<meta name="twitter:card" content="summary_large_image" />');
  });

  it('uses the seoTitle in the title, with the site name when it fits, and the title in link previews', () => {
    const [post] = renderPages(
      parsed([source('a', 'en', { ...fields('a'), title: 'A long heading for the page', seoTitle: 'Short title' })]),
    ).slice(1);
    expect(post.html).toContain('<title>Short title | madAuth</title>');
    expect(post.html).toContain('<meta property="og:title" content="A long heading for the page" />');
    expect(post.html).toContain('<h1>A long heading for the page</h1>');
    const exact = renderPages(parsed([source('b', 'en', { ...fields('b'), title: 'x'.repeat(55) })]))[1];
    expect(exact.html).toContain(`<title>${'x'.repeat(55)}</title>`);
  });

  it('gives a post with three sections and more a table of contents', () => {
    const body = '## One\n\n## Two\n\n## Three';
    const [, withToc] = renderPages(parsed([source('a', 'de', fields('a'), body)]));
    expect(withToc.html).toContain('<nav class="toc" aria-label="Inhalt"><p>Inhalt</p><ol><li><a href="#one">One</a></li>');
    const [, without] = renderPages(parsed([source('a', 'de', fields('a'), '## One\n\n## Two')]));
    expect(without.html).not.toContain('class="toc"');
  });

  it('names the icons and the publisher logo', () => {
    const html = page('posts/passkeys-explained/index.html');
    expect(html).toContain('<link rel="icon" href="/favicon.svg" type="image/svg+xml" />');
    expect(html).toContain('<meta name="robots" content="max-image-preview:large" />');
    expect(html).toContain('"logo":{"@type":"ImageObject","url":"https://madauth.com/icon-512.png"');
  });

  it('lists the newest English posts for the landing page', () => {
    const html = renderLatestPosts(posts, 1);
    expect(html).toContain('<a href="/posts/only-english/">Title only-english</a>');
    expect(html).not.toContain('/posts/passkeys-explained/');
    expect(renderLatestPosts([])).toBe('');
    expect(html).toContain('<a href="/posts/" hreflang="en" lang="en">All posts</a> · <a href="/posts/de/" hreflang="de" lang="de">Artikel auf Deutsch</a>');
    expect(renderLatestPosts(posts.filter((p) => p.language === 'en'))).not.toContain('/posts/de/');
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
