import { marked } from 'marked';

/**
 * The blog at madauth.com/posts/: every post is a folder in content/posts with one Markdown file per language
 * (en.md, de.md). Each language version is its own page with its own slug (/posts/passkeys-explained/,
 * /posts/passkeys-erklaert/), so search engines index every language; the pages name each other with hreflang
 * links, and a language select switches between them.
 */

export const ORIGIN = 'https://madauth.com';
export const AUTHOR = 'David Neuy';

export interface LanguageStrings {
  /** The language's own name, as the language select shows it. */
  name: string;
  /** For og:locale. */
  ogLocale: string;
  /** The path of the language's post list. */
  indexPath: string;
  blog: string;
  indexTitle: string;
  indexDescription: string;
  by: string;
  published: string;
  updated: string;
  language: string;
  docs: string;
  ctaText: string;
  ctaDemo: string;
  ctaStart: string;
  footer: string;
}

export const LANGUAGES = {
  en: {
    name: 'English',
    ogLocale: 'en_US',
    indexPath: '/posts/',
    blog: 'Blog',
    indexTitle: 'madAuth blog: authentication for web apps',
    indexDescription:
      'Articles on passkeys, Google sign-in, passwordless e-mail links, second factors and self-hosted authentication for web apps.',
    by: 'By',
    published: 'Published',
    updated: 'updated',
    language: 'Language',
    docs: 'Docs',
    ctaText:
      'madAuth is an open-source, self-hostable alternative to Cognito and Auth0: run the server in your own cloud account and add a ready-made login dialog to any web app.',
    ctaDemo: 'Try the demo',
    ctaStart: 'Get started',
    footer: 'MIT licensed',
  },
  de: {
    name: 'Deutsch',
    ogLocale: 'de_DE',
    indexPath: '/posts/de/',
    blog: 'Blog',
    indexTitle: 'madAuth-Blog: Authentifizierung für Web-Apps',
    indexDescription:
      'Artikel über Passkeys, Google-Anmeldung, passwortlose E-Mail-Links, zweite Faktoren und selbst gehostete Authentifizierung für Web-Apps.',
    by: 'Von',
    published: 'Veröffentlicht am',
    updated: 'aktualisiert am',
    language: 'Sprache',
    docs: 'Doku',
    ctaText:
      'madAuth ist eine quelloffene Alternative zu Cognito und Auth0, die Sie selbst betreiben: Der Server läuft in Ihrem eigenen Cloud-Konto, und jede Web-App bekommt einen fertigen Anmeldedialog.',
    ctaDemo: 'Demo ausprobieren',
    ctaStart: 'Loslegen',
    footer: 'MIT-Lizenz',
  },
} satisfies Record<string, LanguageStrings>;

export type Language = keyof typeof LANGUAGES;

export const isLanguage = (value: string): value is Language => Object.hasOwn(LANGUAGES, value);

/** One language version of a post, as written in its Markdown file. */
export interface Post {
  /** The folder name, shared by the language versions. */
  id: string;
  language: Language;
  slug: string;
  title: string;
  description: string;
  /** YYYY-MM-DD */
  published: string;
  /** YYYY-MM-DD, when the post was changed after it was published. */
  updated?: string;
  /** The rendered Markdown body. */
  html: string;
}

/** A Markdown file of content/posts: `<id>/<language>.md`. */
export interface SourceFile {
  id: string;
  language: string;
  text: string;
}

export type Result<T> = { isSuccess: true; value: T } | { isSuccess: false; errors: string[] };

/** A page to write: its path under the site root (e.g. `posts/passkeys-explained/index.html`) and its HTML. */
export interface Page {
  file: string;
  html: string;
}

/** Slugs that are paths of their own under /posts/. */
const RESERVED_SLUGS = new Set(Object.keys(LANGUAGES));
const SLUG = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

/** Splits `---`-delimited `key: value` lines from the Markdown that follows them. */
export function parseFrontMatter(text: string): Result<{ fields: Record<string, string>; body: string }> {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (!match) return { isSuccess: false, errors: ['missing front matter (--- lines at the top)'] };
  const lines = match[1].split(/\r?\n/).filter((line) => line.trim() !== '');
  const malformed = lines.filter((line) => !/^[a-z]+:\s/.test(line));
  if (malformed.length > 0) return { isSuccess: false, errors: malformed.map((line) => `not "key: value": ${line}`) };
  const fields = Object.fromEntries(
    lines.map((line) => {
      const colon = line.indexOf(':');
      return [line.slice(0, colon), line.slice(colon + 1).trim()];
    }),
  );
  return { isSuccess: true, value: { fields, body: match[2] } };
}

function parsePost(file: SourceFile): Result<Post> {
  const where = `content/posts/${file.id}/${file.language}.md`;
  const fail = (errors: string[]): Result<Post> => ({ isSuccess: false, errors: errors.map((e) => `${where}: ${e}`) });
  if (!isLanguage(file.language)) return fail([`unknown language "${file.language}" (known: ${Object.keys(LANGUAGES).join(', ')})`]);
  const parsed = parseFrontMatter(file.text);
  if (!parsed.isSuccess) return fail(parsed.errors);
  const { fields, body } = parsed.value;
  const known = new Set(['slug', 'title', 'description', 'published', 'updated']);
  const errors = [
    ...['slug', 'title', 'description', 'published'].filter((key) => !fields[key]).map((key) => `"${key}" is missing`),
    ...Object.keys(fields).filter((key) => !known.has(key)).map((key) => `unknown field "${key}"`),
    ...(fields.slug && (!SLUG.test(fields.slug) || RESERVED_SLUGS.has(fields.slug))
      ? [`slug "${fields.slug}" must be lowercase words joined by "-", and not a language code`]
      : []),
    ...['published', 'updated']
      .filter((key) => fields[key] && !DATE.test(fields[key]))
      .map((key) => `"${key}" must be YYYY-MM-DD`),
  ];
  if (errors.length > 0) return fail(errors);
  return {
    isSuccess: true,
    value: {
      id: file.id,
      language: file.language,
      slug: fields.slug,
      title: fields.title,
      description: fields.description,
      published: fields.published,
      updated: fields.updated,
      html: marked.parse(body, { async: false }),
    },
  };
}

/** Parses every file, and checks that no two posts share a slug and that links to /posts/ lead to a page. */
export function parsePosts(files: SourceFile[]): Result<Post[]> {
  const results = files.map(parsePost);
  const errors = results.flatMap((r) => (r.isSuccess ? [] : r.errors));
  if (errors.length > 0) return { isSuccess: false, errors };
  const posts = results.flatMap((r) => (r.isSuccess ? [r.value] : []));
  const duplicates = [...new Set(posts.map((p) => p.slug))].filter((slug) => posts.filter((p) => p.slug === slug).length > 1);
  if (duplicates.length > 0) return { isSuccess: false, errors: duplicates.map((slug) => `slug "${slug}" is used twice`) };
  const pages = new Set([...posts.map(postPath), ...languagesOf(posts).map((lang) => LANGUAGES[lang].indexPath)]);
  const broken = posts.flatMap((post) =>
    [...post.html.matchAll(/href="(\/posts\/[^"#?]*)/g)]
      .map((match) => match[1])
      .filter((path) => !pages.has(path))
      .map((path) => `content/posts/${post.id}/${post.language}.md: the link to ${path} leads to no page`),
  );
  if (broken.length > 0) return { isSuccess: false, errors: broken };
  return { isSuccess: true, value: posts };
}

/** The languages that have posts, in the order of LANGUAGES: only they get a post list. */
const languagesOf = (posts: Post[]): Language[] =>
  (Object.keys(LANGUAGES) as Language[]).filter((lang) => posts.some((p) => p.language === lang));

export const postPath = (post: Post): string => `/posts/${post.slug}/`;

const escape = (text: string): string =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** JSON for a <script> element: `<` escaped, so the text can't end the element. */
const jsonLd = (value: unknown): string => JSON.stringify(value).replace(/</g, '\\u003c');

const formatDate = (date: string, language: Language): string =>
  new Intl.DateTimeFormat(language, { dateStyle: 'long', timeZone: 'UTC' }).format(new Date(`${date}T00:00:00Z`));

/** The language versions of one page: language → path. The first is the default (English when there is one). */
type Versions = Partial<Record<Language, string>>;

/** The language versions of a post. */
const postVersions = (post: Post, posts: Post[]): Versions =>
  Object.fromEntries(posts.filter((p) => p.id === post.id).sort(byLanguage).map((p) => [p.language, postPath(p)]));

/** The post lists of the languages that have posts. */
const indexVersions = (posts: Post[]): Versions =>
  Object.fromEntries(languagesOf(posts).map((lang) => [lang, LANGUAGES[lang].indexPath]));

function defaultPath(versions: Versions): string {
  return versions.en ?? Object.values(versions)[0]!;
}

function alternateLinks(versions: Versions): string {
  const links = Object.entries(versions).map(
    ([language, path]) => `<link rel="alternate" hreflang="${language}" href="${ORIGIN}${path}" />`,
  );
  return [...links, `<link rel="alternate" hreflang="x-default" href="${ORIGIN}${defaultPath(versions)}" />`].join('\n    ');
}

/** The language select: one option per version, each one's value the version's path. */
function languageSelect(language: Language, versions: Versions): string {
  const entries = Object.entries(versions) as [Language, string][];
  if (entries.length < 2) return '';
  const options = entries
    .map(
      ([lang, path]) =>
        `<option value="${path}" lang="${lang}"${lang === language ? ' selected' : ''}>${LANGUAGES[lang].name}</option>`,
    )
    .join('');
  return `<select class="language" data-language-select aria-label="${LANGUAGES[language].language}">${options}</select>`;
}

interface Layout {
  language: Language;
  title: string;
  description: string;
  path: string;
  versions: Versions;
  /** Extra <head> elements. */
  head: string;
  jsonLd: unknown;
  main: string;
}

function layout(page: Layout): string {
  const strings = LANGUAGES[page.language];
  const otherLocales = (Object.keys(page.versions) as Language[])
    .filter((lang) => lang !== page.language)
    .map((lang) => `<meta property="og:locale:alternate" content="${LANGUAGES[lang].ogLocale}" />`);
  return `<!doctype html>
<html lang="${page.language}">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${escape(page.title)}</title>
    <meta name="description" content="${escape(page.description)}" />
    <link rel="canonical" href="${ORIGIN}${page.path}" />
    ${alternateLinks(page.versions)}
    <meta property="og:site_name" content="madAuth" />
    <meta property="og:title" content="${escape(page.title)}" />
    <meta property="og:description" content="${escape(page.description)}" />
    <meta property="og:url" content="${ORIGIN}${page.path}" />
    <meta property="og:locale" content="${strings.ogLocale}" />
    ${[...otherLocales, page.head].filter(Boolean).join('\n    ')}
    <meta name="twitter:card" content="summary" />
    <script type="application/ld+json">${jsonLd(page.jsonLd)}</script>
    <link rel="stylesheet" href="/src/posts.css" />
    <script type="module" src="/src/language-select.ts"></script>
  </head>
  <body>
    <header>
      <a class="logo" href="/">madAuth</a>
      <nav>
        <a href="${strings.indexPath}">${strings.blog}</a>
        <a href="https://github.com/inouiw/madAuth/tree/main/docs">${strings.docs}</a>
        <a href="https://github.com/inouiw/madAuth">GitHub</a>
        ${languageSelect(page.language, page.versions)}
      </nav>
    </header>
    <main class="posts">
${page.main}
    </main>
    <footer>
      <p>${strings.footer} · <a href="https://github.com/inouiw/madAuth">github.com/inouiw/madAuth</a></p>
    </footer>
  </body>
</html>
`;
}

const organization = { '@type': 'Organization', '@id': `${ORIGIN}/#organization`, name: 'madAuth', url: `${ORIGIN}/` };

function postPage(post: Post, posts: Post[]): Page {
  const strings = LANGUAGES[post.language];
  const versions = postVersions(post, posts);
  const url = `${ORIGIN}${postPath(post)}`;
  const modified = post.updated ?? post.published;
  const dates = `${strings.published} <time datetime="${post.published}">${formatDate(post.published, post.language)}</time>${
    post.updated ? `, ${strings.updated} <time datetime="${post.updated}">${formatDate(post.updated, post.language)}</time>` : ''
  }`;
  const main = `      <nav class="crumbs" aria-label="Breadcrumb"><a href="/">madAuth</a> › <a href="${strings.indexPath}">${strings.blog}</a></nav>
      <article>
        <h1>${escape(post.title)}</h1>
        <p class="meta">${strings.by} ${AUTHOR} · ${dates}</p>
${post.html}
        <aside class="cta">
          <p>${strings.ctaText}</p>
          <p class="actions"><a class="button primary" href="/demo/">${strings.ctaDemo}</a> <a class="button" href="https://github.com/inouiw/madAuth/blob/main/docs/getting-started.md">${strings.ctaStart}</a></p>
        </aside>
      </article>`;
  return {
    file: `posts/${post.slug}/index.html`,
    html: layout({
      language: post.language,
      title: `${post.title} | madAuth`,
      description: post.description,
      path: postPath(post),
      versions,
      head: [
        '<meta property="og:type" content="article" />',
        `<meta property="article:published_time" content="${post.published}" />`,
        `<meta property="article:modified_time" content="${modified}" />`,
      ].join('\n    '),
      jsonLd: {
        '@context': 'https://schema.org',
        '@graph': [
          {
            '@type': 'BlogPosting',
            '@id': `${url}#article`,
            headline: post.title,
            description: post.description,
            inLanguage: post.language,
            url,
            mainEntityOfPage: url,
            datePublished: post.published,
            dateModified: modified,
            author: { '@type': 'Person', name: AUTHOR },
            publisher: { '@id': organization['@id'] },
          },
          organization,
          {
            '@type': 'BreadcrumbList',
            itemListElement: [
              { '@type': 'ListItem', position: 1, name: 'madAuth', item: `${ORIGIN}/` },
              { '@type': 'ListItem', position: 2, name: strings.blog, item: `${ORIGIN}${strings.indexPath}` },
              { '@type': 'ListItem', position: 3, name: post.title, item: url },
            ],
          },
        ],
      },
      main,
    }),
  };
}

const byLanguage = (a: Post, b: Post): number =>
  Object.keys(LANGUAGES).indexOf(a.language) - Object.keys(LANGUAGES).indexOf(b.language);

const newestFirst = (a: Post, b: Post): number => b.published.localeCompare(a.published) || a.slug.localeCompare(b.slug);

function indexPage(language: Language, posts: Post[]): Page {
  const strings = LANGUAGES[language];
  const own = posts.filter((p) => p.language === language).sort(newestFirst);
  const versions = indexVersions(posts);
  const teasers = own
    .map(
      (post) => `        <li>
          <h2><a href="${postPath(post)}">${escape(post.title)}</a></h2>
          <p>${escape(post.description)}</p>
          <p class="meta"><time datetime="${post.published}">${formatDate(post.published, language)}</time></p>
        </li>`,
    )
    .join('\n');
  const url = `${ORIGIN}${strings.indexPath}`;
  return {
    file: `${strings.indexPath.slice(1)}index.html`,
    html: layout({
      language,
      title: strings.indexTitle,
      description: strings.indexDescription,
      path: strings.indexPath,
      versions,
      head: '<meta property="og:type" content="website" />',
      jsonLd: {
        '@context': 'https://schema.org',
        '@graph': [
          {
            '@type': 'Blog',
            '@id': `${url}#blog`,
            name: strings.indexTitle,
            description: strings.indexDescription,
            inLanguage: language,
            url,
            publisher: { '@id': organization['@id'] },
            blogPost: own.map((post) => ({ '@id': `${ORIGIN}${postPath(post)}#article` })),
          },
          organization,
        ],
      },
      main: `      <h1>${escape(strings.indexTitle)}</h1>
      <p class="lead">${escape(strings.indexDescription)}</p>
      <ul class="teasers">
${teasers}
      </ul>`,
    }),
  };
}

/** Every page of the blog: one per post and language, and a post list per language that has posts. */
export function renderPages(posts: Post[]): Page[] {
  return [
    ...languagesOf(posts).map((language) => indexPage(language, posts)),
    ...posts.map((post) => postPage(post, posts)),
  ];
}

/** sitemap.xml: the landing page, the demo, the post lists and the posts, each with its language versions. */
export function renderSitemap(posts: Post[]): string {
  const entry = (path: string, lastmod?: string, versions?: Versions): string => {
    const alternates =
      versions && Object.keys(versions).length > 1
        ? Object.entries(versions)
            .map(([lang, p]) => `\n    <xhtml:link rel="alternate" hreflang="${lang}" href="${ORIGIN}${p}" />`)
            .join('') + `\n    <xhtml:link rel="alternate" hreflang="x-default" href="${ORIGIN}${defaultPath(versions)}" />`
        : '';
    return `  <url>\n    <loc>${ORIGIN}${path}</loc>${lastmod ? `\n    <lastmod>${lastmod}</lastmod>` : ''}${alternates}\n  </url>`;
  };
  const newest = (language: Language) =>
    posts
      .filter((p) => p.language === language)
      .map((p) => p.updated ?? p.published)
      .sort()
      .at(-1);
  const entries = [
    entry('/'),
    entry('/demo/'),
    ...languagesOf(posts).map((lang) => entry(LANGUAGES[lang].indexPath, newest(lang), indexVersions(posts))),
    ...[...posts].sort(newestFirst).map((post) => entry(postPath(post), post.updated ?? post.published, postVersions(post, posts))),
  ];
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
${entries.join('\n')}
</urlset>
`;
}

export const ROBOTS = `User-agent: *
Disallow: /auth/
Sitemap: ${ORIGIN}/sitemap.xml
`;
