# madauth.com

The landing page (`index.html`) and the blog under `/posts/`, built by Vite (`npm run dev -w site`, port 3001). The demo is built on its own and deployed under `/demo/`; the infrastructure is in [`infra`](infra/README.md).

## Writing a post

Every post is a folder in `content/posts`, with one Markdown file per language:

```
content/posts/passkeys/en.md   →  https://madauth.com/posts/passkeys-explained/
content/posts/passkeys/de.md   →  https://madauth.com/posts/passkeys-erklaert/
```

Each file starts with these fields:

```markdown
---
slug: passkeys-explained
title: Passkeys explained: how WebAuthn works and why phishing fails
seoTitle: Passkeys explained: how WebAuthn stops phishing
description: The search result snippet, at most 160 characters.
published: 2026-10-15
updated: 2026-11-02
---

The text, in Markdown. Start with a paragraph; the title is the page's only h1, so sections are ## headings. Every ## and ### heading gets an id from its text (`#warum-phishing-scheitert`) to link to, and a post with three ## sections or more gets a table of contents.
```

- **`slug`** is the page's address, and every language has its own, in its own language: search engines rank a German address for German searches. Lowercase words joined by `-`; not a language code (`/posts/de/` is the German post list).
- **`title`** is the page's heading, and the title of its link preview.
- **`seoTitle`** is optional: the title in search results and the browser tab, for a `title` longer than the 60 characters search results show. The build refuses a longer one, and adds " | madAuth" when that still fits.
- **`description`** is what search results show below the title: at most 160 characters.
- **`updated`** is optional: the date of a change that matters to readers.
- A post in one language only is fine: it has no language select, and only that language's list shows it. A language gets its post list once it has a post.

The folder name ties the language versions together: each page names the others with `hreflang` links and a language select, and `sitemap.xml` lists them all. Every page also gets a link-preview image for social media and chat apps (`og.png` next to the page, 1200×630): a card with its title, the author and the date, drawn at build time by [`generator/og-image.ts`](generator/og-image.ts). Link other posts by their slug in the same language (`/posts/passkeys-erklaert/` from a German post).

The landing page shows the three newest English posts, in place of its `<!-- latest-posts -->` comment. The site's icon is `public/favicon.svg`; the build draws `apple-touch-icon.png` and `icon-512.png` (the publisher logo in the structured data) from it.

`npm run build -w site` checks the files (missing or unknown fields, a title or description too long for search results, a slug used twice, a link to a `/posts/` page that doesn't exist) and fails with the list of problems. The generated pages are written to `posts/` (git-ignored): edit the Markdown, not them.

## Adding a language

Add it to `LANGUAGES` in [`generator/posts.ts`](generator/posts.ts), with its post list's path (`/posts/<code>/`) and the texts of the page around the posts. Then write `<code>.md` files next to the others.
