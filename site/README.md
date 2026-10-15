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
description: The search result snippet, about 150 characters.
published: 2026-10-15
updated: 2026-11-02
---

The text, in Markdown. Start with a paragraph; the title is the page's only h1, so sections are ## headings.
```

- **`slug`** is the page's address, and every language has its own, in its own language: search engines rank a German address for German searches. Lowercase words joined by `-`; not a language code (`/posts/de/` is the German post list).
- **`updated`** is optional: the date of a change that matters to readers.
- A post in one language only is fine: it has no language select, and only that language's list shows it. A language gets its post list once it has a post.

The folder name ties the language versions together: each page names the others with `hreflang` links and a language select, and `sitemap.xml` lists them all. Every page also gets a link-preview image for social media and chat apps (`og.png` next to the page, 1200×630): a card with its title, the author and the date, drawn at build time by [`generator/og-image.ts`](generator/og-image.ts). Link other posts by their slug in the same language (`/posts/passkeys-erklaert/` from a German post).

`npm run build -w site` checks the files (missing or unknown fields, a slug used twice, a link to a `/posts/` page that doesn't exist) and fails with the list of problems. The generated pages are written to `posts/` (git-ignored): edit the Markdown, not them.

## Adding a language

Add it to `LANGUAGES` in [`generator/posts.ts`](generator/posts.ts), with its post list's path (`/posts/<code>/`) and the texts of the page around the posts. Then write `<code>.md` files next to the others.
