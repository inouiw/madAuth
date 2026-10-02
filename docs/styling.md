# Styling the login form

`<madauth-login>` renders inside a shadow DOM, so your page's CSS doesn't leak into it by accident. You can still style it in two ways: **CSS custom properties** for common settings, and **CSS parts** for full control over specific elements.

The dialog follows the user's light/dark preference (`prefers-color-scheme`) automatically. To force a theme, or to follow your page's own theme switch, set `color-scheme` on the element:

```css
madauth-login {
  color-scheme: dark; /* or `light`, or `inherit` to use the page's color-scheme */
}
```

## CSS custom properties

Set these on `madauth-login` or any ancestor (e.g. `:root`).

| Property | Default | Description |
| --- | --- | --- |
| `--madauth-primary` | `#17181a` (light), `#f1f2f3` (dark) | Fill color of the primary "Sign in" button. Its text switches between white and near-black to stay readable on the color you set. |
| `--madauth-radius` | `14px` | Corner radius of the dialog. Buttons and fields use this value minus 6px, the "Other ways to sign in" list minus 4px. |
| `--madauth-font` | `'Public Sans Variable', 'Public Sans', system-ui, sans-serif` | Font family of the dialog. See [Font](#font). |

```css
madauth-login {
  --madauth-primary: #0f766e;
  --madauth-radius: 6px;
  --madauth-font: 'Inter', sans-serif;
}
```

## Font

The dialog is designed for [Public Sans](https://public-sans.digital.gov/), an open-source typeface (SIL Open Font License). The component does not load the font itself, so it never makes a request to a font host on its own. Load Public Sans in your page and the dialog picks it up; without it the dialog falls back to the system font.

Self-hosted, from npm:

```bash
npm install @fontsource-variable/public-sans
```

```js
import '@fontsource-variable/public-sans';
```

Or from Google Fonts:

```html
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Public+Sans:wght@400..600&display=swap" />
```

To use your app's own font instead, set `--madauth-font`.

## CSS parts

Use `::part()` to style an element directly.

| Part | Element |
| --- | --- |
| `dialog` | The dialog box itself (`<dialog>`). |
| `method` | Each sign-in method button: "Continue with Google", the "Sign in" button of the password form, and every row under "Other ways to sign in". With `GoogleFedcm`, the Google button is rendered by Google and can't be styled. |
| `error` | The message shown when a sign-in fails. |

```css
madauth-login::part(dialog) {
  width: min(480px, calc(100vw - 32px));
  box-shadow: none;
  border: 1px solid #d1d5db;
}

madauth-login::part(method) {
  font-weight: 600;
}
```

## Attributes

| Attribute | Default | Description |
| --- | --- | --- |
| `heading` | `Sign in` | Title shown at the top of the dialog. |

```html
<madauth-login heading="Log in to projectmatch"></madauth-login>
```
