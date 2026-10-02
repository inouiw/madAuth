# Styling the login form

`<madauth-login>` renders inside a shadow DOM, so your page's CSS doesn't leak into it by accident. You can still style it in two ways: **CSS custom properties** for common settings, and **CSS parts** for full control over specific elements.

The dialog follows the user's light/dark preference (`prefers-color-scheme`) automatically.

## CSS custom properties

Set these on `madauth-login` or any ancestor (e.g. `:root`).

| Property | Default | Description |
| --- | --- | --- |
| `--madauth-primary` | `#4f46e5` | Accent color, used for hover borders and the "Coming soon" badge. |
| `--madauth-radius` | `12px` | Corner radius of the dialog. Method buttons use this value minus 4px. |
| `--madauth-font` | `system-ui, sans-serif` | Font family of the dialog. |

```css
madauth-login {
  --madauth-primary: #0f766e;
  --madauth-radius: 6px;
  --madauth-font: 'Inter', sans-serif;
}
```

## CSS parts

Use `::part()` to style an element directly.

| Part | Element |
| --- | --- |
| `dialog` | The dialog box itself (`<dialog>`). |
| `method` | Each sign-in method button. |

```css
madauth-login::part(dialog) {
  width: min(480px, calc(100vw - 32px));
  box-shadow: none;
  border: 1px solid #d1d5db;
}

madauth-login::part(method) {
  padding: 16px;
}
```

## Attributes

| Attribute | Default | Description |
| --- | --- | --- |
| `heading` | `Sign in` | Title shown at the top of the dialog. |

```html
<madauth-login heading="Log in to projectmatch"></madauth-login>
```
