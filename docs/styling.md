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
| `--madauth-primary` | `#17181a` (light), `#f1f2f3` (dark) | Fill color of the primary buttons ("Sign in", "Create account", …). Its text switches between white and near-black to stay readable on the color you set. |
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
| `method` | Each sign-in method button: the submit buttons of the forms ("Sign in", "Create account", "Turn on", …), the "Sign in with a passkey" button, and every row under "Other ways to sign in". Google's own button (with `GoogleFedcm`) and the redirect buttons (with `GoogleRedirect` and `GitHub`) follow the providers' design and can't be styled; they take the dialog's light or dark look. |
| `error` | The message shown when a sign-in fails. |
| `form` | Each form: sign in (`signin`), create account (`signup`), forgot password (`forgot`), code (`code`), new password (`reset`), the e-mail link (`email-link`), the authenticator app's: sign in with it (`authenticator`), the second step (`authenticator-code`), the setup (`authenticator-setup`), the code before new recovery codes, a new app or removing it (`authenticator-confirm`), and the SMS code's: the second step (`sms-code`), adding a phone (`sms-setup`, `sms-setup-code`), a new API key (`api-key-create`), and a sign-in provider in the admin dialog (`provider-form`). The class names tell them apart. |
| `input` | Each text field and select, e.g. the second factor to ask for first in the methods dialog. |
| `link` | The text buttons: "Forgot password?", "No account? Create one", "Already have an account? Sign in" (only the action, a `<span>`, is underlined), "Back to sign in", "Back", "Manage" (on the authenticator app's row), "Send the email again", "Use a recovery code instead", "Send a code by SMS instead", "Use your phone number instead", "Cancel", "Start again". |
| `qr` | The QR code of the authenticator app's key: an inline SVG whose modules are drawn in its text color, black on a white background. Keep it dark on light; not every authenticator app reads an inverted code. |
| `codes` | The list of recovery codes, shown once after the setup or after new ones were made. |
| `warning` | In the authenticator app's view of the methods dialog, the note that 3 or fewer recovery codes are left. It has `data-codes-left`. |
| `api-key` | A new [API key](api-keys.md), shown once to copy (monospace, selected with one click). |
| `callback-url` | In the admin dialog, the callback URL to register at a sign-in provider (monospace, selected with one click, like `api-key`). |
| `branding` | The line "by madAuth" at the bottom of the dialog, with the link to [madauth.com](https://madauth.com). |
| `strength` | The strength meter under a new password (create account, new password): four bars and a word. It has `data-score` (0 to 4), and `data-too-easy` while the password is below the server's `minScore`. |

```css
madauth-login::part(dialog) {
  width: min(480px, calc(100vw - 32px));
  box-shadow: none;
  border: 1px solid #d1d5db;
}

madauth-login::part(method) {
  font-weight: 600;
}

madauth-login::part(input) {
  border-color: #9ca3af;
}
```

To change more than the look, e.g. the layout or the texts, build your own screen with the same methods the dialog uses: see [Building your own login screen](custom-ui.md).

## Attributes

| Attribute | Default | Description |
| --- | --- | --- |
| `heading` | `Sign in`, in the dialog's language | Title shown at the top of the dialog. A heading you set is shown as it is in every language. |
| `code-autocomplete` | `off` | `autocomplete` of the fields for the code from the authenticator app. `one-time-code` lets Apple Passwords, 1Password or Bitwarden offer a stored code, but the iCloud Passwords extension for Chrome then opens its panel on the field even with nothing stored. See [Password managers](custom-ui.md#password-managers). |

```html
<madauth-login heading="Log in to projectmatch"></madauth-login>
```

## Language

The dialog has English and German texts. It follows the page's `<html lang>`, then the browser's language, and shows English for every other language. To set the language yourself, pass `locale` to `Madauth.initialize` and call `Madauth.setLocale` when it changes:

```ts
Madauth.initialize({ providers: [new Password()], locale: 'de' }); // or e.g. 'de-CH'
Madauth.setLocale('en'); // an open dialog changes at once
```

Google's own button (with `GoogleFedcm`) is not affected: Google picks its language.
