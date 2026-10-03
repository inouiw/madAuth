# Building your own login screen

madAuth's dialog (`Madauth.signIn()`) is optional. Everything it does is available as methods, grouped by sign-in method, so you can build a login screen that fits your app. The dialog itself is built only on these methods.

```ts
import { Madauth, GoogleFedcm, Password } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm(), new Password()], ui: 'custom' });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
```

`ui: 'custom'` tells madAuth that the page shows its own screen: the dialog never opens by itself, and `Madauth.signIn()` returns an `invalid_options` error.

All methods resolve to a result object and never throw for expected failures:

```ts
const result = await Madauth.password.signIn({ email, password });
if (!result.isSuccess) showError(result.error.code); // e.g. 'invalid_credentials'
```

A successful sign-in also calls the `onAuthStateChanged` listeners, so you can update the page in one place.

A complete example is the demo's [custom login page](../apps/demo/custom.html) ([`src/custom.ts`](../apps/demo/src/custom.ts)), which is at http://localhost:3000/custom.html when the demo runs.

## E-mail & password: `Madauth.password`

Needs `new Password()` in `initialize`, and `DATABASE_URL` and `WEBHOOK_URL` on the server. Without them, the methods fail with `flow_not_enabled`.

| Method | Result | Errors |
| --- | --- | --- |
| `signIn({ email, password })` | `{ user }` | `invalid_credentials`, `email_unverified`, `too_many_attempts` |
| `signUp({ email, password, name?, redirectTo? })` | — | `invalid_email`, `weak_password`, `signup_rejected`, `temporarily_unavailable` |
| `sendVerificationEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `verifyEmail({ email, code })` | `{ user }` | `code_invalid`, `codes_locked` |
| `sendResetEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `confirmReset({ newPassword, token? })` or `confirmReset({ newPassword, email, code })` | `{ user }` | `link_invalid`, `code_invalid`, `codes_locked`, `weak_password` |
| `pendingReset` | `boolean` | True when the page was opened from a reset link |
| `policy` | `{ minLength } \| null` | The server's password rules, for a hint next to the field |

`signUp`, `sendVerificationEmail` and `sendResetEmail` succeed whether or not the address has an account, so nobody can probe for accounts. Tell the user to check their inbox in every case.

`too_many_attempts`, `weak_password` and `signup_rejected` come with a `message` written for the user: the wait time, the minimum length, or the reason your sign-up check gave. For the other codes, write your own texts.

`codes_locked` means that too many wrong codes were entered for this account, across e-mails: its codes no longer work until one of its e-mail links is used. Tell the user to ask for a new e-mail and to open the link in it.

`temporarily_unavailable` means the server's [webhook](server.md#webhooks) did not take over the e-mail, or did not answer the sign-up check. Show something like "E-mail & password sign-up is not available right now. Please try again later." The user's browser language is sent along (`locale`), so your receiver can write the e-mail in it.

### The flows

**Sign up.** Call `signUp`, then show "check your inbox". The e-mail contains a link and a 6-digit code:
- The link opens `redirectTo` (default: the current page). When the page loads, `initialize` confirms the address and signs the user in; your `onAuthStateChanged` listener gets the user.
- For the code, show a field and call `verifyEmail({ email, code })`. This also works when the e-mail is read on another device.

**Sign in** with `signIn`. If it fails with `email_unverified`, offer to send the e-mail again with `sendVerificationEmail`.

**Forgot password.** Call `sendResetEmail`, then show "check your inbox":
- The link opens `redirectTo`. After `initialize`, `pendingReset` is true: show a new-password field and call `confirmReset({ newPassword })`.
- With the code, ask for it and the new password, and call `confirmReset({ newPassword, email, code })`.

A completed reset signs the user in and ends their sessions on other devices.

```ts
await Madauth.initialize({ providers: [new Password()], ui: 'custom' });
if (Madauth.password.pendingReset) showNewPasswordForm();

newPasswordForm.onsubmit = async () => {
  const result = await Madauth.password.confirmReset({ newPassword: input.value });
  if (!result.isSuccess) showError(result.error);
};
```

To handle the link yourself, e.g. on a separate page or in a native app, read the token from the URL's hash (`#madauth_reset=<token>`) and pass it: `confirmReset({ newPassword, token })`.

### `redirectTo`

The page the e-mail's link opens, e.g. `https://app.example.com/login`. The default is the current page without its hash. Its origin must be in the server's `ALLOWED_ORIGINS`, otherwise the method fails with `invalid_options`. The page must call `Madauth.initialize` with `new Password()`.

### Password managers

Use these `autocomplete` values so browsers offer to save and fill passwords and codes:

| Field | `autocomplete` |
| --- | --- |
| E-mail | `email` (or `username`) |
| Password when signing in | `current-password` |
| Password when signing up or resetting | `new-password` |
| Code from the e-mail | `one-time-code` |

## Google: `Madauth.google`

Needs `new GoogleFedcm()` or `new GoogleRedirect()` in `initialize`.

```ts
const result = Madauth.google.renderButton(document.querySelector('#google-button')!, {
  theme: 'auto', // or 'light' / 'dark'; 'auto' follows the container's color-scheme
  onResult: (result) => {
    if (!result.isSuccess) showError(result.error);
  },
});
// Later, e.g. when the screen closes:
if (result.isSuccess) result.remove();
```

- With `GoogleFedcm`, this renders Google's own button, which opens the browser's "Continue as …" dialog. Google's button can't be styled; it is between 200 and 400 pixels wide.
- With `GoogleRedirect`, it renders a "Continue with Google" button in Google's colors that starts the redirect. The result arrives through `onAuthStateChanged` after the return.

You can call `renderButton` before `initialize` has finished. The button appears as soon as madAuth is ready.

One Tap (`GoogleFedcm` with its default `autoPrompt: true`) works on custom screens as well.

## Signing out and the session

These work the same with or without the dialog: `Madauth.signOut()`, `Madauth.deleteAccount()`, `Madauth.getSession()`, `Madauth.currentUser` and `Madauth.onAuthStateChanged(listener)`. See the [README](../README.md#using-madauth-in-your-app).
