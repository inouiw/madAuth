# Building your own login screen

madAuth's dialog (`Madauth.signIn()`) is optional. Everything it does is available as methods, grouped by sign-in method, so you can build a login screen that fits your app. The dialog itself is built only on these methods.

```ts
import { Madauth, GoogleFedcm, Password, Totp } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm(), new Password(), new Totp()], ui: 'custom' });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
```

`ui: 'custom'` tells madAuth that the page shows its own screen: the dialog never opens by itself, and `Madauth.signIn()` and `Madauth.setUpAuthenticator()` return an `invalid_options` error.

All methods resolve to a result object and never throw for expected failures:

```ts
const result = await Madauth.password.signIn({ email, password });
if (!result.isSuccess) showError(result.error.code); // e.g. 'invalid_credentials'
```

A successful sign-in also calls the `onAuthStateChanged` listeners, so you can update the page in one place.

A complete example is the demo's [custom login page](../demo/custom.html) ([`src/custom.ts`](../demo/src/custom.ts)), which is at http://localhost:3000/custom.html when the demo runs.

## E-mail & password: `Madauth.password`

Needs `new Password()` in `initialize`, and `DATABASE_URL` and `WEBHOOK_URL` on the server. Without them, the methods fail with `flow_not_enabled`.

| Method | Result | Errors |
| --- | --- | --- |
| `signIn({ email, password })` | `{ user }` | `invalid_credentials`, `email_unverified`, `too_many_attempts`; `totp_required` or `totp_setup_required` when the sign-in goes on with the [authenticator app](#authenticator-app-madauthtotp) |
| `signUp({ email, password, name?, redirectTo? })` | — | `invalid_email`, `weak_password`, `signup_rejected`, `temporarily_unavailable` |
| `sendVerificationEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `verifyEmail({ email, code })` | `{ user }` | `code_invalid`, `codes_locked`; `totp_required` or `totp_setup_required` like `signIn` |
| `sendResetEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `confirmReset({ newPassword, token? })` or `confirmReset({ newPassword, email, code })` | `{ user }` | `link_invalid`, `code_invalid`, `codes_locked`, `weak_password`; `totp_required` or `totp_setup_required` like `signIn` |
| `pendingReset` | `boolean` | True when the page was opened from a reset link |
| `policy` | `{ minLength, secondFactor } \| null` | The server's password rules, for a hint next to the field, and whether the method asks for the authenticator app (`none`, `optional`, `required`) |

`signUp`, `sendVerificationEmail` and `sendResetEmail` succeed whether or not the address has an account (or a password to reset), so nobody can probe for accounts. Tell the user to check their inbox in every case.

`too_many_attempts`, `weak_password` and `signup_rejected` come with a `message` written for the user: the wait time, the minimum length, or the reason your sign-up check gave. The first two are in English; for another language, write your own texts (`policy` has the minimum length). For the other codes, write your own texts.

`codes_locked` means that too many wrong codes were entered for this account, across e-mails: its codes no longer work until one of its e-mail links is used. Tell the user to ask for a new e-mail and to open the link in it.

`temporarily_unavailable` means the server's [webhook](server.md#webhooks) did not take over the e-mail, or did not answer the sign-up check. Show something like "E-mail & password sign-up is not available right now. Please try again later." The user's locale is sent along (`locale`), so your receiver can write the e-mail in it. See [Language](#language).

### The flows

**Sign up.** Call `signUp`, then show "check your inbox". The e-mail contains a link and a 6-digit code:
- The link opens `redirectTo` (default: the current page). When the page loads, `initialize` confirms the address and signs the user in; your `onAuthStateChanged` listener gets the user.
- For the code, show a field and call `verifyEmail({ email, code })`. This also works when the e-mail is read on another device.

**Sign in** with `signIn`. If it fails with `email_unverified`, offer to send the e-mail again with `sendVerificationEmail`.

**Forgot password.** Call `sendResetEmail`, then show "check your inbox":
- The link opens `redirectTo`. After `initialize`, `pendingReset` is true: show a new-password field and call `confirmReset({ newPassword })`.
- With the code, ask for it and the new password, and call `confirmReset({ newPassword, email, code })`.

If Google is one of your methods, say on the form that a Google user has no password to reset and should use the Google button instead, as the dialog does. (The server tells such a user the same by e-mail: `email.no_password` in [Webhooks](server.md#webhooks).)

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
| Code from the e-mail, or from the authenticator app | `one-time-code` |

## Authenticator app: `Madauth.totp`

Needs `new Totp()` in `initialize`, and the app in use on the server: as the second factor of a method whose [policy](server.md#sign-in-methods) is `optional` or `required`, or as a method of its own. Otherwise the methods fail with `flow_not_enabled` and `initialize` leaves the provider out.

| Method | Result | Errors |
| --- | --- | --- |
| `verify({ code })` or `verify({ recoveryCode })` | `{ user }` | `code_invalid`, `too_many_attempts`, `challenge_expired` |
| `startSetup()` | `{ secret, uri, qrSvg }` | `no_session` |
| `confirmSetup({ code })` | `{ recoveryCodes, user? }` | `code_invalid`, `setup_expired`, `no_session` |
| `remove({ code })` or `remove({ recoveryCode })` | — | `code_invalid`, `required_by_policy`, `no_session` |
| `newRecoveryCodes({ code })` or `newRecoveryCodes({ recoveryCode })` | `{ recoveryCodes }` | `code_invalid`, `no_authenticator`, `no_session` |
| `status()` | `{ enabled, recoveryCodesLeft }` | `no_session` |
| `signIn({ email, code })` or `signIn({ email, recoveryCode })` | `{ user }` | `invalid_credentials`, `too_many_attempts`, `method_disabled` |
| `signUp({ email, name?, redirectTo? })` | — | `invalid_email`, `signup_rejected`, `temporarily_unavailable`, `method_disabled` |
| `sendVerificationEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `verifyEmail({ email, code })` | `{ user }` | `code_invalid`, `codes_locked`; `totp_setup_required` for a sign-up with the app |
| `pendingStep` | `{ step: 'code' \| 'setup', method } \| null` | What a sign-in under way still needs, e.g. after the redirect flow or an e-mail link |
| `policy` | `{ signIn, signUp, secondFactorFor } \| null` | What the app does on this server: whether it signs in on its own, whether people can sign up with it, and which methods ask for it |

### The second step

When the policy of Google or password asks for the app, `password.signIn` (also `verifyEmail` and `confirmReset`) and the Google button's `onResult` end with `totp_required` instead of a user: the password was right, and the sign-in goes on. Ask for the code from the app (or a recovery code) and call `verify`; the user arrives through `onAuthStateChanged`. With `totp_setup_required` the user has no app yet and the policy requires one: run the setup below; `confirmSetup` then signs them in and returns `user` as well. A step older than ten minutes fails with `challenge_expired`: start the sign-in over.

A sign-in that started outside your screen, i.e. the redirect flow (`#madauth_next=…`) or the link in a confirmation e-mail, leaves its step in `pendingStep` after `initialize`: show the matching form.

```ts
const result = await Madauth.password.signIn({ email, password });
if (!result.isSuccess && result.error.code === 'totp_required') showCodeForm();
if (!result.isSuccess && result.error.code === 'totp_setup_required') showSetup();

codeForm.onsubmit = async () => {
  const done = await Madauth.totp.verify({ code: codeInput.value }); // or { recoveryCode }
  if (!done.isSuccess) showError(done.error);
};
```

### Setting the app up

While the user is signed in (whichever way), or in the setup step of a sign-in, call `startSetup()`: it returns the key as `secret` (base32, to type into the app), `uri` (`otpauth://totp/...`) and `qrSvg`, the QR code of the URI as an SVG string. Put `qrSvg` into the page with `innerHTML`; it draws the dark modules in `currentColor` with no background, so give the container a white background and a size. Then ask for the first code the app shows and call `confirmSetup({ code })` within ten minutes; after that it fails with `setup_expired`, and you start again. Show the `recoveryCodes` it returns once, and tell the user to save them. Say on the screen what the app will do (`policy`): that signing in with the password or Google then asks for a code, and whether the app signs in on its own.

```ts
const setup = await Madauth.totp.startSetup();
if (setup.isSuccess) {
  qrContainer.innerHTML = setup.qrSvg;
  keyElement.textContent = setup.secret;
}
confirmForm.onsubmit = async () => {
  const done = await Madauth.totp.confirmSetup({ code: codeInput.value });
  if (done.isSuccess) showRecoveryCodes(done.recoveryCodes);
};
```

`status()` says whether the signed-in user has the app; `remove` and `newRecoveryCodes` take a current code from it or a recovery code. `Madauth.deleteAccount({ code })` needs one as well once the app is set up.

### The app on its own

When the server lists the app as a method (`policy.signIn`), `signIn({ email, code })` signs in with the address and a code from the app, with `invalid_credentials` for an unknown address, one without the app and a wrong code alike. With `policy.signUp`, `signUp({ email, name? })` creates an account that signs in with the app alone: it sends the confirmation e-mail, `verifyEmail` (or the link) ends with `totp_setup_required`, and the setup above signs the new user in.

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
- With `GoogleRedirect`, it renders a "Continue with Google" button in Google's colors that starts the redirect. The result arrives through `onAuthStateChanged` after the return. The button is labelled in English or German, see [Language](#language).

You can call `renderButton` before `initialize` has finished. The button appears as soon as madAuth is ready.

One Tap (`GoogleFedcm` with its default `autoPrompt: true`) works on custom screens as well.

## Language

Pass `locale` to `initialize` to tell madAuth the language of your screen, and call `Madauth.setLocale` when the user switches it:

```ts
Madauth.initialize({ providers: [new Password()], ui: 'custom', locale: 'de' }); // or e.g. 'de-CH'
Madauth.setLocale('en');
```

Without a locale, madAuth uses the page's `<html lang>`, then the browser's language.

The locale is used for:
- **The e-mails.** `signUp`, `sendVerificationEmail` and `sendResetEmail` send it to the server, which passes it to your [webhook](server.md#webhooks) and your sign-up check.
- **The `GoogleRedirect` button.** It says "Weiter mit Google" for a German locale and "Continue with Google" for every other. `setLocale` also changes a button that is already on the page.
- **The `message` of a failed `GoogleRedirect` sign-in**, which `initialize` returns. It is German for a German locale, English otherwise.

## Signing out and the session

These work the same with or without the dialog: `Madauth.signOut()`, `Madauth.deleteAccount()` (with `{ code }` once the authenticator app is set up), `Madauth.getSession()`, `Madauth.sessionReady()`, `Madauth.currentUser` (with `amr`, how the session was authenticated), `Madauth.onAuthStateChanged(listener)` and, for admins, `Madauth.admin`. See the [README](../README.md#using-madauth-in-your-app).
