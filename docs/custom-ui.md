# Building your own login screen

madAuth's dialog (`Madauth.showSignInDialog()`) is optional. Everything it does is available as methods, grouped by sign-in method, so you can build a login screen that fits your app. The dialog itself is built only on these methods.

```ts
import { Madauth, GoogleFedcm, GitHub, Password, Passkey, Authenticator, EmailLink } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm(), new GitHub(), new Password(), new Passkey(), new Authenticator(), new EmailLink()], ui: 'custom' });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
```

`ui: 'custom'` tells madAuth that the page shows its own screen: the dialog never opens by itself, and `Madauth.showSignInDialog()`, `Madauth.showSetUpAuthenticatorDialog()`, `Madauth.showSetUpSmsDialog()`, `Madauth.showSetUpPasskeyDialog()`, `Madauth.showManageSignInMethodsDialog()`, `Madauth.showManageApiKeysDialog()` and `Madauth.showAdminDialog()` return an `invalid_options` error: the calls whose name starts with `show` and ends in `Dialog` open madAuth's dialog, the others only talk to the server.

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
| `signIn({ email, password })` | `{ user }` | `invalid_credentials`, `email_unverified`, `too_many_attempts`; `passkey_required`, `authenticator_required`, `sms_required` or `second_factor_setup_required` when the sign-in goes on with a [second factor](#the-second-step) |
| `signUp({ email, password, name?, redirectTo? })` | — | `invalid_email`, `weak_password`, `signup_rejected`, `temporarily_unavailable` |
| `sendVerificationEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `verifyEmail({ email, code })` | `{ user }` | `code_invalid`, `codes_locked`; `authenticator_required` or `second_factor_setup_required` like `signIn` |
| `sendResetEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `confirmReset({ newPassword, token? })` or `confirmReset({ newPassword, email, code })` | `{ user }` | `link_invalid`, `code_invalid`, `codes_locked`, `weak_password`; `authenticator_required` or `second_factor_setup_required` like `signIn` |
| `pendingReset` | `boolean` | True when the page was opened from a reset link |
| `add({ password })` | — | Adds a password to the signed-in user's [methods](#a-users-sign-in-methods-madauthmethods): `weak_password`, `already_added`, `reauth_required`, `no_session` |
| `policy` | `{ minLength, minScore, secondFactor } \| null` | The server's [password rules](server.md#password-rules), for a hint next to the field, and whether the method asks for a second factor (`none`, `optional`, `required`) |
| `loadRating()` | `(password, userInputs?) => number` | For a strength meter: loads the rating the server uses for `minScore` and resolves to a function that rates a password from 0 to 4. Pass the user's name and e-mail address as `userInputs`, as the server does. It downloads zxcvbn-ts (about 220 kB compressed) on the first call, so call it when the password field is shown or first typed in. |

`signUp`, `sendVerificationEmail` and `sendResetEmail` succeed whether or not the address has an account (or a password to reset), so nobody can probe for accounts. Tell the user to check their inbox in every case.

`too_many_attempts`, `weak_password` and `signup_rejected` come with a `message` written for the user: the wait time, which password rule was broken, or the reason your sign-up check gave. The first two are in English; for another language, write your own texts: a `weak_password` error has `error.minLength` when the password is too short and `error.minScore` when it is too easy to guess. For the other codes, write your own texts.

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

If Google or GitHub is one of your methods, say on the form that such a user has no password to reset and should use that button instead, as the dialog does. (The server tells such a user the same by e-mail: `email.send_password_reset_no_password` in [Webhooks](server.md#webhooks).)

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
| E-mail, next to a password | `username` (with `type="email"`: password managers save and fill it together with the password) |
| E-mail without a password (e-mail link, forgot password, authenticator app) | `email` |
| Password when signing in | `current-password` |
| Password when signing up or resetting | `new-password` |
| Code from the e-mail, or from an SMS | `one-time-code` |
| Code from the authenticator app, or a recovery code | `off` |
| Phone number | `tel` |

`one-time-code` lets Safari and iOS fill the code from Mail or Messages, and lets password managers offer a stored authenticator code. The iCloud Passwords extension for Chrome, though, opens its panel on every such field even with nothing stored for the site, so the dialog uses `off` for the authenticator code and keeps `one-time-code` for the e-mail and SMS codes, where the panel still appears in Chrome. The dialog's [`code-autocomplete` attribute](styling.md#attributes) switches the authenticator fields to `one-time-code`. The extension does the same on a `username` field, which is why an address field without a password gets `email`.

## E-mail link: `Madauth.emailLink`

Needs `new EmailLink()` in `initialize`, and on the server a webhook that sends `email.send_signin_link` with the method listed by an admin. Otherwise the provider is left out with a warning and the methods fail with `flow_not_enabled`.

| Method | Result | Errors |
| --- | --- | --- |
| `send({ email, redirectTo? })` | — | `invalid_email`, `signup_rejected`, `method_disabled`, `temporarily_unavailable` |
| `verify({ email, code })` | `{ user }` | `code_invalid`, `codes_locked`, `method_disabled`; `passkey_required`, `authenticator_required`, `sms_required` or `second_factor_setup_required` when the sign-in goes on with a [second factor](#the-second-step) |
| `add()` | — | Adds the e-mail link to the signed-in user's [methods](#a-users-sign-in-methods-madauthmethods): `already_added`, `reauth_required`, `no_session` |
| `policy` | `{ secondFactor } \| null` | Whether the method asks for a second factor (`none`, `optional`, `required`); null when the server doesn't offer the method |

`send` succeeds for every address: an unknown one is signed up on first use (your [sign-up check](server.md#webhooks) permitting, `signup_rejected` otherwise), and the owner of an address that signs in another way, e.g. with a password, gets an e-mail that says so instead of a link. Tell the user to check their inbox in every case.

### The flows

Call `send`, then show "check your inbox". The e-mail contains a link and a 6-digit code, both good for 15 minutes:
- The link opens `redirectTo` (default: the current page, see [`redirectTo`](#redirectto)). When the page loads, `initialize` signs the user in; your `onAuthStateChanged` listener gets the user, with `amr: ['email']`.
- For the code, show a field and call `verify({ email, code })`. This also works when the e-mail is read on another device.

With a policy that asks for a second factor, both end with `passkey_required`, `authenticator_required`, `sms_required` or `second_factor_setup_required` instead, like a password: see [The second step](#the-second-step). After the link, the step is in `Madauth.authenticator.pendingStep` once `initialize` is done.

```ts
sendForm.onsubmit = async () => {
  const result = await Madauth.emailLink.send({ email: emailInput.value });
  if (result.isSuccess) showCheckInbox();
};
codeForm.onsubmit = async () => {
  const result = await Madauth.emailLink.verify({ email: emailInput.value, code: codeInput.value });
  if (!result.isSuccess) showError(result.error);
};
```

To handle the link yourself, e.g. in a native app, read the token from the URL's hash (`#madauth_signin=<token>`) and post it to `/auth/email-link/verify` (see the [HTTP API](server.md#http-api)).

## Authenticator app: `Madauth.authenticator`

The methods work whenever the app is in use on the server: as the second factor of a method whose [policy](server.md#sign-in-methods) is `optional` or `required`, or as a method of its own; otherwise they fail with `flow_not_enabled`. `signIn` and `signUp`, the app on its own, also need `new Authenticator()` in `initialize`, which is left out with a warning when the server does not let the app sign in on its own; the second step and the account methods need no provider, so an admin's policy applies to every app. A sign-in that reaches the second step signs out whoever was signed in (`onAuthStateChanged` gets `null`) until the step is done.

| Method | Result | Errors |
| --- | --- | --- |
| `verify({ code })` or `verify({ recoveryCode })` | `{ user }` | `code_invalid`, `too_many_attempts`, `challenge_expired` |
| `startSetup()`, or `startSetup({ code })` / `startSetup({ recoveryCode })` when the user has an app already | `{ secret, uri, qrSvg }` | `no_session`; `code_required` (an app exists: give a code from it), `code_invalid` |
| `confirmSetup({ code })` | `{ recoveryCodes, user? }` | `code_invalid`, `setup_expired`, `no_session` |
| `remove({ code })` or `remove({ recoveryCode })` | — | `code_invalid`, `required_by_policy`, `only_method` (the app is the user's last way to sign in; offer adding another method), `no_session` |
| `newRecoveryCodes({ code })` or `newRecoveryCodes({ recoveryCode })` | `{ recoveryCodes }` | `code_invalid`, `no_authenticator`, `no_session` |
| `status()` | `{ enabled, recoveryCodesLeft }` | `no_session` |
| `signIn({ email, code })` or `signIn({ email, recoveryCode })` | `{ user }` | `invalid_credentials`, `too_many_attempts`, `method_disabled` |
| `signUp({ email, name?, redirectTo? })` | — | `invalid_email`, `signup_rejected`, `temporarily_unavailable`, `method_disabled` |
| `sendVerificationEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `verifyEmail({ email, code })` | `{ user }` | `code_invalid`, `codes_locked`; `authenticator_setup_required` for a sign-up with the app |
| `pendingStep` | `{ step: 'passkey' \| 'code' \| 'sms' \| 'setup', method, factors? } \| null` | What a sign-in under way still needs, e.g. after the redirect flow or a link from an e-mail; `method` is the method whose sign-in it is (`google`, `github`, `password`, `authenticator`, `email-link` or `passkey`), `factors` which second factors can finish it (`passkey`, `authenticator`, `sms`), or for `setup` which can be set up |
| `policy` | `{ signIn, signUp, secondFactorFor } \| null` | What the app does on this server: whether it signs in on its own (for every user who has one), whether people can sign up with it, and which methods ask for a second factor |

### The second step

When the policy of a method asks for a second factor, `password.signIn` (also `verifyEmail` and `confirmReset`), `emailLink.verify`, `passkey.signIn` and the Google button's `onResult` end with `authenticator_required` instead of a user: the first step was right, and the sign-in goes on. Ask for the code from the app (or a recovery code) and call `verify`; the user arrives through `onAuthStateChanged`. The error's `factors` says what the user can finish with: with `sms` among them (they have a phone as well, see [SMS codes](#sms-codes-madauthsms)), offer "send a code by SMS instead"; with `passkey`, "use a passkey instead". With `passkey_required` the user has a passkey, which comes first: a button that calls `Madauth.passkey.verify()` (the browser's dialog needs the user's click). With `sms_required` the user has a phone and nothing else: the SMS step. With `second_factor_setup_required` the user has no factor yet and the policy requires one, and `factors` says which they can choose to set up: the app (the setup below), a phone (when `Madauth.sms.available`) or a passkey (`Madauth.passkey.add()`); each signs them in once it is set up and returns `user` as well. (`authenticator_setup_required` is the sign-up with the app alone, which sets up the app and nothing else, see [The app on its own](#the-app-on-its-own).) A step older than ten minutes fails with `challenge_expired`: start the sign-in over.

A sign-in that started outside your screen, i.e. the redirect flow (`#madauth_next=…`) or the link in a confirmation or sign-in e-mail, leaves its step in `pendingStep` after `initialize`: show the matching form.

```ts
const result = await Madauth.password.signIn({ email, password });
if (!result.isSuccess && result.error.code === 'authenticator_required') showCodeForm();
if (!result.isSuccess && result.error.code === 'second_factor_setup_required') showSetup();

codeForm.onsubmit = async () => {
  const done = await Madauth.authenticator.verify({ code: codeInput.value }); // or { recoveryCode }
  if (!done.isSuccess) showError(done.error);
};
```

### Setting the app up

While the user is signed in (whichever way), or in the setup step of a sign-in, call `startSetup()`: it returns the key as `secret` (base32, to type into the app), `uri` (`otpauth://totp/...`) and `qrSvg`, the QR code of the URI as an SVG string. Put `qrSvg` into the page with `innerHTML`; it draws the dark modules in `currentColor` with no background, so give the container a white background and a size. Then ask for the first code the app shows and call `confirmSetup({ code })` within ten minutes; after that it fails with `setup_expired`, and you start again. Show the `recoveryCodes` it returns once, and tell the user to save them. Say on the screen what the app will do (`policy`): that signing in with the password, Google or GitHub then asks for a code, and whether the app signs in on its own. A user who has an app already replaces it: `startSetup()` then fails with `code_required`, so ask for a current code from the old app (or a recovery code) and call `startSetup({ code })`.

```ts
const setup = await Madauth.authenticator.startSetup();
if (setup.isSuccess) {
  qrContainer.innerHTML = setup.qrSvg;
  keyElement.textContent = setup.secret;
}
confirmForm.onsubmit = async () => {
  const done = await Madauth.authenticator.confirmSetup({ code: codeInput.value });
  if (done.isSuccess) showRecoveryCodes(done.recoveryCodes);
};
```

`status()` says whether the signed-in user has the app; `remove` and `newRecoveryCodes` take a current code from it or a recovery code. `Madauth.deleteAccount({ code })` needs one as well once the app is set up.

## SMS codes: `Madauth.sms`

A second factor next to the app, never a sign-in on its own. The methods work whenever the server has SMS codes on (`sms` in the [sign-in methods](server.md#sign-in-methods), with a webhook that sends `sms.send_code`); otherwise they fail with `flow_not_enabled`, and `available` is false. No provider is needed.

| Method | Result | Errors |
| --- | --- | --- |
| `setUp({ phone, code? })` | `{ phone }` (masked) | `invalid_phone`, `code_required` (a number exists: give a code sent to it), `code_invalid`, `too_soon`, `no_session`, `temporarily_unavailable` |
| `confirmSetup({ code })` | `{ user? }` | `code_invalid`, `setup_expired`, `no_session` |
| `send()` | `{ phone }` (masked) | `too_soon`, `no_phone`, `challenge_expired`, `no_session` |
| `verify({ code })` | `{ user }` | `code_invalid`, `too_many_attempts`, `challenge_expired` |
| `remove({ code })` | — | `code_invalid`, `no_phone`, `required_by_policy` (a policy requires a second factor and the user has no other one), `no_session` |
| `status()` | `{ enabled, phone }` | `no_session` |
| `pendingStep` | like `Madauth.authenticator.pendingStep` | `step: 'sms'` when a code by SMS is next |
| `available` | `boolean` | Whether the server has SMS codes on |

### The second step

After `sms_required` (or `authenticator_required` with `sms` in `factors`, when the user chooses the SMS), call `send()` once: the server sends the code and the result says where (masked), so you can show "we sent a code to +41 ••••••• 67". Then ask for the code and call `verify`; the user arrives through `onAuthStateChanged`. `send` again sends a new code, but only once a minute (`too_soon`: the previous code still works).

```ts
const result = await Madauth.password.signIn({ email, password });
if (!result.isSuccess && result.error.code === 'sms_required') {
  const sent = await Madauth.sms.send();
  if (sent.isSuccess) showSmsCodeForm(sent.phone);
}
smsForm.onsubmit = async () => {
  const done = await Madauth.sms.verify({ code: codeInput.value });
  if (!done.isSuccess) showError(done.error);
};
```

### Adding a phone

While the user is signed in, or in the setup step of a sign-in (`second_factor_setup_required` with `Madauth.sms.available`), call `setUp({ phone })` with the number in international form: the server sends a code to it and returns the masked number. Ask for the code and call `confirmSetup({ code })` within ten minutes; it returns `user` when the setup finished a sign-in. A user who has a number already replaces it: `setUp` then fails with `code_required`, so call `send()` (a code to the current number), ask for it, and call `setUp({ phone, code })`. `remove({ code })` takes a code from `send()` as well. Use `autocomplete="tel"` for the number field.

```ts
const setup = await Madauth.sms.setUp({ phone: phoneInput.value });
if (setup.isSuccess) showCodeForm(setup.phone);
confirmForm.onsubmit = async () => {
  const done = await Madauth.sms.confirmSetup({ code: codeInput.value });
  if (done.isSuccess) showPhoneAdded();
};
```

### The app on its own

When the server allows the app as a sign-in method (`policy.signIn`), `signIn({ email, code })` signs in with the address and a code from the app, for every user who has one, with `invalid_credentials` for an unknown address, one without the app and a wrong code alike. With `policy.signUp`, `signUp({ email, name? })` creates an account that signs in with the app alone: it sends the confirmation e-mail, `verifyEmail` (or the link) ends with `authenticator_setup_required`, and the setup above signs the new user in.

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

With `purpose: 'link'`, the button adds a Google account to the signed-in user's [methods](#a-users-sign-in-methods-madauthmethods) instead of signing in: with `GoogleFedcm`, `onResult` gets the user as they are, or `account_taken` (the Google account signs in another user) or `reauth_required`; with `GoogleRedirect`, the page comes back with `linked: 'google'` in the result of `Madauth.initialize`, or with the error. The button says "Connect Google" for the redirect; Google's own button keeps its text.

## GitHub: `Madauth.github`

Needs `new GitHub()` in `initialize`.

```ts
const result = Madauth.github.renderButton(document.querySelector('#github-button')!, {
  theme: 'auto', // or 'light' / 'dark'; 'auto' follows the container's color-scheme
});
// Later, e.g. when the screen closes:
if (result.isSuccess) result.remove();
```

With `purpose: 'link'` it says "Connect GitHub" and adds GitHub to the signed-in user's methods, like Google's: the page comes back with `linked: 'github'` in the result of `Madauth.initialize`. It renders a "Continue with GitHub" button (GitHub's mark, black on white or white on dark) that starts the server's redirect flow: the browser goes to GitHub and comes back to the page, without its hash. The user then arrives through `onAuthStateChanged`. A sign-in that failed is returned by `initialize` (e.g. `cancelled`, `email_unverified` for a GitHub account without a verified address, `other_method` when the address signs in another way), and one that goes on with a second factor is in `Madauth.authenticator.pendingStep` with `method: 'github'`. The button is labelled in English or German, see [Language](#language).

## Any provider: `Madauth.provider(id)`

Every provider the server offers, by its id: the [OpenID Connect providers](server.md#openid-connect-provider-setup) an admin added (e.g. `gitlab`), and Google and GitHub too. madAuth registers them by itself, so `initialize` needs nothing for them (Google's One Tap aside: `new GoogleFedcm()`).

```ts
const result = Madauth.provider('gitlab').renderButton(document.querySelector('#gitlab-button')!, { theme: 'auto' });
// Or, from a button of your own:
await Madauth.provider('gitlab').signIn(); // the browser goes to the provider and back
```

- `renderButton(container, options?)` renders a "Continue with <name>" button, with the name an admin gave the provider, in the dialog's colours with a neutral sign-in mark (nothing is loaded from the provider). Google's and GitHub's buttons are the ones of `Madauth.google` and `Madauth.github`. It takes the same options, and can be called before `initialize` has finished: when the server turns out not to offer the provider, `onResult` gets `flow_not_enabled`.
- `signIn({ purpose? })` starts the redirect without a button of madAuth's. It fails with `flow_not_enabled` when the server doesn't offer the provider, or when it signs in without a redirect here (Google with `GoogleFedcm`).
- Like GitHub's, the result arrives after the return: the user through `onAuthStateChanged`, a failure (e.g. `cancelled`, `email_unverified`, `other_method`) from `initialize`, a second step in `Madauth.authenticator.pendingStep` with the provider's id as `method`. With `purpose: 'link'` it adds the provider to the signed-in user's methods, and the page comes back with `linked: '<id>'`.

The ids the server offers, with their names, are in `GET /auth/config` (`providers`). The method of an OpenID Connect provider is its id: in `amr`, in the user's [methods](#a-users-sign-in-methods-madauthmethods) and in the TypeScript type `LoginMethodId`, which is any string besides madAuth's own ids (`BuiltInMethodId`).

## Passkeys: `Madauth.passkey`

Signing in or up with a passkey alone needs `new Passkey()` in `initialize` and a server that allows it; the second step, adding and renaming work whenever the server has passkeys on (`available`).

| Method | Resolves to | Errors |
| --- | --- | --- |
| `signIn()` or `signIn({ conditional: true, signal })` | `{ user }` | `cancelled` (the user closed the browser's dialog), `passkey_unknown`, `verification_failed`, `method_disabled`, `passkey_unsupported`; the [second step](#the-second-step) when the passkey's policy asks for one |
| `verify()` | `{ user }` | Finishes a sign-in that ended with `passkey_required`: `cancelled`, `verification_failed`, `challenge_expired` |
| `add({ name? })` | `{ passkey, user? }` | Adds a passkey for the signed-in user, or as the setup of a sign-in (`second_factor_setup_required` with `passkey` in `factors`) or of a sign-up with a passkey (`passkey_setup_required`); then it signs in (`user`): `cancelled`, `already_added`, `reauth_required`, `verification_failed`, `no_session`, `setup_expired`, `passkey_unsupported`; in a sign-up whose policy asks for a second factor, `second_factor_setup_required` (the passkey is created, set the factor up next) |
| `signUp({ email, name?, redirectTo? })` | — | `invalid_email`, `signup_rejected`, `temporarily_unavailable`, `method_disabled`, `forbidden_origin`; `flow_not_enabled` without `policy.signUp` or the Passkey provider (which is left out in a browser without passkeys) |
| `sendVerificationEmail({ email, redirectTo? })` | — | `invalid_email`, `temporarily_unavailable` |
| `verifyEmail({ email, code })` | `{ user }` | `code_invalid`, `codes_locked`; `passkey_setup_required` for a sign-up with a passkey |
| `rename({ id, name })` | `{ passkey }` | `method_not_found`, `invalid_options`, `no_session` |
| `conditionalAvailable()` | `boolean` | Whether the browser offers passkeys in an e-mail field's autofill |
| `available`, `signInAvailable` | `boolean` | Whether passkeys are on here (server and browser), and whether they sign in on their own here |
| `policy` | `{ signIn, signUp, secondFactor } \| null` | What passkeys do on this server: whether they sign in on their own, whether people can sign up with one alone, and whether such a sign-in asks for a second factor |

A passkey button calls `signIn()`. For the autofill, give the e-mail field `autocomplete="username webauthn"` and start `signIn({ conditional: true, signal })` when the screen shows: the browser offers the user's passkeys in the field's suggestions, and the call resolves when the user picks one. Abort it (`signal`) before another sign-in starts, and when the screen goes. `cancelled` is no error to show: the user closed the dialog.

### Signing up with a passkey alone

With `policy.signUp`, `signUp({ email, name? })` creates an account that signs in with a passkey alone, like the [app on its own](#the-app-on-its-own): it sends the confirmation e-mail, and `verifyEmail` (or the link, after which the step is in `pendingStep` once `initialize` is done) ends with `passkey_setup_required` (`pendingStep` is `{ step: 'setup', method: 'passkey', factors: ['passkey'] }`). Show a "Create passkey" button that calls `add()`: the browser's dialog needs the user's click. The new passkey signs the user in; with a policy that asks for a second factor after a passkey, `add()` ends with `second_factor_setup_required` again, with the factors to set up next. A user without another method who loses their passkeys signs up again once an admin [reset their sign-in](server.md#resetting-a-users-sign-in): see [Passkey security](passkey-security.md#signing-up-with-a-passkey).

## A user's sign-in methods: `Madauth.methods`

| Method | Resolves to | Errors |
| --- | --- | --- |
| `list()` | `{ methods: [{ id, method, signIn, removable, createdAt, email?, name?, lastUsedAt? }] }` | `no_session` |
| `remove(id)` | — | `only_method` (the user's last way in), `required_by_policy`, `reauth_required`, `method_not_found`, `no_session` |

A user adds a method with its own call: `Madauth.passkey.add()`, `Madauth.password.add({ password })`, `Madauth.emailLink.add()`, a provider's button with `purpose: 'link'` (Google, GitHub, `Madauth.provider(id)`), or the app's setup. Adding and removing need a sign-in within the last ten minutes: otherwise they fail with `reauth_required`, and the user signs in again first. The authenticator app is removed with `Madauth.authenticator.remove`, which takes a code. See [Several sign-in methods](sign-in-methods.md).

## API keys: `Madauth.apiKeys`

A user's keys for programs that call your API, or madAuth's admin API, in their name. See [API keys](api-keys.md).

| Method | Resolves to | Errors |
| --- | --- | --- |
| `scopes()` | `{ scopes: [{ name, description, role, endpoints, allowed }] }`: madAuth's and your app's scopes; `allowed` says whether the signed-in user may give a key the scope, by their claims as stored | |
| `list()` | `{ apiKeys: [{ id, name, scopes, createdAt, expiresAt, lastUsedAt }] }` | `no_session` |
| `create({ name, scopes, expiresAt? })` | `{ key, apiKey }`: show `key` to the user to copy, it is never shown again | `invalid_options`, `invalid_scopes`, `scope_not_allowed`, `too_many_api_keys`, `reauth_required`, `temporarily_unavailable`, `no_session` |
| `revoke(id)` | — | `api_key_not_found`, `no_session` |

Making a key needs a sign-in within the last ten minutes, like adding a sign-in method: otherwise it fails with `reauth_required`, and the user signs in again first. Offer only the scopes with `allowed`; the server refuses the others. `Madauth.admin.listApiKeys(email)` and `revokeApiKey(email, id)` let an admin revoke a user's key.

## Language

Pass `locale` to `initialize` to tell madAuth the language of your screen, and call `Madauth.setLocale` when the user switches it:

```ts
Madauth.initialize({ providers: [new Password()], ui: 'custom', locale: 'de' }); // or e.g. 'de-CH'
Madauth.setLocale('en');
```

Without a locale, madAuth uses the page's `<html lang>`, then the browser's language.

The locale is used for:
- **The e-mails.** `signUp`, `sendVerificationEmail`, `sendResetEmail` and `emailLink.send` send it to the server, which passes it to your [webhook](server.md#webhooks) and your sign-up check.
- **The `GoogleRedirect` and `GitHub` buttons.** They say "Weiter mit Google" / "Weiter mit GitHub" for a German locale and "Continue with Google" / "Continue with GitHub" for every other. `setLocale` also changes a button that is already on the page.
- **The `message` of a failed redirect sign-in** (`GoogleRedirect`, `GitHub`), which `initialize` returns. It is German for a German locale, English otherwise.

## Signing out and the session

These work the same with or without the dialog: `Madauth.signOut()`, `Madauth.deleteAccount()` (with `{ code }` once the authenticator app is set up; a phone alone asks for none), `Madauth.getSession()`, `Madauth.sessionReady()`, `Madauth.currentUser` (with `amr`, how the session was authenticated), `Madauth.onAuthStateChanged(listener)` and, for admins, `Madauth.admin`. See the [README](../README.md#using-madauth-in-your-app).
