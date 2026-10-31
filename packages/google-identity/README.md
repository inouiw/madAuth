# @madauth/google-identity

Get a Google ID token in the browser, and nothing else: the browser's own "Continue as …" dialog ([FedCM](https://developers.google.com/privacy-sandbox/cookies/fedcm)) where the browser has it, [Google One Tap](https://developers.google.com/identity/gsi/web/guides/features) and [Google's sign-in button](https://developers.google.com/identity/gsi/web/guides/display-button) otherwise. No backend, no framework, no dependencies: about 2 kB gzipped.

What you do with the token is up to you: send it to your own server, or to a [madAuth](https://github.com/inouiw/madAuth) server, which verifies it and signs the user in. [`@madauth/web`](https://www.npmjs.com/package/@madauth/web) builds its `GoogleFedcm` provider on this package, and so does the web target of [capacitor-native-google-one-tap-signin](https://github.com/inouiw/capacitor-native-google-one-tap-signin).

## Install

```bash
npm install @madauth/google-identity
```

You need an OAuth client ID of type **Web application** from the [Google Cloud console](https://console.cloud.google.com/apis/credentials), with your page's origin under *Authorized JavaScript origins*.

## Usage

### One Tap

```ts
import { signIn } from '@madauth/google-identity';

const result = await signIn({ clientId: 'xxx.apps.googleusercontent.com', nonce });

if (result.isSuccess) {
  // result.idToken is a JWT for your client ID, with `nonce` in its nonce claim. Verify it on your server.
} else if (result.reason !== 'cancelled' && result.reason !== 'skipped') {
  console.error('Google sign-in failed:', result.reason, result.detail);
}
```

In Chrome and other browsers with FedCM, this is the browser's own dialog, and Google's script is never loaded. Elsewhere, the script is loaded on first use and shows One Tap in the page's top right corner. `signIn` resolves once and never rejects.

Sign a returning user in silently with `autoSelect: true`: the browser picks the account that signed in last, if there is one, and the user sees only a short "Signing in as …". A common pattern is to try that first and show the prompt when it doesn't work:

```ts
let result = await signIn({ clientId, nonce, autoSelect: true });
if (!result.isSuccess && result.reason !== 'cancelled') {
  result = await signIn({ clientId, nonce: await freshNonce() });
}
```

### The nonce

Google puts `nonce` into the token unchanged. Your server should generate one per sign-in, remember it, and refuse a token with another one, so that a token can't be replayed. Get a new nonce for each attempt: a token your server has seen is used up.

### Google's button

```ts
import { renderButton } from '@madauth/google-identity';

const rendered = await renderButton(document.getElementById('google-button'), {
  clientId,
  nonce,
  onCredential: ({ idToken }) => verifyOnYourServer(idToken),
  button: { theme: 'filled_black', text: 'continue_with', width: 300 },
});
```

Google draws the button; `button` takes its [configuration](https://developers.google.com/identity/gsi/web/reference/js-reference#GsiButtonConfiguration). The button comes in an iframe with a light page, so it is wrapped in an element with `color-scheme: light`: on a dark page, it would be painted on an opaque white box otherwise. `rendered.remove()` takes it off the page again. `onCredential` is called for every sign-in through the button; after a token your server refused, render the button again with a new nonce.

### Cancel, sign out, disconnect

```ts
import { cancel, disableAutoSelect, revoke } from '@madauth/google-identity';

cancel();                       // closes the dialog or One Tap: the pending signIn resolves with `cancelled`
disableAutoSelect();            // after a sign-out: the next signIn asks again instead of auto-selecting
await revoke(idTokenClaims.sub); // the user disconnects the app from their Google account
```

### Results

`signIn` resolves with `{ isSuccess: true, idToken, isAutoSelected }` or `{ isSuccess: false, reason, detail? }`:

| `reason`              | Meaning                                                                                                                                              |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cancelled`           | `cancel()` was called, the `signal` aborted, the browser aborted the request, or the user closed its dialog.                                           |
| `skipped`             | The prompt was not shown, or closed without a choice: Chrome's cooldown after dismissals, no Google session in the browser, a user who opted out, …  |
| `configuration_error` | The client ID is missing, or the page's origin is not among its authorized JavaScript origins.                                                       |
| `load_failed`         | Google's script could not be loaded (offline, a content blocker).                                                                                    |
| `error`               | Anything else; `detail` names it.                                                                                                                    |

`cancelled` and `skipped` are the user's choice or the browser's: show nothing, or your own button.

## Things to know

- **One configuration at a time.** Google's script holds a single configuration (client ID, nonce, callback): a `signIn` or `renderButton` started later takes over. Don't run One Tap and a button with different nonces at once; call `cancel()` before rendering the button.
- **Chrome's cooldown.** After the user closes One Tap a few times, Chrome stops showing it for a while, and `signIn` resolves with `skipped`. The button keeps working; it is the way back in.
- **FedCM needs a secure context** (`https://`, or `localhost`), like most browser credential APIs. Without one, the script path is used.
- **The script is loaded once**, and only when needed: never for the browser's dialog. If the page has `google.accounts.id` already, it is used as is. `loadGis()` loads it ahead of time, e.g. so the button appears at once.
- **Server-side flows are not here.** Google's authorization-code flow (a redirect to Google and back to your server) has no Google code in the browser. madAuth's `GoogleRedirect` does that.

## API

| Function                              | What it does                                                                                                                      |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `signIn(options)`                     | The browser's dialog or One Tap. `clientId`, `nonce`; `autoSelect`, `context` (`signin`, `signup`, `use`), `signal`, `fedcm: false` to always use the script, `cancelOnTapOutside`. |
| `renderButton(container, options)`    | Google's button. `clientId`, `nonce`, `onCredential`; `context`, `button`, `uxMode` and `loginUri` for Google's redirect mode. Resolves with `remove()`, or with `load_failed` or `error`. |
| `cancel()`                            | Ends the sign-in under way.                                                                                                        |
| `disableAutoSelect()`                 | The next sign-in asks instead of auto-selecting; it loads nothing, Google's script is told only if it has loaded.                |
| `revoke(hint)`                        | Revokes the app's grant at Google, by e-mail address or account id.                                                                |
| `isFedcmSupported()`                  | Whether the browser has the FedCM API.                                                                                             |
| `loadGis()`                           | Loads Google's script and resolves with `google.accounts.id`; rejects when it can't be loaded, and a later call tries again.       |

Types: `CredentialResult`, `GoogleCredential`, `NoCredential`, `NoCredentialReason`, `SignInOptions`, `ButtonOptions`, `RenderedButton`, `GsiButtonConfiguration`, `GoogleAccountsId`, `IdConfiguration`, `PromptMomentNotification`, `CredentialResponse`.

## License

MIT
