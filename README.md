# madAuth

A self-hostable alternative to Cognito / Auth0. Sign-in methods:

| Method | Status |
| --- | --- |
| Google sign-in (FedCM / One Tap, or server-side redirect) | available |
| GitHub sign-in (server-side redirect) | available |
| E-mail & password (with e-mail confirmation and password reset) | available |
| Passwordless e-mail link (a link and a code by e-mail, sign-up on first use) | available |
| Passkeys (WebAuthn): on their own (with sign-up by e-mail confirmation), in the e-mail field's autofill, and as a second factor | available |
| Authenticator app (TOTP): as a second factor, and on its own | available |
| SMS code (as a second factor) | available |

A user can have several of these: they sign up with one and add more while signed in. The admin decides which methods sign in on their own and which ask for a second factor.

Users can also make **API keys** for programs that call your API, or madAuth's admin API, in their name, each limited to scopes; your backend checks them with `createApiKeyVerifier`. See [API keys](docs/api-keys.md).

**Try it: [madauth.com/demo](https://madauth.com/demo/)** – the live demo: sign in and see the signed-in user's claims.

## Repository layout

```
packages/web     @madauth/web – sign-in client and UI as framework-agnostic web components (Lit)
packages/server  @madauth/server – the madAuth server for Docker, AWS Lambda and Azure Functions (Hono)
demo             demo page: plain HTML + TypeScript served by Vite, no framework (live at https://madauth.com/demo/)
deploy/aws       AWS CDK template to host the madAuth server: Lambda, DynamoDB, secrets in SSM
site             the madauth.com website (landing page and blog, see site/README.md) and its infrastructure (site/infra)
```

The UI ships as a standard custom element, so it works in plain HTML, React, Angular, Vue, Svelte and Capacitor apps.

## Getting started

Install dependencies:

```bash
npm install
```

Create the server's configuration from the example. It uses a Google client that already allows `http://localhost:3000`, stores e-mail & password users in `packages/server/madauth.db`, and hands e-mails to a development webhook receiver that prints them:

```bash
cp packages/server/.env.example packages/server/.env
```

Start the madAuth server. The first start prints a signing key, then a webhook secret; copy each into `packages/server/.env` (`MADAUTH_SIGNING_KEY`, `WEBHOOK_SECRET`) and start again:

```bash
npm run dev:server
```

In a second terminal, start the development receiver from the [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks) repository. The confirmation and reset e-mails appear there, with their links and codes. Get it once, next to this repository. Its `.env` (see its [README](https://github.com/inouiw/madAuth-webhooks/tree/main/dev-receiver)) is linked to `packages/server/.env`, so it always has the server's `WEBHOOK_URL` and `WEBHOOK_SECRET`:

```bash
git clone https://github.com/inouiw/madAuth-webhooks.git ../madAuth-webhooks && npm install --prefix ../madAuth-webhooks/dev-receiver && ln -s "$PWD/packages/server/.env" ../madAuth-webhooks/dev-receiver/.env
```

```bash
npm run dev --prefix ../madAuth-webhooks/dev-receiver
```

In a third terminal, start the demo at http://localhost:3000 (it proxies `/auth` to the server). The demo page switches between Google One Tap and the server-side redirect flow (which needs a Google provider with a client secret: until the first admin exists, add it with the setup token the server prints, see [First setup](docs/server.md#first-setup)), shows the signed-in user's claims, and has a button for every other call a signed-in user can make, the admin API included. http://localhost:3000/custom.html shows a custom login screen built with the same library:

```bash
npm run dev
```

The admin API needs the role `admin`, which the public demo at madauth.com gives to nobody: an admin could change every visitor's claims and switch sign-in methods off for everyone. Here you give it to yourself: set `INITIAL_ADMIN_EMAIL` in `packages/server/.env` to your address, start the server again, and sign in with that address (see [The first admin](docs/server.md#the-first-admin)).

Build the server, the library and the demo:

```bash
npm run build
```

Run the type checker and the unit tests (Vitest + happy-dom):

```bash
npm run typecheck
npm test
```

## Using madAuth in your app

madAuth has two parts: the sign-in library for your web app, and the madAuth server it talks to.

New to madAuth? [Getting started](docs/getting-started.md) walks you through both on your machine: install, create the configuration, start the server and sign up.

Install the library:

```bash
npm install @madauth/web
```

Run the server with Node. `init` asks a few questions and writes the configuration to `.env`:

```bash
npm install @madauth/server
```

```bash
npx @madauth/server init
```

```bash
npx @madauth/server start --env-file .env
```

Or with Docker (see [Running the madAuth server](docs/server.md) for the configuration and other hosting options):

```bash
docker run --rm -p 8787:8787 --env-file .env -v madauth-data:/data ghcr.io/inouiw/madauth-server
```

Then sign users in:

```ts
import { Madauth, GoogleFedcm, GitHub, Password, Passkey, Authenticator, EmailLink } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm(), new GitHub(), new Password(), new Passkey(), new Authenticator(), new EmailLink()] });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
signInButton.onclick = () => Madauth.showSignInDialog();
```

- **`initialize`** checks the server and loads the current session. You don't need to await it. Problems are logged to the console and returned as `{ isSuccess: false, error }`. A provider whose method the server doesn't offer (e.g. `GoogleRedirect` on a development server without a Google client) is left out with a warning and named in the result's `leftOut`, and the other methods work; `initialize` fails only when no method is left.
- **Google sign-in:** `new GoogleFedcm()` shows Google One Tap on page load ("Continue as …"). `Madauth.showSignInDialog()` opens the sign-in dialog with Google's button, which keeps working when Chrome holds One Tap back. For the server-side redirect flow use `new GoogleRedirect()`.
- **GitHub sign-in:** a "Continue with GitHub" button that starts the server-side redirect flow, shown by itself when the server has a GitHub provider that is on (`new GitHub()` also gives `Madauth.github`). An admin adds the provider with a GitHub OAuth App's client ID and secret (`Madauth.admin.addProvider`, see [Providers](docs/server.md#providers)). See [GitHub security](docs/github-security.md).
- **E-mail & password:** `new Password()` adds the form to the dialog, with "Create account" and "Forgot password?". New accounts confirm their address with a link or a code from an e-mail. The links in the e-mails lead back to your page: `initialize` handles them, and opens the dialog to choose a new password after a reset link. See [Password security](docs/password-security.md).
- **E-mail link:** `new EmailLink()` adds "E-mail link" to the dialog: the user enters their address and gets an e-mail with a link that signs them in and a 6-digit code. An unknown address is signed up on first use (your sign-up check permitting); the owner of an address that signs in another way gets an e-mail that says so instead. The policy for the authenticator app applies as for a password. See [E-mail link security](docs/email-link-security.md).
- **Passkeys:** `Madauth.showSetUpPasskeyDialog()` lets a signed-in user add a passkey (the browser's dialog: a fingerprint, the face or the screen lock). With the server allowing passkeys as a sign-in method, `new Passkey()` adds "Passkey" to the dialog and offers the user's passkeys in the e-mail field's autofill, and, where the server confirms addresses by e-mail, a sign-up with a passkey alone (the address is confirmed first, then the passkey is created; `Madauth.passkey.signUp` on a custom screen); as a second factor, the dialog asks for one by itself. See [Passkey security](docs/passkey-security.md).
- **Several sign-in methods:** `Madauth.showManageSignInMethodsDialog()` opens the dialog on the signed-in user's methods, to add a passkey, a password, the e-mail link, Google, GitHub or the app, and to remove one. See [Several sign-in methods](docs/sign-in-methods.md).
- **SMS codes:** a second factor only, never a sign-in on its own. A signed-in user adds a phone number with `Madauth.showSetUpSmsDialog()` (a code confirms it); from then on, Google, the password and the e-mail link ask for a code sent to it when the policy is `optional` or `required`. A user who has the app as well is asked for the app first and can switch. `Madauth.sms.status()` and `remove({ code })` manage it from your account page. Your webhook receiver sends the SMS (`sms.send_code`). See [SMS code security](docs/sms-security.md).
- **Authenticator app** (TOTP: Google Authenticator, 1Password and the like). What it does is the server's [sign-in policy](docs/server.md#sign-in-methods): a second factor after another method (`optional`: for users who have one; `required`: everyone sets one up at their next sign-in), which the dialog handles by itself, and/or a method of its own (the e-mail address and a code, with sign-up by e-mail confirmation), which `new Authenticator()` adds to the dialog. `Madauth.showSetUpAuthenticatorDialog()` opens the dialog with the QR code and shows the recovery codes once; `Madauth.authenticator.status()`, `newRecoveryCodes(...)` and `remove(...)` manage it from your account page, the last two with a current code. See [Authenticator app security](docs/authenticator-security.md).
- **API keys:** `Madauth.showManageApiKeysDialog()` opens the dialog on the signed-in user's API keys, to make one (its name, scopes and expiry; the key is shown once) and to revoke one; `Madauth.apiKeys` does the same on your own screen. See [API keys](docs/api-keys.md).
- **The dialog:** `showSignInDialog()` adds a `<madauth-login>` to the page; put one in your HTML only to customize it. `showSignInDialog({ email })` opens it with the e-mail address filled in, e.g. from a link like `/?email=…`, so the user only types the password.
- **Language:** the dialog has English and German texts. It follows the page's `<html lang>`, then the browser's language. To set the language yourself, pass `locale: 'de'` (or e.g. `'de-CH'`) to `initialize`, and call `Madauth.setLocale('en')` when the user switches the language of your app; an open dialog changes at once. Every other language shows English. The same locale goes to your e-mail webhook, so the e-mails can match the dialog.
- **Your own login screen:** pass `ui: 'custom'` and use `Madauth.password`, `Madauth.google`, `Madauth.github`, `Madauth.passkey`, `Madauth.authenticator`, `Madauth.emailLink`, `Madauth.sms`, `Madauth.methods` and `Madauth.apiKeys` instead of the dialog. See [Building your own login screen](docs/custom-ui.md).
- **Other methods:** `signOut()`, `getSession()`, `currentUser`, `deleteAccount()` to [delete the signed-in user's account](docs/server.md#deleting-an-account) (with a code from the authenticator app once it is set up), and `sessionReady()` to wait for a fresh session before calling your own backend (see [Sessions](docs/server.md#sessions)). All methods resolve to `{ isSuccess, ... }` and never throw for expected failures.
- **Claims:** `currentUser.claims` holds what admins attached to the user, e.g. `{ roles: ['admin'] }`; it is in the session token for your backends too, as is `currentUser.amr`, how the session was authenticated (e.g. `['pwd', 'otp']`, or `['email']` after an e-mail link). Admins set claims with `Madauth.admin.setClaims(email, claims)`, the sign-in methods and their policies with `Madauth.admin.setSettings(...)`, reset the sign-in of a user who lost every way in with `Madauth.admin.resetSignIn(email)`, and find users by role, address or sign-up date with `Madauth.admin.searchUsers(...)`. See [Claims](docs/server.md#claims) and [Sign-in methods](docs/server.md#sign-in-methods).
- **Server URL:** the server is expected on the page's own origin (`/auth/...`). Pass `serverUrl: 'https://auth.example.com'` to `initialize` if it runs elsewhere on the same site.

### Running the server

See [Running the madAuth server](docs/server.md) for:
- the configuration
- Google Cloud Console setup, and GitHub OAuth App setup
- the database (SQLite, Postgres or Amazon DynamoDB) that stores every user, and webhooks for sending e-mails (with ready-made receivers in [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks), e.g. for Amazon SES), checking sign-ups and receiving events
- Node, Docker, AWS Lambda and Azure Functions
- storing users in your own database (custom store adapter)
- verifying the session in your own backend

### Styling

The login form can be styled to match your app (colors, corner radius, font, and individual parts of the dialog). See [Styling the login form](docs/styling.md) for all available settings.

## Adding a sign-in method

1. Add or update the entry in [`packages/web/src/methods.ts`](packages/web/src/methods.ts), and its texts in [`strings.ts`](packages/web/src/strings.ts).
2. Implement a `SignInProvider` (see [`packages/web/src/providers`](packages/web/src/providers)). The dialog lists a method once its provider is passed to `Madauth.initialize` and the server offers it (a provider whose `setup` answers `flow_not_enabled` is left out).
3. Add the server endpoints in a module in [`packages/server/src/routes`](packages/server/src/routes) and register it in [`app.ts`](packages/server/src/app.ts). A provider with a redirect flow (like Google's code flow and GitHub) builds on [`routes/oauth.ts`](packages/server/src/routes/oauth.ts): the state cookie, the way back to the app, and resolving the user behind a verified profile. Store what it needs as models in [`madauthSchema`](packages/server/src/store/schema.ts). A second factor (like SMS codes) has no provider and no row in the dialog: it is a scope, views for its step, and a `step` in `PendingStep` with the `factors` the server names.
4. Add the method's actions as a scope on `Madauth` (see [`packages/web/src/scopes`](packages/web/src/scopes)), so custom login screens can use it.
5. Add tests next to the code (`*.test.ts`) and run `npm test`.

## Releasing

See [Releasing](docs/releasing.md).

## Contributing

Contributions are welcome! Open an issue to discuss an idea or report a bug, or send a pull request. Please make sure `npm run typecheck` and `npm test` pass.

## License

madAuth is released under the [MIT License](LICENSE).
