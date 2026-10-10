# madAuth

A self-hostable alternative to Cognito / Auth0. Sign-in methods:

| Method | Status |
| --- | --- |
| Google sign-in (FedCM / One Tap, or server-side redirect) | available |
| E-mail & password (with e-mail confirmation and password reset) | available |
| Authenticator app (TOTP) | coming soon |
| Passwordless e-mail link | coming soon |
| SMS code | coming soon |

## Repository layout

```
packages/web     @madauth/web – sign-in client and UI as framework-agnostic web components (Lit)
packages/server  @madauth/server – the madAuth server for Docker, AWS Lambda and Azure Functions (Hono)
demo             demo page: plain HTML + TypeScript served by Vite, no framework (live at https://madauth.com/demo/)
deploy/aws       AWS CDK template to host the madAuth server: Lambda, DynamoDB, secrets in SSM
site             the madauth.com website (landing page) and its infrastructure (site/infra)
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

In a third terminal, start the demo at http://localhost:3000 (it proxies `/auth` to the server). The demo page switches between Google One Tap and the server-side redirect flow (which needs `GOOGLE_CLIENT_SECRET` in `packages/server/.env`), shows the signed-in user's claims, and has a button for every other call a signed-in user can make, the admin API included. http://localhost:3000/custom.html shows a custom login screen built with the same library:

```bash
npm run dev
```

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
import { Madauth, GoogleFedcm, Password } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm(), new Password()] });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
signInButton.onclick = () => Madauth.signIn();
```

- **`initialize`** checks the server and loads the current session. You don't need to await it. Problems are logged to the console and returned as `{ isSuccess: false, error }`. A provider whose method the server doesn't offer (e.g. `GoogleRedirect` on a development server without a Google client) is left out with a warning, and the other methods work; `initialize` fails only when no method is left.
- **Google sign-in:** `new GoogleFedcm()` shows Google One Tap on page load ("Continue as …"). `Madauth.signIn()` opens the sign-in dialog with Google's button, which keeps working when Chrome holds One Tap back. For the server-side redirect flow use `new GoogleRedirect()`.
- **E-mail & password:** `new Password()` adds the form to the dialog, with "Create account" and "Forgot password?". New accounts confirm their address with a link or a code from an e-mail. The links in the e-mails lead back to your page: `initialize` handles them, and opens the dialog to choose a new password after a reset link. See [Password security](docs/password-security.md).
- **The dialog:** `signIn()` adds a `<madauth-login>` to the page; put one in your HTML only to customize it. `signIn({ email })` opens it with the e-mail address filled in, e.g. from a link like `/?email=…`, so the user only types the password.
- **Language:** the dialog has English and German texts. It follows the page's `<html lang>`, then the browser's language. To set the language yourself, pass `locale: 'de'` (or e.g. `'de-CH'`) to `initialize`, and call `Madauth.setLocale('en')` when the user switches the language of your app; an open dialog changes at once. Every other language shows English. The same locale goes to your e-mail webhook, so the e-mails can match the dialog.
- **Your own login screen:** pass `ui: 'custom'` and use `Madauth.password` and `Madauth.google` instead of the dialog. See [Building your own login screen](docs/custom-ui.md).
- **Other methods:** `signOut()`, `getSession()`, `currentUser`, `deleteAccount()` to [delete the signed-in user's account](docs/server.md#deleting-an-account), and `sessionReady()` to wait for a fresh session before calling your own backend (see [Sessions](docs/server.md#sessions)). All methods resolve to `{ isSuccess, ... }` and never throw for expected failures.
- **Claims:** `currentUser.claims` holds what admins attached to the user, e.g. `{ roles: ['admin'] }`; it is in the session token for your backends too. Admins set them with `Madauth.admin.setClaims(email, claims)`, and switch sign-in methods on and off with `Madauth.admin.setSettings(...)`. See [Claims](docs/server.md#claims) and [Sign-in methods](docs/server.md#sign-in-methods).
- **Server URL:** the server is expected on the page's own origin (`/auth/...`). Pass `serverUrl: 'https://auth.example.com'` to `initialize` if it runs elsewhere on the same site.

### Running the server

See [Running the madAuth server](docs/server.md) for:
- the configuration
- Google Cloud Console setup
- the database (SQLite or Amazon DynamoDB) that stores every user, and webhooks for sending e-mails (with ready-made receivers in [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks), e.g. for Amazon SES), checking sign-ups and receiving events
- Node, Docker, AWS Lambda and Azure Functions
- storing users in your own database (custom store adapter)
- verifying the session in your own backend

### Styling

The login form can be styled to match your app (colors, corner radius, font, and individual parts of the dialog). See [Styling the login form](docs/styling.md) for all available settings.

## Adding a sign-in method

1. Add or update the entry in [`packages/web/src/methods.ts`](packages/web/src/methods.ts), and its texts in [`strings.ts`](packages/web/src/strings.ts).
2. Implement a `SignInProvider` (see [`packages/web/src/providers`](packages/web/src/providers)). A method shows "coming soon" until its provider is passed to `Madauth.initialize`.
3. Add the server endpoints in a module in [`packages/server/src/routes`](packages/server/src/routes) and register it in [`app.ts`](packages/server/src/app.ts). Store what it needs as models in [`madauthSchema`](packages/server/src/store/schema.ts).
4. Add the method's actions as a scope on `Madauth` (see [`packages/web/src/scopes`](packages/web/src/scopes)), so custom login screens can use it.
5. Add tests next to the code (`*.test.ts`) and run `npm test`.

## Releasing

See [Releasing](docs/releasing.md).

## Contributing

Contributions are welcome! Open an issue to discuss an idea or report a bug, or send a pull request. Please make sure `npm run typecheck` and `npm test` pass.

## License

madAuth is released under the [MIT License](LICENSE).
