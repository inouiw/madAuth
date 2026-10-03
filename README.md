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
apps/demo        demo page: plain HTML + TypeScript served by Vite, no framework
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

In a second terminal, start the webhook receiver. The confirmation and reset e-mails appear there, with their links and codes:

```bash
npm run dev:webhooks
```

In a third terminal, start the demo at http://localhost:3000 (it proxies `/auth` to the server). http://localhost:3000/custom.html shows a custom login screen built with the same library:

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

Install the library:

```bash
npm install @madauth/web
```

Run the server, for example with Docker (see [Running the madAuth server](docs/server.md) for the configuration and other hosting options):

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

- **`initialize`** checks the server and loads the current session. You don't need to await it. Problems are logged to the console and returned as `{ isSuccess: false, error }`.
- **Google sign-in:** `new GoogleFedcm()` shows Google One Tap on page load ("Continue as …"). `Madauth.signIn()` opens the sign-in dialog with Google's button, which keeps working when Chrome holds One Tap back. For the server-side redirect flow use `new GoogleRedirect()`.
- **E-mail & password:** `new Password()` adds the form to the dialog, with "Create account" and "Forgot password?". New accounts confirm their address with a link or a code from an e-mail. The links in the e-mails lead back to your page: `initialize` handles them, and opens the dialog to choose a new password after a reset link. See [Password security](docs/password-security.md).
- **The dialog:** `signIn()` adds a `<madauth-login>` to the page; put one in your HTML only to customize it.
- **Your own login screen:** pass `ui: 'custom'` and use `Madauth.password` and `Madauth.google` instead of the dialog. See [Building your own login screen](docs/custom-ui.md).
- **Other methods:** `signOut()`, `getSession()` and `currentUser`. All methods resolve to `{ isSuccess, ... }` and never throw for expected failures.
- **Server URL:** the server is expected on the page's own origin (`/auth/...`). Pass `serverUrl: 'https://auth.example.com'` to `initialize` if it runs elsewhere on the same site.

### Running the server

See [Running the madAuth server](docs/server.md) for:
- the configuration
- Google Cloud Console setup
- e-mail & password sign-in: the database, and webhooks for sending e-mails (with an [Amazon SES example](examples/aws-ses-mailer)), checking sign-ups and receiving events
- Docker, AWS Lambda and Azure Functions
- storing users in your own database (custom store adapter)
- verifying the session in your own backend

### Styling

The login form can be styled to match your app (colors, corner radius, font, and individual parts of the dialog). See [Styling the login form](docs/styling.md) for all available settings.

## Adding a sign-in method

1. Add or update the entry in [`packages/web/src/methods.ts`](packages/web/src/methods.ts).
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
