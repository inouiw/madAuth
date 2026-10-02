# madAuth

A self-hostable alternative to Cognito / Auth0. Sign-in methods:

| Method | Status |
| --- | --- |
| Google sign-in (FedCM / One Tap, or server-side redirect) | available |
| Username & password | coming soon |
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

Create the server's configuration from the example. It uses a Google client that already allows `http://localhost:3000`:

```bash
cp packages/server/.env.example packages/server/.env
```

Start the madAuth server. The first start prints a signing key; copy it into `packages/server/.env` as `MADAUTH_SIGNING_KEY` and start again:

```bash
npm run dev:server
```

In a second terminal, start the demo at http://localhost:3000 (it proxies `/auth` to the server):

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

```ts
import { Madauth, GoogleFedcm } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm()] });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
signInButton.onclick = () => Madauth.signIn();
```

- **`initialize`** checks the server and loads the current session. You don't need to await it. Problems are logged to the console and returned as `{ isSuccess: false, error }`.
- **Google sign-in:** `new GoogleFedcm()` shows Google One Tap on page load ("Continue as …"). `Madauth.signIn()` opens the sign-in dialog with Google's button, which keeps working when Chrome holds One Tap back. For the server-side redirect flow use `new GoogleRedirect()`.
- **The dialog:** `signIn()` adds a `<madauth-login>` to the page; put one in your HTML only to customize it.
- **Other methods:** `signOut()`, `getSession()` and `currentUser`. All methods resolve to `{ isSuccess, ... }` and never throw for expected failures.
- **Server URL:** the server is expected on the page's own origin (`/auth/...`). Pass `serverUrl: 'https://auth.example.com'` to `initialize` if it runs elsewhere on the same site.

### Running the server

See [Running the madAuth server](docs/server.md) for:
- the configuration
- Google Cloud Console setup
- Docker, AWS Lambda and Azure Functions
- verifying the session in your own backend

### Styling

The login form can be styled to match your app (colors, corner radius, font, and individual parts of the dialog). See [Styling the login form](docs/styling.md) for all available settings.

## Adding a sign-in method

1. Add or update the entry in [`packages/web/src/methods.ts`](packages/web/src/methods.ts).
2. Implement a `SignInProvider` (see [`packages/web/src/providers`](packages/web/src/providers)). A method shows "coming soon" until its provider is passed to `Madauth.initialize`.
3. Add the server endpoints in [`packages/server/src/app.ts`](packages/server/src/app.ts).
4. Add tests next to the code (`*.test.ts`) and run `npm test`.

## Contributing

Contributions are welcome! Open an issue to discuss an idea or report a bug, or send a pull request. Please make sure `npm run typecheck` and `npm test` pass.

## License

madAuth is released under the [MIT License](LICENSE).
