# Developing madAuth

How to work on madAuth itself: run the server, the demo and the webhook receiver from this repository, build, test, and add a sign-in method. To use madAuth in your app, see [Getting started](getting-started.md) instead.

## Repository layout

```
packages/web     @madauth/web – sign-in client and UI as framework-agnostic web components (Lit)
packages/server  @madauth/server – the madAuth server for Docker, AWS Lambda and Azure Functions (Hono)
demo             demo page: plain HTML + TypeScript served by Vite, no framework (live at https://madauth.com/demo/)
deploy/aws       AWS CDK template to host the madAuth server: Lambda, DynamoDB, keys in AWS KMS, secrets in SSM
site             the madauth.com website (landing page and blog, see site/README.md) and its infrastructure (site/infra)
scripts          the release script (see Releasing below) and the bundle size measurement (see Bundle size)
```

## Running the demo locally

Install dependencies:

```bash
npm install
```

Create the server's configuration from the example. It uses a Google client that already allows `http://localhost:3000`, stores the users in `packages/server/madauth.db`, and hands e-mails to a development webhook receiver that prints them:

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

In a third terminal, start the demo at http://localhost:3000 (it proxies `/auth` to the server). The demo page switches between Google One Tap and the server-side redirect flow (which needs a Google provider with a client secret: until the first admin exists, add it with the setup token the server prints, see [First setup](server.md#first-setup)), shows the signed-in user's claims, and has a button for every other call a signed-in user can make, the admin API included. http://localhost:3000/custom.html shows a custom login screen built with the same library:

```bash
npm run dev
```

The admin API needs the role `admin`, which the public demo at madauth.com gives to nobody: an admin could change every visitor's claims and switch sign-in methods off for everyone. Here you give it to yourself: set `INITIAL_ADMIN_EMAIL` in `packages/server/.env` to your address, start the server again, and sign in with that address (see [The first admin](server.md#the-first-admin)).

## Building and testing

Build the server, the library and the demo:

```bash
npm run build
```

Run the type checker and the unit tests (Vitest + happy-dom):

```bash
npm run typecheck
```

```bash
npm test
```

CI runs these three, and the [size check](#bundle-size). `deploy/aws` and `site/infra` are npm projects of their own, outside the workspaces: see [`.github/workflows/infra.yml`](../.github/workflows/infra.yml) for what CI runs there.

## Bundle size

The sizes the README, the [`@madauth/web` README](../packages/web/README.md) and the landing page name come from:

```bash
npm run size
```

It builds `@madauth/web`, bundles two small apps with esbuild (minified, with code splitting) and prints the gzipped and Brotli sizes of what loads with the page: one that imports `@madauth/web` and passes all six providers to `initialize` (Lit and the QR code library included), and one that imports `@madauth/web/client` instead. zxcvbn-ts and its list of common passwords are printed apart: they load on first use, only on a screen that asks for a new password (see [`strength.ts`](../packages/web/src/strength.ts)). The script is [`scripts/size.mjs`](../scripts/size.mjs). Run it after a change that adds to the client, and update those three places if the numbers move. CI checks them:

```bash
npm run size -- --check
```

fails when a size in kB that one of those files names is more than 1 kB off every measured size, and names the file and line.

## Adding a sign-in method

1. Add or update the entry in [`packages/web/src/methods.ts`](../packages/web/src/methods.ts), its name and button in [`strings-core.ts`](../packages/web/src/strings-core.ts), and the texts of its views in [`strings.ts`](../packages/web/src/strings.ts).
2. Implement a `SignInProvider` (see [`packages/web/src/providers`](../packages/web/src/providers)). The dialog lists a method once its provider is passed to `Madauth.initialize` and the server offers it (a provider whose `setup` answers `flow_not_enabled` is left out).
3. Add the server endpoints in a module in [`packages/server/src/routes`](../packages/server/src/routes) and register it in [`app.ts`](../packages/server/src/app.ts). A provider with a redirect flow (like Google's code flow and GitHub) builds on [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts): the state cookie, the way back to the app, and resolving the user behind a verified profile. Store what it needs as models in [`madauthSchema`](../packages/server/src/store/schema.ts). A second factor (like SMS codes) has no provider and no row in the dialog: it is a scope, views for its step, and a `step` in `PendingStep` with the `factors` the server names.
4. Add the method's actions as a scope on `Madauth` (see [`packages/web/src/scopes`](../packages/web/src/scopes)), so custom login screens can use it.
5. Add tests next to the code (`*.test.ts`) and run `npm test`.

## Releasing

See [Releasing](releasing.md).
