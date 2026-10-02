# Running the madAuth server

`@madauth/server` signs users in with Google and issues the madAuth session. It is stateless (no database), so you can run it as a Docker container, an AWS Lambda function or an Azure Function.

## How it works

1. The browser signs in with Google. This happens either in the browser with FedCM / One Tap (`GoogleFedcm`) or through the server-side redirect flow (`GoogleRedirect`).
2. The server verifies Google's ID token: signature, issuer, audience, expiry, nonce and a verified e-mail address.
3. The server sets its own session: an ES256-signed JWT in an HttpOnly cookie named `madauth_session`.
4. Your app backends verify that JWT with [`createSessionVerifier`](#verifying-the-session-in-your-backend) or any JWT library, using the public key at `/.well-known/jwks.json`.

> **Same site required.** The session is a cookie, so the madAuth server must be on the same site as your app, for example `auth.example.com` and `app.example.com`, or the same origin behind a reverse proxy. Browsers block third-party cookies, so cross-site setups do not work.

## Configuration

All settings are environment variables.

| Variable | Required | Description |
| --- | --- | --- |
| `MADAUTH_ISSUER` | yes | Public base URL of the server, e.g. `https://auth.example.com`. Used as the JWT issuer and for the code-flow callback `<issuer>/auth/google/callback`. |
| `MADAUTH_SIGNING_KEY` | yes | Private ES256 key (JWK JSON) used to sign sessions. Use the same key on every instance and keep it secret. |
| `ALLOWED_ORIGINS` | yes | Comma-separated origins of your apps, e.g. `https://app.example.com`. Only these may call the server or be redirected back to. |
| `GOOGLE_CLIENT_ID` | yes | OAuth client ID of type "Web application", ending in `.apps.googleusercontent.com`. |
| `GOOGLE_CLIENT_SECRET` | no | Client secret of the same client. Enables the server-side redirect flow (`GoogleRedirect`); without it those routes return 404. |
| `SESSION_TTL` | no | Session lifetime in seconds. Default `28800` (8 hours). The session is renewed when the app checks it after half of this time. |
| `COOKIE_DOMAIN` | no | Cookie domain, e.g. `.example.com`, so backends on sibling subdomains receive the session cookie. By default the cookie belongs to the server's host only. |
| `PORT` | no | Port for the Node / Docker server. Default `8787`. |

### Signing key

Start the server without `MADAUTH_SIGNING_KEY` and the error message contains a freshly generated key to copy. You can also generate one directly:

```bash
npx @madauth/server generate-key
```

## Google Cloud Console setup

1. Open [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials) and create an **OAuth client ID** of type **Web application**.
2. Under **Authorized JavaScript origins**, add every origin your app runs on (e.g. `https://app.example.com`, and `http://localhost:3000` plus `http://localhost` for development). The FedCM / One Tap flow needs only this.
3. For the redirect flow, add `<MADAUTH_ISSUER>/auth/google/callback` under **Authorized redirect URIs** and set `GOOGLE_CLIENT_SECRET`.
4. Set `GOOGLE_CLIENT_ID` to the client ID.

## Hosting

### Docker

Build the image from the repository root:

```bash
docker build -f packages/server/Dockerfile -t madauth-server .
```

Run it:

```bash
docker run --rm -p 8787:8787 --env-file packages/server/.env madauth-server
```

There is also a `docker-compose.yml` in `packages/server`. The container exposes `GET /health` for health checks.

### AWS Lambda

Build the self-contained bundle:

```bash
npm run build -w packages/server
```

Deploy `packages/server/dist/standalone/lambda.mjs` with the handler `lambda.handler` on a Node.js 20 or newer runtime. Put it behind a Function URL, API Gateway (HTTP API) or an ALB, and set the environment variables on the function.

### Azure Functions

Build as above, then deploy `packages/server/dist/standalone/azure.mjs` as the main file of a Node.js (v4 programming model) function app. It registers one HTTP function for all routes.

Add a `host.json` that removes the default `/api` route prefix:

```json
{
  "version": "2.0",
  "extensions": { "http": { "routePrefix": "" } }
}
```

And a `package.json` that points to the bundle:

```json
{ "type": "module", "main": "azure.mjs" }
```

Set the environment variables as application settings.

### Your own Node server

```ts
import { createApp, loadConfig } from '@madauth/server';

const app = createApp(await loadConfig(process.env)); // a Hono app: app.fetch(request) → response
```

## Verifying the session in your backend

`createSessionVerifier` checks the madAuth session cookie (or an `Authorization: Bearer` token) in any backend that has the Web `Request` API. The public key is fetched from `<issuer>/.well-known/jwks.json` once and then cached.

```ts
import { createSessionVerifier } from '@madauth/server/verify';

const verifySession = createSessionVerifier({ issuer: 'https://auth.example.com' });

const user = await verifySession(request); // or a Cookie header, or the token itself
if (!user) return new Response('Unauthorized', { status: 401 });
console.log(user.id, user.email);
```

Other languages can verify the JWT with any JOSE library:
- algorithm `ES256`
- issuer `MADAUTH_ISSUER`
- header `typ` `madauth-session+jwt`
- keys from `/.well-known/jwks.json`

## HTTP API

| Method & path | Description |
| --- | --- |
| `GET /auth/config` | Public settings for the web library: `{ google: { clientId, codeFlow } }` |
| `POST /auth/google/nonce` | Starts a FedCM / One Tap sign-in: returns `{ nonce }` and sets a 5-minute nonce cookie |
| `POST /auth/google/verify` | `{ credential }` (Google ID token) → `{ user }` and the session cookie |
| `GET /auth/google/start?return_to=` | Starts the redirect flow (needs `GOOGLE_CLIENT_SECRET`) |
| `GET /auth/google/callback` | Google redirects here; redirects back to `return_to`, or to `return_to#madauth_error=<code>` |
| `GET /auth/session` | `{ user }` for the current session, or 401 |
| `POST /auth/logout` | Clears the session cookie |
| `GET /.well-known/jwks.json` | Public key to verify sessions |
| `GET /health` | `ok` |

POST requests must come from an origin in `ALLOWED_ORIGINS`.
