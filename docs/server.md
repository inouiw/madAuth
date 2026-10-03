# Running the madAuth server

`@madauth/server` signs users in with Google or with e-mail & password, and issues the madAuth session. You can run it as a Docker container, an AWS Lambda function or an Azure Function.

Google sign-in needs no database. E-mail & password sign-in stores its users through a [store adapter](#custom-store-adapter): SQLite is built in, and other databases need a small adapter of your own.

## How it works

1. The browser signs in:
   - with Google, either in the browser with FedCM / One Tap (`GoogleFedcm`) or through the server-side redirect flow (`GoogleRedirect`). The server verifies Google's ID token: signature, issuer, audience, expiry, nonce and a verified e-mail address.
   - or with an e-mail address and password (`Password`). The server checks the password against its scrypt hash; new accounts confirm their address first. See [Password security](password-security.md).
2. The server sets its own session: an ES256-signed JWT in an HttpOnly cookie named `madauth_session`.
3. Your app backends verify that JWT with [`createSessionVerifier`](#verifying-the-session-in-your-backend) or any JWT library, using the public key at `/.well-known/jwks.json`.

> **Same site required.** The session is a cookie, so the madAuth server must be on the same site as your app, for example `auth.example.com` and `app.example.com`, or the same origin behind a reverse proxy. Browsers block third-party cookies, so cross-site setups do not work.

## Configuration

All settings are environment variables.

| Variable | Required | Description |
| --- | --- | --- |
| `MADAUTH_ISSUER` | yes | Public base URL of the server, e.g. `https://auth.example.com`. Used as the JWT issuer and for the code-flow callback `<issuer>/auth/google/callback`. |
| `MADAUTH_SIGNING_KEY` | yes | Private ES256 key (JWK JSON) used to sign sessions. Use the same key on every instance and keep it secret. |
| `ALLOWED_ORIGINS` | yes | Comma-separated origins of your apps, e.g. `https://app.example.com`. Only these may call the server or be redirected back to. |
| `GOOGLE_CLIENT_ID` | for Google | OAuth client ID of type "Web application", ending in `.apps.googleusercontent.com`. Turns on Google sign-in. |
| `GOOGLE_CLIENT_SECRET` | no | Client secret of the same client. Enables the server-side redirect flow (`GoogleRedirect`); without it those routes return 404. |
| `DATABASE_URL` | for e-mail & password | `sqlite:<path>`, e.g. `sqlite:/data/madauth.db`. Turns on e-mail & password sign-in. For other databases pass your own [store adapter](#custom-store-adapter) instead. |
| `SMTP_URL` | for e-mail & password | Mail server for the verification and reset e-mails, e.g. `smtps://user:password@smtp.example.com:465`. `console` prints the e-mails to the log instead (development only). |
| `MAIL_FROM` | with `SMTP_URL` | Sender of the e-mails, e.g. `"Example" <no-reply@example.com>`. |
| `PASSWORD_MIN_LENGTH` | no | Minimum password length. Default `8`. |
| `SESSION_TTL` | no | Session lifetime in seconds. Default `28800` (8 hours). The session is renewed when the app checks it after half of this time. |
| `COOKIE_DOMAIN` | no | Cookie domain, e.g. `.example.com`, so backends on sibling subdomains receive the session cookie. By default the cookie belongs to the server's host only. |
| `PORT` | no | Port for the Node / Docker server. Default `8787`. |

At least one sign-in method must be configured: `GOOGLE_CLIENT_ID`, `DATABASE_URL` (or a `store`), or both.

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

## E-mail & password sign-in

Set `DATABASE_URL` and `SMTP_URL`. Users are stored in the SQLite file; with Docker, keep it on a volume (the `docker-compose.yml` does this).

madAuth sends three e-mails: the address confirmation, the password reset, and a note to the owner when someone tries to sign up with an address that already has an account. The confirmation and reset e-mails contain a link to the app page that asked for them (its origin must be in `ALLOWED_ORIGINS`) and a 6-digit code, for when the e-mail is read on another device.

Examples for `SMTP_URL`:

| Service | `SMTP_URL` |
| --- | --- |
| Amazon SES | `smtps://<SMTP user>:<SMTP password>@email-smtp.eu-central-1.amazonaws.com:465` |
| Postmark | `smtps://<server token>:<server token>@smtp.postmarkapp.com:465` |
| Gmail (app password) | `smtps://you%40gmail.com:<app password>@smtp.gmail.com:465` |

URL-encode special characters in the user name and password (`@` → `%40`). To send through an HTTP API instead of SMTP, pass your own `mailer` (an object with `send({ to, subject, text, html })`) the same way as a [custom store adapter](#registering-your-adapter).

To create a user without e-mail, e.g. the first admin or for testing, run on a machine with the same environment variables:

```bash
npx @madauth/server create-user admin@example.com
```

In this repository, `npm run cli -w packages/server -- create-user you@example.com` does the same with the settings from `packages/server/.env`.

Brute-force protection is per account. Limit requests per IP address in your reverse proxy, load balancer or WAF as well. See [Password security](password-security.md) for all rules.

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

Deploy `packages/server/dist/standalone/lambda.mjs` with the handler `lambda.handler` on a Node.js 22 or newer runtime. Put it behind a Function URL, API Gateway (HTTP API) or an ALB, and set the environment variables on the function.

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

For e-mail & password sign-in on Lambda or Azure, use a [custom store adapter](#custom-store-adapter): their file system is not persistent, so SQLite does not fit. Password hashing needs about 32 MB per sign-in; give a Lambda function at least 256 MB.

### Your own Node server

```ts
import { createApp, loadConfig } from '@madauth/server';

const app = createApp(await loadConfig(process.env)); // a Hono app: app.fetch(request) → response
```

## Custom store adapter

E-mail & password users are stored through a `StoreAdapter`. madAuth does all the security work (hashing, throttling, single-use links); an adapter only stores records. It has five methods:

```ts
interface StoreAdapter {
  create(model: string, data: Row): Promise<boolean>; // false, writing nothing, if a unique value or primary key exists
  findOne(model: string, where: Where): Promise<Row | null>;
  findMany(model: string, where: Where, opts?: { limit?: number }): Promise<Row[]>;
  update(model: string, where: Where, patch: Row): Promise<number>; // records changed
  delete(model: string, where: Where): Promise<number>; // records deleted; must be exact under concurrency
}
// Row: { field: string | number | boolean | null }. Where: every field equals the value (null: is empty).
```

The models and their fields are in `madauthSchema` (exported by `@madauth/server`): `user`, `account` and `verification`. Rows use the schema's camelCase field names; the SQL tables use `madauth_<model>` and snake_case columns (`tableName()` and `columnName()` convert). Print the SQL to create the tables:

```bash
npx @madauth/server schema --dialect postgres
```

`mysql` and `sqlite` work as well. The built-in SQLite adapter ([`packages/server/src/store/sqlite.ts`](../packages/server/src/store/sqlite.ts)) uses only this public API, so it is a complete example.

### Example: Postgres

With the [`postgres`](https://github.com/porsager/postgres) package:

```ts
// postgres-adapter.ts
import postgres from 'postgres';
import { columnName, madauthSchema, tableName, type Row, type StoreAdapter, type Where } from '@madauth/server';

export function createPostgresAdapter(url: string): StoreAdapter {
  const sql = postgres(url);
  const fieldsOf = (model: string) => {
    const def = (madauthSchema.models as Record<string, { fields: object }>)[model];
    if (!def) throw new Error(`Unknown model "${model}"`);
    return Object.keys(def.fields);
  };
  const table = (model: string) => sql(tableName(model));
  const toColumns = (row: Row) => Object.fromEntries(Object.entries(row).map(([field, value]) => [columnName(field), value]));
  const toRow = (model: string, record: Record<string, unknown>): Row =>
    Object.fromEntries(fieldsOf(model).map((field) => [field, record[columnName(field)] as Row[string]]));
  const where = (w: Where) =>
    Object.entries(w).reduce(
      (acc, [field, value], i) => sql`${acc} ${i ? sql`and` : sql`where`} ${sql(columnName(field))} ${value === null ? sql`is null` : sql`= ${value}`}`,
      sql``,
    );

  return {
    async create(model, data) {
      fieldsOf(model);
      return (await sql`insert into ${table(model)} ${sql(toColumns(data))} on conflict do nothing`).count === 1;
    },
    async findOne(model, w) {
      const [record] = await sql`select * from ${table(model)} ${where(w)} limit 1`;
      return record ? toRow(model, record) : null;
    },
    async findMany(model, w, opts = {}) {
      const limit = opts.limit === undefined ? sql`` : sql`limit ${opts.limit}`;
      return (await sql`select * from ${table(model)} ${where(w)} ${limit}`).map((record) => toRow(model, record));
    },
    async update(model, w, patch) {
      fieldsOf(model);
      return (await sql`update ${table(model)} set ${sql(toColumns(patch))} ${where(w)}`).count;
    },
    async delete(model, w) {
      fieldsOf(model);
      return (await sql`delete from ${table(model)} ${where(w)}`).count;
    },
  };
}
```

### Testing your adapter

`@madauth/server/testing` checks an adapter against everything madAuth relies on, e.g. that duplicates are refused and that only one of several concurrent deletes of a record counts. It works with any test runner that has `describe`, `it` and `expect`, and only adds records with fresh IDs, so a shared test database is fine:

```ts
// postgres-adapter.test.ts
import { describe, expect, it } from 'vitest';
import { storeAdapterContract } from '@madauth/server/testing';
import { createPostgresAdapter } from './postgres-adapter.js';

storeAdapterContract({ describe, it, expect }, () => createPostgresAdapter(process.env.TEST_DATABASE_URL!));
```

### Registering your adapter

Every entry point takes a `store` (and a `mailer`) instead of `DATABASE_URL` (and `SMTP_URL`). Build and deploy your entry file like any Lambda function, Azure Function or Node app.

AWS Lambda:

```ts
import { createHandler } from '@madauth/server/lambda';
import { createPostgresAdapter } from './postgres-adapter.js';

export const handler = createHandler({ store: createPostgresAdapter(process.env.PG_URL!) });
```

Azure Functions:

```ts
import { register } from '@madauth/server/azure';
import { createPostgresAdapter } from './postgres-adapter.js';

register({ store: createPostgresAdapter(process.env.PG_URL!) });
```

Node / Docker:

```ts
import { start } from '@madauth/server/node';
import { createPostgresAdapter } from './postgres-adapter.js';

await start({ store: createPostgresAdapter(process.env.PG_URL!) });
```

With `createApp`, pass it to `loadConfig`: `createApp(await loadConfig(process.env, { store }))`.

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
| `GET /auth/config` | Public settings for the web library: `{ google: { clientId, codeFlow } \| null, password: { minLength } \| null }` |
| `POST /auth/google/nonce` | Starts a FedCM / One Tap sign-in: returns `{ nonce }` and sets a 5-minute nonce cookie |
| `POST /auth/google/verify` | `{ credential }` (Google ID token) → `{ user }` and the session cookie |
| `GET /auth/google/start?return_to=` | Starts the redirect flow (needs `GOOGLE_CLIENT_SECRET`) |
| `GET /auth/google/callback` | Google redirects here; redirects back to `return_to`, or to `return_to#madauth_error=<code>` |
| `POST /auth/password/signin` | `{ email, password }` → `{ user }` and the session cookie; 401 `invalid_credentials`, 403 `email_unverified`, 429 `too_many_attempts` |
| `POST /auth/password/signup` | `{ email, password, name?, redirectTo }` → 202, and the confirmation e-mail; 400 `invalid_email` or `weak_password` |
| `POST /auth/password/send-verification` | `{ email, redirectTo }` → 202, and the confirmation e-mail again |
| `POST /auth/password/verify-email` | `{ token }` or `{ email, code }` → `{ user }` and the session cookie; 400 `link_invalid` or `code_invalid` |
| `POST /auth/password/send-reset` | `{ email, redirectTo }` → 202, and the reset e-mail |
| `POST /auth/password/reset` | `{ password, token }` or `{ password, email, code }` → `{ user }` and the session cookie; ends all older sessions |
| `GET /auth/session` | `{ user }` for the current session, or 401 |
| `POST /auth/logout` | Clears the session cookie |
| `GET /.well-known/jwks.json` | Public key to verify sessions |
| `GET /health` | `ok` |

POST requests must come from an origin in `ALLOWED_ORIGINS`. The e-mail endpoints answer 202 whether or not the address has an account, and at most one e-mail per minute is sent to an account. The `/auth/password/*` routes return 404 when e-mail & password sign-in is not configured.
