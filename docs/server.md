# Running the madAuth server

`@madauth/server` signs users in with Google or with e-mail & password, and issues the madAuth session. You can run it with Node, as a Docker container, an AWS Lambda function or an Azure Function.

To set it up on your machine step by step, see [Getting started](getting-started.md).

Every user is stored, whichever way they sign in, through a [store adapter](#custom-store-adapter): SQLite and [Amazon DynamoDB](#dynamodb) are built in, and other databases need a small adapter of your own. A user has one id (`usr_…`) and one e-mail address, and one account per sign-in method: the password, or the Google account (known by Google's stable `sub`). Someone who signs in with Google using the address of their e-mail & password account is the same user, and the other way round. A password nobody has confirmed yet (a sign-up whose e-mail link was never used) is dropped when its address signs in with Google. "Forgot password?" only resets a password that exists: a user who signs in with Google alone gets an e-mail that says how they sign in instead (`email.no_password`), and the answer is the same as for any address.

## How it works

1. The browser signs in:
   - with Google, either in the browser with FedCM / One Tap (`GoogleFedcm`) or through the server-side redirect flow (`GoogleRedirect`). The server verifies Google's ID token: signature, issuer, audience, expiry, nonce and a verified e-mail address.
   - or with an e-mail address and password (`Password`). The server checks the password against its scrypt hash; new accounts confirm their address first. See [Password security](password-security.md).
2. The server finds or creates the user, and sets its own session: an ES256-signed JWT in an HttpOnly cookie named `madauth_session`, with the user's [claims](#claims). It is short-lived and renewed without the user noticing; see [Sessions](#sessions).
3. Your app backends verify that JWT with [`createSessionVerifier`](#verifying-the-session-in-your-backend) or any JWT library, using the public key at `/.well-known/jwks.json`.

> **Same site required.** The session is a cookie, so the madAuth server must be on the same site as your app, for example `auth.example.com` and `app.example.com`, or the same origin behind a reverse proxy. Browsers block third-party cookies, so cross-site setups do not work.

## Configuration

All settings are environment variables. `npx @madauth/server init` asks for the main ones and writes them to a `.env` file, with a new signing key and webhook secret (see [Getting started](getting-started.md)).

| Variable | Required | Description |
| --- | --- | --- |
| `MADAUTH_ISSUER` | yes | Public base URL of the server, e.g. `https://auth.example.com`. Used as the JWT issuer and for the code-flow callback `<issuer>/auth/google/callback`. |
| `MADAUTH_SIGNING_KEY` | yes | Private ES256 key (JWK JSON) used to sign sessions. Use the same key on every instance and keep it secret. |
| `ALLOWED_ORIGINS` | yes | Comma-separated origins of your apps, e.g. `https://app.example.com`. Only these may call the server or be redirected back to. |
| `GOOGLE_CLIENT_ID` | for Google | OAuth client ID of type "Web application", ending in `.apps.googleusercontent.com`. Turns on Google sign-in. |
| `GOOGLE_CLIENT_SECRET` | no | Client secret of the same client. Enables the server-side redirect flow (`GoogleRedirect`); without it those routes return 404. |
| `DATABASE_URL` | yes | Where the users are stored: `sqlite:<path>`, e.g. `sqlite:/data/madauth.db`, or `dynamodb:<table>` (see [DynamoDB](#dynamodb)). For other databases pass your own [store adapter](#custom-store-adapter) instead. |
| `WEBHOOK_URL` | for e-mail & password | Your [webhook](#webhooks) receiver, which sends the e-mails and can check sign-ups and receive events. Must be https, except `localhost`, `127.0.0.1` and `host.docker.internal`. |
| `WEBHOOK_SECRET` | with `WEBHOOK_URL` | Signs every webhook call; your receiver needs the same one. Start without it once and the error message contains a new one, or run `npx @madauth/server generate-webhook-secret`. |
| `WEBHOOK_EVENTS` | with `WEBHOOK_URL` | Comma-separated [types](#webhooks) your receiver handles; only these are sent. E-mail & password sign-in is on when they include `email.verify` and `email.reset`, e.g. `email.verify,email.reset,email.already_registered`. |
| `PASSWORD_MIN_LENGTH` | no | Minimum password length. Default `8`. |
| `SESSION_TTL` | no | Lifetime of a session token in seconds: how long your backends accept it. Default `28800` (8 hours). The web library renews it when needed, see [Sessions](#sessions). |
| `SESSION_RENEWAL_TTL` | no | How long a user stays signed in without opening your app, in seconds: a session can be renewed this long after its last renewal. Default `2592000` (30 days). Not less than `SESSION_TTL`. |
| `COOKIE_DOMAIN` | no | Cookie domain, e.g. `.example.com`, so backends on sibling subdomains receive the session cookie. By default the cookie belongs to the server's host only. |
| `PORT` | no | Port for the Node / Docker server. Default `8787`. |

At least one sign-in method must be configured: `GOOGLE_CLIENT_ID`, a webhook that sends the e-mails (e-mail & password), or both. Admins can switch a configured method off and on while the server runs, see [Sign-in methods](#sign-in-methods).

### Signing key

`init` writes a new key into `.env`. Otherwise, start the server without `MADAUTH_SIGNING_KEY` and the error message contains a freshly generated key to copy. You can also generate one directly:

```bash
npx @madauth/server generate-key
```

## Google Cloud Console setup

1. Open [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials) and create an **OAuth client ID** of type **Web application**.
2. Under **Authorized JavaScript origins**, add every origin your app runs on (e.g. `https://app.example.com`, and `http://localhost:3000` plus `http://localhost` for development). The FedCM / One Tap flow needs only this.
3. For the redirect flow, add `<MADAUTH_ISSUER>/auth/google/callback` under **Authorized redirect URIs** and set `GOOGLE_CLIENT_SECRET`.
4. Set `GOOGLE_CLIENT_ID` to the client ID.

## E-mail & password sign-in

Set `WEBHOOK_URL`, `WEBHOOK_SECRET` and `WEBHOOK_EVENTS` with `email.verify` and `email.reset` among the events: e-mail & password sign-in is on exactly when your webhook sends those e-mails. The users are in `DATABASE_URL`: with `sqlite:<path>` in that SQLite file (with Docker, keep it on a volume; the `docker-compose.yml` does this), with `dynamodb:<table>` in a [DynamoDB table](#dynamodb).

madAuth does not send e-mails itself: it hands each one to your [webhook](#webhooks) receiver. There are three: the address confirmation, the password reset, and a note to the owner when someone tries to sign up with an address that already has an account. The confirmation and reset e-mails contain a link to the app page that asked for them (its origin must be in `ALLOWED_ORIGINS`) and a 6-digit code, for when the e-mail is read on another device.

Ready-made receivers are in the [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks) repository:
- [`dev-receiver`](https://github.com/inouiw/madAuth-webhooks/tree/main/dev-receiver) prints the e-mails in the terminal, for development.
- [`aws-ses-mailer`](https://github.com/inouiw/madAuth-webhooks/tree/main/aws-ses-mailer) sends them with Amazon SES from an AWS Lambda function, with a step-by-step AWS setup.

To create a user without e-mail, e.g. the first admin or for testing, run on a machine with the same environment variables (or add `--env-file .env`):

```bash
npx @madauth/server create-user admin@example.com
```

In this repository, `npm run cli -w packages/server -- create-user you@example.com` does the same with the settings from `packages/server/.env`.

Brute-force protection is per account. Limit requests per IP address in your reverse proxy, load balancer or WAF as well. See [Password security](password-security.md) for all rules.

### DynamoDB

On AWS, and always on AWS Lambda, store the users in a DynamoDB table. madAuth keeps all its records in one table.

1. Create the table, with the partition key `pk` and the sort key `sk`, both strings:

   ```bash
   aws dynamodb create-table --table-name madauth \
     --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
     --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
     --billing-mode PAY_PER_REQUEST
   ```

2. Set `DATABASE_URL=dynamodb:madauth` on the server.
3. Allow the server these actions on the table: `dynamodb:GetItem`, `dynamodb:Query`, `dynamodb:PutItem`, `dynamodb:UpdateItem` and `dynamodb:DeleteItem`. On Lambda, add them to the function's role.

The region and the credentials come from the environment, as for every AWS SDK: on Lambda from the function itself, elsewhere e.g. from `AWS_REGION` and `aws configure`.

The adapter needs the `@aws-sdk/client-dynamodb` package. AWS Lambda's Node.js runtimes and the madAuth Docker image contain it. Anywhere else, install it next to madAuth:

```bash
npm install @aws-sdk/client-dynamodb
```

The command line works with the table as well, e.g. to create the first user. Run it in a project where `@madauth/server` and `@aws-sdk/client-dynamodb` are installed:

```bash
DATABASE_URL=dynamodb:madauth npx @madauth/server create-user admin@example.com
```

In your own entry file, create the adapter yourself, e.g. to pass a configured client:

```ts
import { createHandler } from '@madauth/server/lambda';
import { createDynamoDbAdapter } from '@madauth/server/dynamodb';

export const handler = createHandler({ store: createDynamoDbAdapter({ tableName: 'madauth' }) });
```

How the records are stored: each record is one item (`pk` = `r|<model>|<id>`), with one more item per unique value (`u|user|emailNormalized|<address>`) and per indexed value (`i|account|userId|<id>`). A record and these items are always written in one transaction, and every read is strongly consistent, so the table needs no secondary index.

## Hosting

Ready-made deployment templates are in [`deploy/`](../deploy/README.md). On AWS, [`deploy/aws`](../deploy/aws/README.md) creates the Lambda function, the DynamoDB table and the secrets in the Parameter Store with one `cdk deploy`.

### Node

With Node.js 22.13 or newer, install the package and start the server:

```bash
npm install @madauth/server
```

```bash
npx @madauth/server start --env-file .env
```

`--env-file` reads the settings from a file. A variable that is already set in the environment wins, so `PORT=9000 npx @madauth/server start --env-file .env` listens on another port. Every command takes it. Without it, the server reads the environment only.

`npx @madauth/server init` writes such a file. It asks for your app's URL and the sign-in methods, and every question is also an option (`--yes` takes the defaults); see [Getting started](getting-started.md). Run `npx @madauth/server` for all commands.

### Docker

Run the published image (for `linux/amd64` and `linux/arm64`). Pin a version, e.g. `ghcr.io/inouiw/madauth-server:0.1.0`, in production:

```bash
docker run --rm -p 8787:8787 --env-file .env -v madauth-data:/data ghcr.io/inouiw/madauth-server
```

The `madauth-data` volume keeps a SQLite database (`DATABASE_URL=sqlite:/data/madauth.db`) when the container is removed.

To build the image yourself, run this from the repository root:

```bash
docker build -f packages/server/Dockerfile -t madauth-server .
```

There is also a `docker-compose.yml` in `packages/server` that builds and runs it from the repository. The container exposes `GET /health` for health checks.

With e-mail & password sign-in, the container must reach your webhook receiver. A receiver on your own machine, e.g. the development receiver, is `http://host.docker.internal:8790/webhook` from inside the container.

### AWS Lambda

Download `madauth-server-lambda.mjs` from a [GitHub release](https://github.com/inouiw/madAuth/releases), or take `dist/standalone/lambda.mjs` from the `@madauth/server` npm package. In this repository, build it with:

```bash
npm run build -w packages/server
```

The [AWS CDK template](../deploy/aws/README.md) does all of the following for you. By hand: deploy the bundle, as `lambda.mjs`, with the handler `lambda.handler` on a Node.js 22 or newer runtime. Put it behind a Function URL, API Gateway (HTTP API) or an ALB, and set the environment variables on the function.

Environment variables of a function can be read by everyone who may view its configuration. To keep `MADAUTH_SIGNING_KEY` and the other secrets in the Parameter Store or Secrets Manager instead, write a small entry file and pass `env`: a function that loads the settings. It runs once, before the first request:

```ts
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { createHandler } from '@madauth/server/lambda';

const ssm = new SSMClient({});
const secret = async (name: string) =>
  (await ssm.send(new GetParameterCommand({ Name: name, WithDecryption: true }))).Parameter?.Value;

export const handler = createHandler({
  env: async () => {
    const [signingKey, webhookSecret] = await Promise.all([
      secret('/madauth/signing-key'),
      secret('/madauth/webhook-secret'),
    ]);
    return { ...process.env, MADAUTH_SIGNING_KEY: signingKey, WEBHOOK_SECRET: webhookSecret };
  },
});
```

`register` (Azure Functions) and `start` (Node) take the same `env` option.

### Azure Functions

Get `madauth-server-azure.mjs` (or `dist/standalone/azure.mjs`) as above, then deploy it as `azure.mjs`, the main file of a Node.js (v4 programming model) function app. It registers one HTTP function for all routes.

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

For e-mail & password sign-in on Lambda or Azure, SQLite does not fit: their file system is not persistent. On Lambda, use [DynamoDB](#dynamodb): `DATABASE_URL=dynamodb:<table>` works with the bundle as it is. On Azure, use a [custom store adapter](#custom-store-adapter). Password hashing needs about 32 MB per sign-in; give a Lambda function at least 256 MB.

### Your own Node server

`start` runs madAuth as a server of its own. To serve it from your own Node server instead, create the app:

```ts
import { createApp, loadConfig } from '@madauth/server';

const app = createApp(await loadConfig(process.env)); // a Hono app: app.fetch(request) → response
```

## Webhooks

madAuth calls one URL of yours, `WEBHOOK_URL`, to send e-mails, to let you decide on sign-ups, and to tell you what happened. This works the same in Docker, Lambda and Azure, and the receiver can be written in any language.

Each call is a `POST` with a JSON body `{ "type": "…", "data": { … } }`:

| `type` | When | `data` | Your answer | If it fails (no 2xx within the time, or unreachable) |
| --- | --- | --- | --- | --- |
| `email.verify` | Sign-up, or "send the e-mail again" | `to`, `link`, `code`, `expiresAt`, `site`, `locale`, `user { id, name }` | 2xx within 10 s, once you have taken over the e-mail (e.g. your mail service accepted it) | The request fails with `503 temporarily_unavailable`, and the user sees that e-mails can't be sent right now. They can retry at once. |
| `email.reset` | "Forgot password?" | the same | the same | the same |
| `email.already_registered` | Sign-up with an address that already has a confirmed account | `to`, `link` (the sign-in page), `site`, `locale`, `user`, `methods` (how the user signs in, e.g. `["google"]`) | the same | the same |
| `email.no_password` | "Forgot password?" for a user without a password, who signs in with Google: tell them so | the same | the same | the same |
| `signup.before` | Before a user is created: a password sign-up, or the first Google sign-in of an address nobody has | `email`, `name`, `locale`, `method` (`password` or `google`) | 2xx within 10 s. `{ "allow": false, "message": "…" }` refuses the sign-up and the user sees your message (`403 signup_rejected`); any other 2xx allows it. | The sign-up is refused with `503 temporarily_unavailable`: without your answer, nobody signs up. |
| `user.created` | A user was created (with a password: not yet confirmed) | `user { id, email, name }`, `method` | 2xx within 5 s | Logged; the request still succeeds. |
| `email.verified` | An address was confirmed | `user`, `via` (`link` or `code`) | the same | the same |
| `email.password_reset` | A password was reset (older sessions end) | `user` | the same | the same |
| `user.signed_in` | Someone signed in, including after confirming or resetting | `user`, `method` (`password` or `google`) | the same | the same |
| `user.deleted` | A user deleted their account | `user` | the same | the same |
| `user.claims_changed` | An admin set the claims of a user | `userId`, `email`, `claims`, `by` (the admin's address) | the same | the same |

- `link` already contains the token: send it as it is. `code` is the 6-digit code, `site` the app's host (e.g. `app.example.com`), `locale` the user's language (e.g. `de-CH`) if known: the `locale` your app passed to `Madauth.initialize`, else the page's or the browser's language.
- Only the types in `WEBHOOK_EVENTS` are sent, so list what your receiver handles. E-mail & password sign-in is on when `email.verify` and `email.reset` are in the list; a receiver that only wants events (e.g. `user.signed_in`) is fine on a Google-only server.
- Without `email.already_registered` in the list, a sign-up with an address that already has a confirmed account is answered like any other and no e-mail is sent; the same goes for `email.no_password` and "Forgot password?" for a user without a password. Without `signup.before`, every sign-up is allowed.
- madAuth waits for each call before it answers the browser, because AWS Lambda stops a function as soon as it has answered. Keep receivers fast.

### Signatures

Every call is signed in the [Standard Webhooks](https://www.standardwebhooks.com/) format, so you can use their libraries in many languages. The headers are `webhook-id`, `webhook-timestamp` and `webhook-signature` (`v1,` and the base64 HMAC-SHA256 of `<id>.<timestamp>.<body>`, keyed with the base64 part of `WEBHOOK_SECRET` after `whsec_`).

Verify each call against the **raw** body before you trust it, and reject calls older than five minutes. In JavaScript:

```ts
import { verifyWebhook } from '@madauth/server/webhook';

const body = await request.text();
if (!verifyWebhook(process.env.WEBHOOK_SECRET!, request.headers, body)) return new Response(null, { status: 401 });
const { type, data } = JSON.parse(body);
```

The calls contain e-mail links and codes, so `WEBHOOK_URL` must be https, except for a receiver on the same machine (`localhost`, `127.0.0.1`, or `host.docker.internal` from a Docker container). Calls with the same `webhook-id` are the same call; madAuth does not retry by itself.

## Sessions

A session has two lifetimes: how long your backends trust it, and how long the user stays signed in. They are separate, so the first can be short without making users sign in again.

Signing in sets three cookies:

| Cookie | Lifetime | What it is |
| --- | --- | --- |
| `madauth_session` | `SESSION_TTL` (8 hours) | The session token, a signed JWT. Your backends verify it without asking madAuth. HttpOnly. |
| `madauth_renewal` | `SESSION_RENEWAL_TTL` (30 days) | The renewal token. It gets a new session token when the old one has expired or is about to. HttpOnly, and only sent to the madAuth server: its path is `/auth`, and it has no domain even with `COOKIE_DOMAIN`. Your backends never see it. |
| `madauth_session_expires` | `SESSION_RENEWAL_TTL` | When the session token expires, in seconds since 1970, for the web library. Scripts can read it; it holds no secret. |

**Renewal.** `GET /auth/session` renews the session when its token is missing, has expired or has passed half of its lifetime, if the request carries a valid renewal token. Before it does, the server checks again: the user still exists, no password reset happened since, and which [claims](#claims) they have now. Then it sets all three cookies anew. So a password reset, a deleted account and changed claims reach your backends within `SESSION_TTL` at the latest, while an active user stays signed in.

Each renewal starts the renewal time again: a user who opens your app at least every 30 days stays signed in. Without a visit in that time, they sign in again.

**In the browser**, the web library renews the session when the page loads and when you call `Madauth.sessionReady()`. A page that has been open for hours, or is opened after hours, may hold an expired session token. Wait for the renewal before you call your own backend:

```ts
await Madauth.sessionReady(); // at once while the session is valid, or when nobody is signed in
const response = await fetch('/api/orders');
```

A backend that answers 401 although the user is signed in met a session that expired in between: call `Madauth.sessionReady()` and send the request once more.

**What renewal can't do.** Whoever has both cookies stays signed in until the renewal token expires or the password is reset. A password reset ends every session of the user, also those started with Google. A session token issued by madAuth 0.1 has no renewal token, and one issued by madAuth 0.2 for a Google user belongs to an id that no longer exists: either lasts until it expires, and then the user signs in again.

## Claims

Claims are what admins attach to a user, as a JSON object, e.g. `{ "roles": ["admin"], "plan": "pro" }`. madAuth puts them into the session, so your app and your backends can tell what a user may do or has. What a claim means is up to you; madAuth only knows the role `admin` in `claims.roles`: the role that may manage claims and settings.

- Claims belong to the **user**, whichever way they sign in: with Google as well as with a password.
- The session carries them as `claims` (a `claims` claim in the JWT). `createSessionVerifier` returns them as `user.claims`, and the web library as `Madauth.currentUser.claims`. A user without claims has no `claims` field.
- A claims object has at most 2048 characters as JSON. Its keys are names: letters, digits and `_`, starting with a letter, at most 64 characters. `roles`, if present, is a list of role names: lower-case letters, digits, `-` and `_`, starting with a letter, at most 32 characters, at most 20 of them. Other values can be anything JSON carries.

**The first admin** is made on the command line, by someone who can reach the database, after that person has signed in once (or was created with `create-user`). Run it where the server's settings are available:

```bash
npx @madauth/server set-roles you@example.com admin
```

`set-roles <email> [role...]` replaces the roles of the user, leaving their other claims alone (without roles: removes them), and `get-roles <email>` prints them. `set-claims <email> '<json>'` replaces all claims, and `get-claims <email>` prints them. This is also the way back in if the last admin removed their own role.

**Admins manage claims** from your app with the web library, or with the HTTP API:

```ts
await Madauth.admin.setClaims('ada@example.com', { roles: ['editor'], plan: 'pro' }); // replaces her claims; {} removes them
const result = await Madauth.admin.getClaims('ada@example.com'); // { isSuccess: true, userId: 'usr_…', claims: { … } }
```

Whether the caller is an admin is asked from the store each time, not read from their session, so a removed `admin` role stops counting at once.

**When a change shows.** The claims of a session token are from the moment it was issued. The madAuth server reads them again whenever the app checks the session (`GET /auth/session`, e.g. on page load) and at every [renewal](#sessions), and issues a new session token if they changed. Your own backends, which verify the token offline, see the change from that moment, and after `SESSION_TTL` at the latest.

## Sign-in methods

Which sign-in methods the server offers is configured at start (`GOOGLE_CLIENT_ID`, the webhook for e-mail & password). Which of them are switched on is a setting in the database that admins change while the server runs, at once and for every instance: to pause sign-ups with one method, or to turn a new method on for everyone at the same moment.

A method that is off is not shown by the web library (`GET /auth/config` reports it as `null`), and its routes answer `403 method_disabled`. Existing sessions continue. The last method that is on can't be switched off.

From your app with the web library, or with the HTTP API:

```ts
await Madauth.admin.setSettings({ methods: { password: false } }); // a method not mentioned stays as it is
const result = await Madauth.admin.getSettings(); // { isSuccess: true, methods: { google: { available, enabled }, password: { … } } }
```

On the command line, `set-methods google` switches on the listed methods and off the others (`set-methods` alone: all on), and `get-methods` prints them.

## Deleting an account

`Madauth.deleteAccount()` in the web library (`POST /auth/account/delete`) lets a signed-in user delete their account:

- The user is deleted with all their sign-in methods (the password, the Google account), their claims, and their pending confirmation and reset links. The session proves who they are, whichever way they signed in.
- The session cookie is cleared, and `user.deleted` is sent to the webhook if it is in `WEBHOOK_EVENTS`, with the user as the session held them.

Delete the user's data in your own backend first, while the user is still signed in. Sessions on other devices end when the app next checks them; your own backends accept them until they expire (see [Password security](password-security.md#sessions)).

## Custom store adapter

Users are stored through a `StoreAdapter`. madAuth does all the security work (hashing, throttling, single-use links); an adapter only stores records. It has five methods:

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

The models and their fields are in `madauthSchema` (exported by `@madauth/server`): `user`, `account` (one per sign-in method of a user), `verification` and `setting`. The schema says nothing about how records are stored, so it fits any database. For SQL databases there are helpers: rows use the schema's camelCase field names, while the SQL tables use `madauth_<model>` and snake_case columns (`tableName()` and `columnName()` convert), and `createTablesSql()` creates them. Print the SQL to create the tables:

```bash
npx @madauth/server schema --dialect postgres
```

`mysql` and `sqlite` work as well. The built-in SQLite adapter ([`packages/server/src/store/sqlite.ts`](../packages/server/src/store/sqlite.ts)) uses only this public API, so it is a complete example. The DynamoDB adapter ([`dynamodb.ts`](../packages/server/src/store/dynamodb.ts)) is one for a database without SQL.

### Schema versions

`madauthSchema.version` increases when a madAuth release adds a model or a field. The built-in SQLite adapter upgrades its database by itself. For your own SQL tables, print the changes since the version they were created for and run them before you deploy the new madAuth version:

```bash
npx @madauth/server schema --dialect postgres --from 1
```

| Version | Change |
| --- | --- |
| 2 | `user.wrongCodes`: wrong e-mail codes in a row, see [Password security](password-security.md#links-and-codes-in-e-mails). Number, starts at 0. |
| 3 | New model `role`: the roles of an e-mail address. A new table; existing ones don't change. |
| 4 | Every user is stored, with their [claims](#claims): `user.claims` (JSON string, empty without claims) and `account.email` (the address the provider reported, e.g. Google's; empty for passwords). New model `setting` (the [sign-in methods](#sign-in-methods)). The `role` table is dropped: roles are a claim now, set them again with `set-roles`. |

Stores without fixed columns need no change: madAuth reads a missing `wrongCodes` as 0, and a missing `claims` or `email` as empty. Records of the `role` model are simply not read any more.

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

Every entry point takes a `store` instead of `DATABASE_URL`. Build and deploy your entry file like any Lambda function, Azure Function or Node app.

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
console.log(user.id, user.email, user.claims); // claims: e.g. { roles: ['admin'] }, see "Claims"
```

A session token is valid for `SESSION_TTL`. When `verifySession` finds none, answer 401: the web library then renews the session, and the app sends the request again (see [Sessions](#sessions)).

Other languages can verify the JWT with any JOSE library:
- algorithm `ES256`
- issuer `MADAUTH_ISSUER`
- header `typ` `madauth-session+jwt`
- keys from `/.well-known/jwks.json`

The claims are `sub` (the user's id), `email`, `name`, `picture`, `amr` (how the user signed in) and `claims` (what admins attached, see [Claims](#claims)).

## HTTP API

| Method & path | Description |
| --- | --- |
| `GET /auth/config` | Public settings for the web library: `{ google: { clientId, codeFlow } \| null, password: { minLength } \| null }`. A method is `null` when it is not configured or [switched off](#sign-in-methods). |
| `POST /auth/google/nonce` | Starts a FedCM / One Tap sign-in: returns `{ nonce }` and sets a 5-minute nonce cookie |
| `POST /auth/google/verify` | `{ credential, locale? }` (Google ID token) → `{ user }` and the session cookie; 403 `signup_rejected` (a first sign-in the sign-up check refused), 503 `temporarily_unavailable` |
| `GET /auth/google/start?return_to=` | Starts the redirect flow (needs `GOOGLE_CLIENT_SECRET`) |
| `GET /auth/google/callback` | Google redirects here; redirects back to `return_to`, or to `return_to#madauth_error=<code>` |
| `POST /auth/password/signin` | `{ email, password }` → `{ user }` and the session cookie; 401 `invalid_credentials`, 403 `email_unverified`, 429 `too_many_attempts` |
| `POST /auth/password/signup` | `{ email, password, name?, redirectTo, locale? }` → 202, and the confirmation e-mail; 400 `invalid_email` or `weak_password`, 403 `signup_rejected`, 503 `temporarily_unavailable` |
| `POST /auth/password/send-verification` | `{ email, redirectTo, locale? }` → 202, and the confirmation e-mail again; 503 `temporarily_unavailable` |
| `POST /auth/password/verify-email` | `{ token }` or `{ email, code }` → `{ user }` and the session cookie; 400 `link_invalid` or `code_invalid`, 429 `codes_locked` |
| `POST /auth/password/send-reset` | `{ email, redirectTo, locale? }` → 202, and the reset e-mail if the address has a password (`email.no_password` if its user has none); 503 `temporarily_unavailable` |
| `POST /auth/password/reset` | `{ password, token }` or `{ password, email, code }` → `{ user }` and the session cookie; ends all older sessions; 400 `link_invalid` or `code_invalid`, 429 `codes_locked` |
| `GET /auth/session` | `{ user }` for the current session, [renewing](#sessions) it if needed; 401 `no_session`, which also clears the cookies |
| `POST /auth/logout` | Clears the cookies of the session |
| `POST /auth/admin/claims/get` | `{ email }` → `{ email, userId, claims }`, for users with the role `admin`; 401 `no_session`, 403 `forbidden`, 400 `invalid_email`, 404 `user_not_found`. See [Claims](#claims). |
| `POST /auth/admin/claims/set` | `{ email, claims }` → `{ email, userId, claims }`: replaces the claims of the user; also 400 `invalid_claims` |
| `POST /auth/admin/settings/get` | `{}` → `{ methods: { google: { available, enabled }, password: { … } } }`, for admins. See [Sign-in methods](#sign-in-methods). |
| `POST /auth/admin/settings/set` | `{ methods: { google?, password? } }` (booleans) → the same; 400 `invalid_settings` |
| `POST /auth/account/delete` | Deletes the signed-in user's account and clears the session cookie; 401 `no_session`. See [Deleting an account](#deleting-an-account). |
| `GET /.well-known/jwks.json` | Public key to verify sessions |
| `GET /health` | `ok` |

POST requests must come from an origin in `ALLOWED_ORIGINS`. The e-mail endpoints answer 202 whether or not the address has an account, and at most one e-mail per minute is sent to an account. The routes of a sign-in method return 404 when it is not configured, and 403 `method_disabled` when an admin switched it off.
