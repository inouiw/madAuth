# madAuth on AWS (CDK)

Deploys the madAuth server as an AWS Lambda function with a Function URL. The users are stored in a DynamoDB table, and the secrets are kept in the Parameter Store. It costs close to nothing at low traffic: Lambda and DynamoDB are paid per request, and the Parameter Store's standard parameters are free.

What it creates (`lib/madauth-server.ts`, the `MadAuthServer` construct):

- **A DynamoDB table** with the keys `pk` and `sk`. It is on-demand, has point-in-time recovery, and is kept when the stack is deleted.
- **A Lambda function** (Node.js 22, arm64, 512 MB) that runs [`lambda/server.ts`](lambda/server.ts). It reads every parameter under the secrets path, e.g. `/madauth/MADAUTH_SIGNING_KEY`, as the environment variable of that name. The secrets therefore never appear in the function's configuration.

It deploys madAuth 0.3 or newer, which stores every user in the table, with or without e-mail & password sign-in.
- **A Function URL.** madAuth checks the `Origin` of every request itself (`ALLOWED_ORIGINS`).

## What you need

- An AWS account, the AWS CLI signed in (`aws configure` or `aws sso login`), and Node.js 22.13 or newer.
- Your app's origin, e.g. `https://example.com`, where `/auth/*` and `/.well-known/*` will be routed to madAuth (see step 4).
- For Google sign-in: a [Google OAuth client](../../docs/server.md#google-cloud-console-setup).
- For e-mail & password: a webhook receiver that sends the e-mails, e.g. the [aws-ses-mailer](https://github.com/inouiw/madAuth-webhooks/tree/main/aws-ses-mailer).

## 1. Get the template

Download this repository, then install the template's dependencies:

```bash
git clone https://github.com/inouiw/madAuth.git
```

```bash
cd madAuth/deploy/aws && npm install
```

If CDK has never been used in this account and region, bootstrap it once:

```bash
npx cdk bootstrap
```

## 2. Store the secrets

The script creates the signing key and the webhook secret, then asks for the Google client secret. You can leave that empty if you only use Google One Tap / FedCM. The values go straight into the Parameter Store, under `/madauth` by default:

```bash
scripts/bootstrap-secrets.sh /madauth
```

Use the same `WEBHOOK_SECRET` for your webhook receiver.

## 3. Configure and deploy

Set your values in [`cdk.json`](cdk.json) under `context`:

| Key | Example | |
| --- | --- | --- |
| `issuer` | `https://example.com` | Your app's origin (`MADAUTH_ISSUER`). Required. |
| `allowedOrigins` | `https://example.com,https://admin.example.com` | Comma-separated. Default: the issuer |
| `googleClientId` | `123….apps.googleusercontent.com` | Empty: no Google sign-in |
| `secretsPath` | `/madauth` | Where step 2 stored the secrets |
| `webhookUrl` | `https://abc.lambda-url.eu-central-1.on.aws/` | Empty: Google sign-in only |
| `webhookEvents` | `email.verify,email.reset,email.already_registered` | What the receiver handles. This default turns on e-mail & password sign-in. |

Then deploy:

```bash
npx cdk deploy
```

The output `FunctionUrl` is the server, e.g. `https://xyz.lambda-url.eu-central-1.on.aws/`. Check it with:

```bash
curl https://xyz.lambda-url.eu-central-1.on.aws/health
```

## 4. Put it behind your app's origin

madAuth's cookies must be first-party, so the browser should reach the server on your app's origin. Route `/auth/*` and `/.well-known/*` to the Function URL:

- **CloudFront:** add the Function URL as an origin with two behaviors for these paths. Use the cache policy `CachingDisabled`, the origin request policy `AllViewerExceptHostHeader` and all HTTP methods. [`site/infra/lib/site-stack.ts`](../../site/infra/lib/site-stack.ts) does exactly this for madauth.com.
- **Another reverse proxy** (nginx, Caddy, your framework's dev proxy): forward the two paths to the Function URL. Send the Function URL's own `Host` header, and pass the `Origin` and `Cookie` headers through.

For Google's redirect flow, also add `https://example.com/auth/google/callback` as an authorized redirect URI of the Google client.

## Using the construct in your own CDK app

Copy `lib/madauth-server.ts` and `lambda/server.ts` into your app, or install this folder (`npm install <path>/deploy/aws`). Then use it:

```ts
import { MadAuthServer } from '@madauth/deploy-aws';

const madauth = new MadAuthServer(this, 'MadAuth', {
  issuer: 'https://example.com',
  googleClientId: '123.apps.googleusercontent.com',
  secretsPath: '/madauth',
  webhook: { url: mailerUrl, events: ['email.verify', 'email.reset', 'email.already_registered'] },
  reservedConcurrentExecutions: 10,
});
// madauth.functionUrl, madauth.function, madauth.table
```

`environment` adds more settings, e.g. `{ SESSION_TTL: '3600' }`; see [all settings](../../docs/server.md#configuration).

## Administration

The [command line](../../docs/server.md#dynamodb) works with the table, e.g. to make yourself an admin. Use the table name from the stack's resources:

```bash
DATABASE_URL=dynamodb:<table> npx @madauth/server set-roles you@example.com admin
```
