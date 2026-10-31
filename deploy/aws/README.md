# madAuth on AWS (CDK)

Deploys the madAuth server as an AWS Lambda function with a Function URL. The users are stored in a DynamoDB table, madAuth's keys in AWS KMS, and the secrets in the Parameter Store. At low traffic it costs about $3 a month, for the three KMS keys: Lambda, DynamoDB and KMS's requests are paid per request, and the Parameter Store's standard parameters are free.

What it creates (`lib/madauth-server.ts`, the `MadAuthServer` construct):

- **A DynamoDB table** with the keys `pk` and `sk`. It is on-demand, has point-in-time recovery, and is kept when the stack is deleted.
- **A Lambda function** (Node.js 22, arm64, 512 MB) that runs [`lambda/server.ts`](lambda/server.ts). It reads every parameter under the secrets path, e.g. `/madauth/WEBHOOK_SECRET`, as the environment variable of that name. The secrets therefore never appear in the function's configuration.
- **Three keys in AWS KMS** that sign the sessions, hash the codes and encrypt the stored secrets (`MADAUTH_KEY_SERVICE=aws-kms`, see [AWS KMS](../../docs/server.md#aws-kms)). They never leave KMS, and the server's role may only use them. A second function with a role of its own, [`lambda/keys.ts`](lambda/keys.ts), creates them at the first deploy, checks them every day and rotates them once a year; a failed rotation is an error of that function (`keyManager`), which an alarm can watch. The keys are kept when the stack is deleted, like the table: without them nothing stored in it can be read. Each costs $1 a month, and every rotation, once a year, adds one. They are named after the issuer: a new `issuer` gets new keys, which signs every user out, and the old ones stay, and cost, until you schedule their deletion in KMS.

It deploys madAuth 0.6 or newer, the first that keeps its keys in AWS KMS.
- **A Function URL.** madAuth checks the `Origin` of every request itself (`ALLOWED_ORIGINS`).
- **For a webhook receiver whose Function URL has `AWS_IAM` auth** (`webhookFunctionArn`): the server's role may invoke it, and madAuth signs its calls with that role (`WEBHOOK_AUTH=aws-iam`) instead of a webhook secret. See [A webhook receiver with AWS IAM](#a-webhook-receiver-with-aws-iam).

## What you need

- An AWS account, the AWS CLI signed in (`aws configure` or `aws sso login`), and Node.js 22.13 or newer.
- Your app's origin, e.g. `https://example.com`, where `/auth/*` and `/.well-known/*` will be routed to madAuth (see step 4).
- For Google sign-in: a [Google OAuth client](../../docs/server.md#google-cloud-console-setup).
- For GitHub sign-in: a [GitHub OAuth App](../../docs/server.md#github-oauth-app-setup).
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

The script creates the webhook secret (after asking: answer `n` for a receiver with AWS IAM). It goes straight into the Parameter Store, under `/madauth` by default. Google and GitHub are no secrets of the deployment: an admin adds them later as providers (step 5).

```bash
scripts/bootstrap-secrets.sh /madauth
```

Use the same `WEBHOOK_SECRET` for your webhook receiver. A receiver with AWS IAM (see [below](#a-webhook-receiver-with-aws-iam)) needs no secret, and the deploy fails while there is one; for it, run the script with `WEBHOOK_AUTH=aws-iam`, which creates none:

```bash
WEBHOOK_AUTH=aws-iam scripts/bootstrap-secrets.sh /madauth
```

## 3. Configure and deploy

Set your values in [`cdk.json`](cdk.json) under `context`:

| Key | Example | |
| --- | --- | --- |
| `issuer` | `https://example.com` | Your app's origin (`MADAUTH_ISSUER`). Required. |
| `allowedOrigins` | `https://example.com,https://admin.example.com` | Comma-separated. Default: the issuer |
| `secretsPath` | `/madauth` | Where step 2 stored the secrets |
| `webhookUrl` | `https://abc.lambda-url.eu-central-1.on.aws/` | Empty: no e-mails, so people sign in only through the providers an admin adds (step 5) |
| `webhookFunctionArn` | `arn:aws:lambda:eu-central-1:123456789012:function:madauth-mailer` | The receiver's function, when `webhookUrl` is its Function URL with `AWS_IAM` auth, in this account. Empty: the calls are signed with `WEBHOOK_SECRET`. See [A webhook receiver with AWS IAM](#a-webhook-receiver-with-aws-iam). |
| `webhookEvents` | `email.send_verification,email.send_password_reset,email.send_already_registered` | What the receiver handles. This default turns on e-mail & password sign-in; add `email.send_signin_link` for the e-mail link. |
| `environment` | `{ "INITIAL_ADMIN_EMAIL": "you@example.com" }` | More environment variables of the server, each under its own name, see [all settings](../../docs/server.md#configuration): `INITIAL_ADMIN_EMAIL` makes you the first admin (madAuth 0.6 or newer, see [Administration](#administration)), others are e.g. `PASSKEY_RP_ID`, `AUTHENTICATOR_ISSUER` or `SESSION_TTL`. |

Then deploy:

```bash
npx cdk deploy
```

The first deploy also creates the keys. KMS may take up to five minutes to let the server use them, so the server may answer errors until then. The output `FunctionUrl` is the server, e.g. `https://xyz.lambda-url.eu-central-1.on.aws/`. Check it with:

```bash
curl https://xyz.lambda-url.eu-central-1.on.aws/health
```

## 4. Put it behind your app's origin

madAuth's cookies must be first-party, so the browser should reach the server on your app's origin. Route `/auth/*` and `/.well-known/*` to the Function URL:

- **CloudFront:** add the Function URL as an origin with two behaviors for these paths. Use the cache policy `CachingDisabled`, the origin request policy `AllViewerExceptHostHeader` and all HTTP methods. [`site/infra/lib/site-stack.ts`](../../site/infra/lib/site-stack.ts) does exactly this for madauth.com.
- **Another reverse proxy** (nginx, Caddy, your framework's dev proxy): forward the two paths to the Function URL. Send the Function URL's own `Host` header, and pass the `Origin` and `Cookie` headers through.

## 5. Add Google or GitHub

Google and GitHub sign-in are providers in madAuth's store, which an admin adds through the admin API; the sign-in dialog then shows their buttons by itself. Until the first admin exists, the server prints a setup token in its log at every start (in CloudWatch, the function's log group): `[madauth] No admin yet. This setup token …`. With it, add a provider and switch it on:

```bash
curl -X POST https://example.com/auth/admin/providers/add -H 'Authorization: Bearer madauth_setup_…' -H 'Content-Type: application/json' \
  -d '{"kind":"github","clientId":"Ov23li…","clientSecret":"…"}'
```

The answer's `callbackUrl` is what the provider needs: `https://example.com/auth/providers/google/callback` as an authorized redirect URI of the Google client, `https://example.com/auth/providers/github/callback` as the OAuth App's authorization callback URL. Then switch it on with `POST /auth/admin/settings/set` (see [Providers](../../docs/server.md#providers)), and sign in with `INITIAL_ADMIN_EMAIL`, which makes you the first admin and ends the setup. After that, admins change providers with `Madauth.admin.addProvider` and the like.

## A webhook receiver with AWS IAM

When the receiver is a Lambda function in the same account, e.g. the [aws-ses-mailer](https://github.com/inouiw/madAuth-webhooks/tree/main/aws-ses-mailer), IAM replaces the webhook secret: the receiver's Function URL has `AWS_IAM` auth, so AWS refuses a call that the server's role didn't sign before the receiver runs, and the receiver accepts only that role. No secret is shared or stored (see [AWS IAM](../../docs/server.md#aws-iam)). It needs a madAuth server newer than 0.6.0: with an older `@madauth/server` installed, the template refuses to synthesize.

The receiver needs the server's role and the server the receiver's function, so it takes three steps:

1. Deploy madAuth as in step 3, without `webhookUrl` (or with your receiver as it is). The output `RoleArn` is the server's role.
2. Deploy the receiver with `AWS_IAM` auth and that role, e.g. the aws-ses-mailer with `MadauthRoleArn` (see its README). Note its URL and its function's ARN.
3. Set `webhookUrl` and `webhookFunctionArn` in `cdk.json` and deploy madAuth again. The server's role may now invoke the receiver through its URL (`lambda:InvokeFunctionUrl`, and `lambda:InvokeFunction` with `lambda:InvokedViaFunctionUrl`), and madAuth signs every call with it (`WEBHOOK_AUTH=aws-iam`).

There must be no `<secretsPath>/WEBHOOK_SECRET` and no `<secretsPath>/WEBHOOK_PREVIOUS_SECRET`: madAuth refuses to start with a secret and `WEBHOOK_AUTH=aws-iam`, so the deploy fails while one exists, and the running server keeps working. To move an existing deployment, see [Switching the webhook receiver to AWS IAM](#switching-the-webhook-receiver-to-aws-iam).

## Using the construct in your own CDK app

Copy `lib/madauth-server.ts`, `lambda/server.ts` and `lambda/keys.ts` into your app and add `@madauth/server` 0.6 or newer to its dependencies (the construct reads the KMS policy from it), and `@smithy/signature-v4` for `awsIamReceiver` (the server's bundle takes it from there), or install this folder (`npm install <path>/deploy/aws`). Then use it:

```ts
import { EMAIL_LINK_EVENTS, MadAuthServer } from '@madauth/deploy-aws';

const madauth = new MadAuthServer(this, 'MadAuth', {
  issuer: 'https://example.com',
  secretsPath: '/madauth',
  // The e-mails of e-mail & password and of the e-mail link; EMAIL_EVENTS without the e-mail link.
  webhook: { url: mailerUrl, events: EMAIL_LINK_EVENTS },
  reservedConcurrentExecutions: 10,
});
// madauth.functionUrl, madauth.function, madauth.role, madauth.table, madauth.keyManager
```

With a receiver in the same app, IAM replaces the webhook secret (see [above](#a-webhook-receiver-with-aws-iam)): its Function URL has `AWS_IAM` auth, `awsIamReceiver` lets the server's role invoke it, and the receiver learns the role, e.g. the aws-ses-mailer as `MADAUTH_ROLE_ARN`:

```ts
const mailerUrl = mailer.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.AWS_IAM });
const madauth = new MadAuthServer(this, 'MadAuth', {
  issuer: 'https://example.com',
  webhook: { url: mailerUrl.url, events: EMAIL_LINK_EVENTS, awsIamReceiver: mailer },
});
mailer.addEnvironment('MADAUTH_ROLE_ARN', madauth.role.roleArn);
```

[`site/infra/lib/site-stack.ts`](../../site/infra/lib/site-stack.ts) does this for madauth.com.

A failed key rotation is an error of `keyManager`. To hear of it, alarm on its errors, e.g. to an SNS topic:

```ts
madauth.keyManager.metricErrors({ period: Duration.days(1) }).createAlarm(this, 'KeyRotationFailed', {
  threshold: 1,
  evaluationPeriods: 1,
}).addAlarmAction(new SnsAction(topic));
```

`environment` adds more settings, e.g. `{ SESSION_TTL: '3600' }`; see [all settings](../../docs/server.md#configuration).

## Upgrading from a template before madAuth 0.7

The template's `googleClientId` and `githubClientId` are gone: Google and GitHub are providers in the store, which an admin adds (step 5). So after the upgrade, Google and GitHub sign-in are off until an admin adds them, with the client IDs from `cdk.json` and the secrets from the Google Cloud Console and the GitHub OAuth App. Their routes moved too: update the redirect URI at Google and the callback URL at GitHub to `https://example.com/auth/providers/google/callback` and `…/auth/providers/github/callback`. Then delete the old secrets, which nothing reads any more:

```bash
aws ssm delete-parameter --name /madauth/GOOGLE_CLIENT_SECRET
```

```bash
aws ssm delete-parameter --name /madauth/GITHUB_CLIENT_SECRET
```

## Upgrading from a template before madAuth 0.6

The template kept madAuth's keys in the Parameter Store, as `<secretsPath>/MADAUTH_SIGNING_KEY`; now they are in AWS KMS. The move is a clean cut: what the old key made can't be read any more, so every user is signed out, and the authenticator apps and recovery codes set up before stop working (see [AWS KMS](../../docs/server.md#aws-kms)). While the old key is in the Parameter Store, the deploy fails and rolls back, and the running server keeps working. When you are ready, delete it and deploy right away (the running server can't start new instances without it):

```bash
aws ssm delete-parameter --name /madauth/MADAUTH_SIGNING_KEY
```

```bash
npx cdk deploy
```

## Switching the webhook receiver to AWS IAM

For a deployment whose receiver checks `WEBHOOK_SECRET`, to a receiver with AWS IAM as [above](#a-webhook-receiver-with-aws-iam). While the deploy fails because `<secretsPath>/WEBHOOK_SECRET` exists, the running server keeps working. Once you delete it, the running server can't start new instances, so deploy right away:

1. Note the ARN of the receiver's function (in the Lambda console) and set it as `webhookFunctionArn` in `cdk.json`.
2. Delete the secret and deploy:

   ```bash
   aws ssm delete-parameter --name /madauth/WEBHOOK_SECRET
   ```

   ```bash
   npx cdk deploy
   ```

3. Deploy the receiver with `AWS_IAM` auth and the output `RoleArn`, e.g. the aws-ses-mailer with `MadauthRoleArn` and without `WebhookSecret`.

From step 2 until step 3 is deployed, the receiver refuses madAuth's calls (they carry no secret's signature any more): no e-mail is sent, and with `user.signing_up` nobody signs up; users see that it failed and can try again. A receiver in the same CDK app (see the construct above) switches in the same deploy as the server.

## Changing the webhook secret

For a receiver that checks `WEBHOOK_SECRET`, without a gap in which it refuses madAuth's calls (see [Changing the webhook secret](../../docs/server.md#changing-the-webhook-secret)). The server reads the Parameter Store when an instance starts, so after each change to the parameters, make it start new instances: any change to the server function's configuration does, e.g. `cdk deploy` with a changed `environment` value, or `aws lambda update-function-configuration --function-name <the server's function> --description "<anything new>"`.

1. Keep the old secret as the previous one and store a new one:

   ```bash
   aws ssm put-parameter --name /madauth/WEBHOOK_PREVIOUS_SECRET --type SecureString --value "$(aws ssm get-parameter --name /madauth/WEBHOOK_SECRET --with-decryption --query Parameter.Value --output text)"
   ```

   ```bash
   aws ssm put-parameter --name /madauth/WEBHOOK_SECRET --type SecureString --overwrite --value "$(npx --yes @madauth/server generate-webhook-secret)"
   ```

   Then make the server start new instances. Every call now carries both signatures.
2. Give the receiver the new secret, e.g. the aws-ses-mailer's `WebhookSecret`.
3. Delete the previous secret and make the server start new instances again:

   ```bash
   aws ssm delete-parameter --name /madauth/WEBHOOK_PREVIOUS_SECRET
   ```

## Administration

Set `INITIAL_ADMIN_EMAIL` under `environment` in `cdk.json` to your address and deploy (step 3), then sign in with that address in your app. Once the address is proven, you have the role `admin` and manage claims and sign-in methods from your app with `Madauth.admin`. Give a second user the role as well, so that one admin can help the other. A value applies once: to make another admin later, e.g. when the only admin is locked out, set a new address and deploy again. See [The first admin](../../docs/server.md#the-first-admin).
