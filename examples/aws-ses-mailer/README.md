# Sending madAuth's e-mails with Amazon SES

A madAuth [webhook](../../docs/server.md#webhooks) receiver on AWS Lambda that sends the confirmation and password-reset e-mails with [Amazon SES](https://aws.amazon.com/ses/). It:

- checks that each call is signed with your `WEBHOOK_SECRET`
- renders the e-mail ([`src/templates.ts`](src/templates.ts)) with the link and the 6-digit code
- answers `200` only after SES has accepted the e-mail. Otherwise it answers `502`, and madAuth tells the user that e-mails can't be sent right now.

Other calls (the sign-up check and events) are answered with `204`, which allows sign-ups. madAuth only sends them if you add their types to `WEBHOOK_EVENTS`; add your own logic to [`src/handler.ts`](src/handler.ts) if you need it.

Costs: SES charges about $0.10 per 1000 e-mails. The Lambda function stays in the free tier for most sites.

## What you need

- An AWS account and the [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html), signed in (`aws configure` or `aws sso login`).
- A domain you can add DNS records to, e.g. `example.com`. The e-mails come from an address at it, e.g. `no-reply@example.com`.

## 1. Verify your domain in SES

Pick one AWS region for SES and the function, e.g. `eu-central-1`, and use it everywhere below.

1. Open the [SES console](https://console.aws.amazon.com/ses/) → **Identities** → **Create identity** → **Domain**, and enter your domain.
2. Keep **Easy DKIM** (RSA 2048) selected and create the identity. SES shows three CNAME records: add them at your DNS provider. After a few minutes to hours, the identity shows **Verified**.
3. Recommended: under **Custom MAIL FROM domain**, set e.g. `mail.example.com` and add the MX and TXT records SES shows. Then SPF passes with your own domain.
4. Recommended: add a DMARC record if your domain has none, e.g. a TXT record at `_dmarc.example.com` with `v=DMARC1; p=none; rua=mailto:dmarc@example.com`. Mail providers such as Gmail expect one.

## 2. Leave the SES sandbox

New SES accounts are in a sandbox: they can only send to addresses you verified yourself, and at most 200 e-mails a day. That's enough for a first test (verify your own address under **Identities** → **Create identity** → **Email address**). Before real users sign up, open **Account dashboard** → **Request production access** and describe the use: "transactional e-mails (address confirmation and password reset) for sign-ups on our site". AWS usually answers within a day.

## 3. Create the webhook secret

madAuth and this function share one secret. Create it once:

```bash
npx @madauth/server generate-webhook-secret
```

In this repository: `npm run cli -w packages/server -- generate-webhook-secret`.

## 4. Deploy

From this directory:

```bash
sam build
```

```bash
sam deploy --guided
```

The guided deploy asks for:

| Parameter | Example |
| --- | --- |
| Stack name | `madauth-mailer` |
| AWS region | the SES region from step 1 |
| `WebhookSecret` | the secret from step 3 |
| `MailFrom` | `"Example" <no-reply@example.com>` |
| `SendingDomain` | `example.com` (the identity from step 1) |
| `ConfigurationSet` | leave empty, or see "Bounces and complaints" below |

Confirm "MailerFunction Function Url has no authentication" with `y`: the function checks every call's signature itself. At the end, SAM prints the output **WebhookUrl**, e.g. `https://abc123.lambda-url.eu-central-1.on.aws/`.

If `sam build` fails with `Unknown cli flag: --unsafe-perm`, your SAM CLI is older than your npm. Update the SAM CLI.

## 5. Connect madAuth

Set these on the madAuth server and restart it:

```
WEBHOOK_URL=https://abc123.lambda-url.eu-central-1.on.aws/
WEBHOOK_SECRET=<the same secret>
WEBHOOK_EVENTS=email.verify,email.reset,email.already_registered
```

`WEBHOOK_EVENTS` lists what this function handles: the three e-mails. madAuth then sends nothing else to it.

## 6. Test

Sign up in your app with an address you can read (in the sandbox, a verified one). The confirmation e-mail should arrive within seconds.

If it doesn't, check these in order:
- **The madAuth server's log:** `[madauth] Webhook "email.verify" … failed: HTTP 401` means the two secrets differ. `HTTP 502` means SES refused the e-mail.
- **The function's log** in CloudWatch (Lambda console → the function → **Monitor** → **View CloudWatch logs**), which contains SES's reason, e.g. `MessageRejected: Email address is not verified` while in the sandbox.
- **Your spam folder.** If the e-mail lands there, check that DKIM and DMARC are set up (step 1).

## Bounces and complaints

SES suspends accounts whose e-mails bounce or are marked as spam too often. Watch the rates under **Account dashboard** → **Reputation metrics**. To record each bounce and complaint, create a **configuration set** with an event destination (e.g. an SNS topic that e-mails you), and deploy again with its name as `ConfigurationSet`.

## Changing the e-mails

Edit [`src/templates.ts`](src/templates.ts) and deploy again (`sam build && sam deploy`). Each call contains the user's browser language as `data.locale` (e.g. `de-CH`), if you want to send translated e-mails.
