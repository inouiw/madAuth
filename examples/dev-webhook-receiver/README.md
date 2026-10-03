# Development webhook receiver

Receives madAuth's [webhook](../../docs/server.md#webhooks) calls during development and prints them instead of sending e-mails: each confirmation and reset e-mail appears in the terminal with its link and 6-digit code.

It reads `WEBHOOK_URL` and `WEBHOOK_SECRET` from `packages/server/.env` (the same settings the madAuth server uses), and listens on `WEBHOOK_URL`'s port. Start it from the repository root:

```bash
npm run dev:webhooks
```

To try the sign-up check, start it with `ALLOWED_EMAIL_DOMAINS`. Sign-ups from other domains are then refused with a message:

```bash
ALLOWED_EMAIL_DOMAINS=example.com npm run dev:webhooks
```

The code ([`src/receiver.ts`](src/receiver.ts)) is also a small example of a receiver: it verifies the signature with `verifyWebhook` from `@madauth/server/webhook`, then answers each `type`. To send real e-mails, see the [Amazon SES example](../aws-ses-mailer).
