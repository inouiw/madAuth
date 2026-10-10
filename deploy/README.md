# Deploying the madAuth server

Templates that host the madAuth server in your own cloud account, one folder per target. Each one runs the
same server; they differ in where the users are stored and how the secrets are kept.

| Target | Folder | Google sign-in | E-mail & password | Users stored in |
| --- | --- | --- | --- | --- |
| AWS Lambda | [`aws/`](aws/README.md) | yes | yes | DynamoDB |
| Docker (any VM or container host) | [`docs/server.md`](../docs/server.md#docker) | yes | yes | SQLite on a volume |
| Azure Functions | [`docs/server.md`](../docs/server.md#azure-functions) | yes | needs a [custom store adapter](../docs/server.md#custom-store-adapter) | – |

More templates (Azure, Docker with HTTPS) will be added next to `aws/`.

## Wherever you host it

- **Serve madAuth from your app's origin.** Route `/auth/*` and `/.well-known/*` of your app's domain to the
  server (a CloudFront behavior, a reverse proxy rule, …). Then madAuth's cookies are first-party, and
  `MADAUTH_ISSUER` is your app's origin, e.g. `https://example.com`.
- **E-mail & password needs a webhook receiver** that sends the e-mails, e.g. the
  [aws-ses-mailer](https://github.com/inouiw/madAuth-webhooks/tree/main/aws-ses-mailer).
- **Limit requests per IP address** in front of the server (WAF, reverse proxy): madAuth's brute-force
  protection is per account. See [Password security](../docs/password-security.md).

madauth.com itself is deployed with the AWS template: see [`site/infra`](../site/infra/README.md).
