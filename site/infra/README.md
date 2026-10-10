# madauth.com infrastructure

The AWS CDK app behind https://madauth.com. One CloudFront distribution serves everything:

| Path | Served from |
| --- | --- |
| `/` | the landing page (`site/dist`) in S3 |
| `/demo/` | the demo (`demo/dist`, built with `DEMO_BASE=/demo/`) in S3 |
| `/auth/*`, `/.well-known/*` | the demo's madAuth server: the [`MadAuthServer`](../../deploy/aws/README.md) construct, the same template users get |

E-mails (confirmation, password reset) go through the [aws-ses-mailer](https://github.com/inouiw/madAuth-webhooks/tree/main/aws-ses-mailer) of madAuth-webhooks. It sends with SES from `noreply@madauth.com`.

The app has four stacks:

| Stack | Region | |
| --- | --- | --- |
| `MadAuthSiteZone` | us-east-1 | Route 53 hosted zone of madauth.com |
| `MadAuthSiteCertificate` | us-east-1 | TLS certificate for CloudFront |
| `MadAuthSite` | eu-central-1 | Server, mailer, SES identity, S3, CloudFront, DNS records, budget |
| `MadAuthSiteGithub` | eu-central-1 | The role GitHub Actions deploys with (OIDC, no stored keys) |

## Security

Nothing in this folder is secret.

- **Secrets** are SecureString parameters under `/madauth-site/` in the Parameter Store, read by the functions at runtime: the signing key, the webhook secret and the Google client secret.
- **The account ID** comes from the AWS credentials. `cdk.context.json` and `cdk.out/` are not committed.
- **Deploys** run only in the GitHub environment `site`, which has required reviewers. The deploy role trusts only that environment, so pull requests can't use it.
- **Abuse limits:** the server runs with at most 5 concurrent executions and the mailer with at most 2. A budget alert fires at $8 of the $10/month budget.

## One-time setup

Run these with AWS credentials for the account (`aws sso login`). First install and build:

```bash
npm ci && npm run build -w packages/server -w site && DEMO_BASE=/demo/ npm run build -w demo
```

```bash
cd deploy/aws && npm ci && npm run build && cd ../../site/infra && npm ci
```

1. **Bootstrap CDK** in both regions:

   ```bash
   npx cdk bootstrap aws://<account>/eu-central-1 aws://<account>/us-east-1
   ```

2. **Create the hosted zone** (every command synthesizes the whole app, so it needs the madAuth-webhooks checkout of step 5 too), then copy the four name servers from the output `NameServers` to madauth.com's settings at domaindiscount24. Wait until `dig NS madauth.com` shows them.

   ```bash
   npx cdk deploy MadAuthSiteZone
   ```

3. **Create a Google OAuth client** in the Google Cloud Console (Web application):
   - Authorized JavaScript origin: `https://madauth.com`.
   - Authorized redirect URI: `https://madauth.com/auth/google/callback`.

   Put its client ID into `cdk.json` as `googleClientId` and commit it; client IDs are public.

4. **Store the secrets.** When the script asks for the Google client secret, enter the new client's secret:

   ```bash
   AWS_REGION=eu-central-1 ../../deploy/aws/scripts/bootstrap-secrets.sh /madauth-site
   ```

5. **Deploy everything.** It needs a checkout of [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks), next to this repository by default; pass `-c webhooksDir=<path>` for another place:

   ```bash
   npx cdk deploy --all -c alertEmail=you@example.com
   ```

6. **Leave the SES sandbox.** In the SES console (eu-central-1), go to **Account dashboard** → **Request production access**. Until AWS grants it, e-mails only reach verified addresses.

7. **Set up GitHub deploys:**
   - Create the environment `site` with yourself as required reviewer. Limit it to tags `v*` and the branch `main`.
   - Add the variable `AWS_DEPLOY_ROLE_ARN` (the output `DeployRoleArn` of `MadAuthSiteGithub`) and the secret `ALERT_EMAIL`.
   - If the account already has a GitHub OIDC provider (an account can only have one), deploy `MadAuthSiteGithub` with `-c githubOidcProviderArn=<its ARN>`.
   - The role trusts the repository by GitHub's ids (`githubOwnerId` and `githubRepoId` in `cdk.json`, from `gh api repos/inouiw/madAuth --jq '[.owner.id, .id]'`), not by name: a repository with "immutable subject claims" on identifies itself by the ids, and a repository that later takes over the name can't deploy. Without the ids the role trusts the name, and a repository with immutable claims fails with "Not authorized to perform sts:AssumeRoleWithWebIdentity".

## Deploying

[`deploy-site.yml`](../../.github/workflows/deploy-site.yml) deploys `MadAuthSite` on every release tag (`v*`). You can also run it by hand from the Actions tab. It builds the server, the landing page and the demo from the tagged commit.

After changing `deploy/aws`, run `npm run build` there and `npm install` here, so this app uses the new version.

## Checking a deployment

```bash
curl https://madauth.com/.well-known/jwks.json
```

Then sign in at https://madauth.com/demo/ with Google and with e-mail & password.
