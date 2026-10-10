// madauth.com. The settings are in cdk.json ("context"); the ones that are not public come from the environment
// or -c: alertEmail (budget alert), githubOidcProviderArn (if the account already has a GitHub OIDC provider),
// webhooksDir (a checkout of madAuth-webhooks; default: next to this repository).
// Build the packages, the landing page and the demo (DEMO_BASE=/demo/) before synthesizing; see README.md.
import { App } from 'aws-cdk-lib';
import { fileURLToPath } from 'node:url';
import { CertificateStack, ZoneStack } from '../lib/dns-stack.js';
import { GithubOidcStack } from '../lib/github-oidc-stack.js';
import { SiteStack } from '../lib/site-stack.js';

const app = new App();
const context = (key: string): string | undefined => app.node.tryGetContext(key) || process.env[key] || undefined;

const domain = context('domain')!;
const account = process.env.CDK_DEFAULT_ACCOUNT;
const region = context('region')!;
// CloudFront only uses certificates from us-east-1.
const usEast1 = { account, region: 'us-east-1' };

const zone = new ZoneStack(app, 'MadAuthSiteZone', { env: usEast1, crossRegionReferences: true, domain });
const certificate = new CertificateStack(app, 'MadAuthSiteCertificate', {
  env: usEast1,
  crossRegionReferences: true,
  domain,
  zone: zone.zone,
});

new SiteStack(app, 'MadAuthSite', {
  env: { account, region },
  crossRegionReferences: true,
  domain,
  zone: zone.zone,
  certificate: certificate.certificate,
  googleClientId: context('googleClientId'),
  webhooksDir: context('webhooksDir') ?? fileURLToPath(new URL('../../../../madAuth-webhooks', import.meta.url)),
  alertEmail: context('alertEmail'),
});

new GithubOidcStack(app, 'MadAuthSiteGithub', {
  env: { account, region },
  repo: context('githubRepo')!,
  environment: context('githubEnvironment')!,
  existingProviderArn: context('githubOidcProviderArn'),
});
