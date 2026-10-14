// A stack with only the madAuth server. Configure it in cdk.json ("context") or with -c, e.g.
//   npx cdk deploy -c issuer=https://example.com -c googleClientId=123.apps.googleusercontent.com
// "environment" holds more environment variables of the server, each under its own name (docs/server.md), e.g.
//   -c 'environment={"INITIAL_ADMIN_EMAIL":"you@example.com"}'
import { App, Stack } from 'aws-cdk-lib';
import { MadAuthServer } from '../lib/madauth-server.js';

const app = new App();
const context = (key: string): string => String(app.node.tryGetContext(key) ?? '');
const list = (key: string): string[] | undefined => {
  const items = context(key).split(',').filter(Boolean);
  return items.length ? items : undefined;
};
/** The map under `key`: an object in cdk.json, JSON text with -c. */
const map = (key: string): Record<string, string> => {
  const value: unknown = app.node.tryGetContext(key) ?? {};
  const parsed: unknown = typeof value === 'string' ? JSON.parse(value || '{}') : value;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Set ${key} in cdk.json (context) to a map of environment variables, e.g. { "INITIAL_ADMIN_EMAIL": "you@example.com" }.`);
  }
  const entries = Object.entries(parsed);
  const wrong = entries.find(([, item]) => typeof item !== 'string');
  if (wrong) throw new Error(`${key}.${wrong[0]} in cdk.json (context) must be a string, as every environment variable is.`);
  return Object.fromEntries(entries) as Record<string, string>;
};

const stack = new Stack(app, context('stackName') || 'MadAuth', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
});

if (!context('issuer')) {
  throw new Error('Set issuer in cdk.json (context) or with -c issuer=https://example.com: the origin of your app.');
}

new MadAuthServer(stack, 'MadAuth', {
  issuer: context('issuer'),
  allowedOrigins: list('allowedOrigins'),
  googleClientId: context('googleClientId') || undefined,
  githubClientId: context('githubClientId') || undefined,
  secretsPath: context('secretsPath') || undefined,
  webhook: context('webhookUrl') ? { url: context('webhookUrl'), events: list('webhookEvents') } : undefined,
  environment: map('environment'),
});
