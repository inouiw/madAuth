// A stack with only the madAuth server. Configure it in cdk.json ("context") or with -c, e.g.
//   npx cdk deploy -c issuer=https://example.com -c googleClientId=123.apps.googleusercontent.com
import { App, Stack } from 'aws-cdk-lib';
import { MadAuthServer } from '../lib/madauth-server.js';

const app = new App();
const context = (key: string): string => String(app.node.tryGetContext(key) ?? '');
const list = (key: string): string[] | undefined => {
  const items = context(key).split(',').filter(Boolean);
  return items.length ? items : undefined;
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
  secretsPath: context('secretsPath') || undefined,
  webhook: context('webhookUrl') ? { url: context('webhookUrl'), events: list('webhookEvents') } : undefined,
});
