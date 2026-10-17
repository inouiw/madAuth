// A stack with only the madAuth server. Configure it in cdk.json ("context") or with -c, e.g.
//   npx cdk deploy -c issuer=https://example.com -c webhookUrl=https://abc.lambda-url.eu-central-1.on.aws/
// "environment" holds more environment variables of the server, each under its own name (docs/server.md), e.g.
//   -c 'environment={"INITIAL_ADMIN_EMAIL":"you@example.com"}'
import { App, Stack } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
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

if (context('webhookFunctionArn') && !context('webhookUrl')) {
  throw new Error('webhookFunctionArn is the function of the receiver at webhookUrl: set webhookUrl too, to its Function URL.');
}
// A receiver whose Function URL has AWS_IAM auth: the server signs its calls with its role instead of the webhook secret.
const awsIamReceiver = context('webhookFunctionArn') ? lambda.Function.fromFunctionArn(stack, 'WebhookReceiver', context('webhookFunctionArn')) : undefined;

new MadAuthServer(stack, 'MadAuth', {
  issuer: context('issuer'),
  allowedOrigins: list('allowedOrigins'),
  secretsPath: context('secretsPath') || undefined,
  webhook: context('webhookUrl') ? { url: context('webhookUrl'), events: list('webhookEvents'), awsIamReceiver } : undefined,
  environment: map('environment'),
});
