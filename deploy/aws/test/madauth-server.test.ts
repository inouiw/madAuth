// What the construct makes of its webhook receiver, synthesized (nothing is deployed). Run with `npm test`.
import { App, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import type * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { MadAuthServer, signsWebhooksWithIam } from '../lib/madauth-server.js';

const MAILER_URL = 'https://abcdefghijklmnopqrstuvwxyz012345.lambda-url.eu-central-1.on.aws/';
// This repository's server, which signs with AWS IAM whatever its version says.
const SERVER_DIR = fileURLToPath(new URL('../../../packages/server', import.meta.url));

function synth(receiver?: (stack: Stack) => lambda.IFunction, serverPackageDir: string | null = SERVER_DIR) {
  // Not bundled: the functions' code doesn't matter here.
  const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
  const stack = new Stack(app, 'Test', { env: { account: '123456789012', region: 'eu-central-1' } });
  const awsIamReceiver = receiver?.(stack);
  const server = new MadAuthServer(stack, 'MadAuth', { issuer: 'https://example.com', webhook: { url: MAILER_URL, awsIamReceiver }, serverPackageDir: serverPackageDir ?? undefined });
  const template = Template.fromStack(stack);
  const roleId = stack.getLogicalId(server.role.node.defaultChild as iam.CfnRole);
  return { stack, server, template, roleId };
}

/** The environment variables of the server function. */
function serverEnvironment(template: Template): Record<string, unknown> {
  const functions = Object.values(template.findResources('AWS::Lambda::Function', { Properties: { Environment: { Variables: { MADAUTH_KEY_SERVICE: 'aws-kms' } } } }));
  assert.equal(functions.length, 1);
  return functions[0].Properties.Environment.Variables;
}

/** The statements of the server role's policies. */
function serverStatements(template: Template, roleId: string): Record<string, unknown>[] {
  return Object.values(template.findResources('AWS::IAM::Policy', { Properties: { Roles: [{ Ref: roleId }] } })).flatMap(
    (policy) => policy.Properties.PolicyDocument.Statement,
  );
}

test('an AWS_IAM receiver: the server signs with its role, may invoke the URL, and the deploy checks for a webhook secret', () => {
  const { stack, template, roleId } = synth((scope) => {
    const mailer = new lambda.Function(scope, 'Mailer', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('export const handler = async () => ({ statusCode: 204 });'),
    });
    mailer.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.AWS_IAM });
    return mailer;
  });
  const mailerId = stack.getLogicalId(stack.node.findChild('Mailer').node.defaultChild as lambda.CfnFunction);
  const mailerArn = { 'Fn::GetAtt': [mailerId, 'Arn'] };

  assert.deepEqual(
    { WEBHOOK_URL: serverEnvironment(template).WEBHOOK_URL, WEBHOOK_AUTH: serverEnvironment(template).WEBHOOK_AUTH },
    { WEBHOOK_URL: MAILER_URL, WEBHOOK_AUTH: 'aws-iam' },
  );
  // Both actions, each limited to the Function URL with AWS_IAM auth, on the receiver only; in its policy, not the receiver's.
  const invokes = serverStatements(template, roleId).filter((statement) => String(statement.Action).startsWith('lambda:'));
  assert.deepEqual(invokes, [
    { Action: 'lambda:InvokeFunctionUrl', Effect: 'Allow', Resource: mailerArn, Condition: { StringEquals: { 'lambda:FunctionUrlAuthType': 'AWS_IAM' } } },
    { Action: 'lambda:InvokeFunction', Effect: 'Allow', Resource: mailerArn, Condition: { Bool: { 'lambda:InvokedViaFunctionUrl': true } } },
  ]);
  const mailerPermissions = Object.values(template.findResources('AWS::Lambda::Permission')).filter((permission) => JSON.stringify(permission).includes(mailerId));
  assert.deepEqual(mailerPermissions, []);
  template.hasResourceProperties('AWS::Lambda::Url', { AuthType: 'AWS_IAM', TargetFunctionArn: mailerArn });

  // The key manager fails the deploy while <secretsPath>/WEBHOOK_SECRET or WEBHOOK_PREVIOUS_SECRET exists; the new property makes it check again.
  template.hasResourceProperties('Custom::MadAuthKmsKeys', { Deployment: 'example-com', WebhookAuth: 'aws-iam' });
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: {
        SIGNING_KEY_PARAMETER: '/madauth/MADAUTH_SIGNING_KEY',
        WEBHOOK_SECRET_PARAMETER: '/madauth/WEBHOOK_SECRET',
        WEBHOOK_PREVIOUS_SECRET_PARAMETER: '/madauth/WEBHOOK_PREVIOUS_SECRET',
      },
    },
  });
  template.hasResourceProperties('AWS::IAM::Policy', {
    PolicyDocument: {
      Statement: Match.arrayWith([
        {
          Action: 'ssm:GetParameters',
          Effect: 'Allow',
          Resource: [
            { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':ssm:eu-central-1:123456789012:parameter/madauth/MADAUTH_SIGNING_KEY']] },
            { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':ssm:eu-central-1:123456789012:parameter/madauth/WEBHOOK_SECRET']] },
            { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':ssm:eu-central-1:123456789012:parameter/madauth/WEBHOOK_PREVIOUS_SECRET']] },
          ],
        },
      ]),
    },
  });
  template.hasOutput('*', { Value: { 'Fn::GetAtt': [roleId, 'Arn'] } });
});

test('an AWS_IAM receiver deployed elsewhere, by its ARN (webhookFunctionArn in cdk.json)', () => {
  const arn = 'arn:aws:lambda:eu-central-1:123456789012:function:madauth-mailer';
  const { template, roleId } = synth((scope) => lambda.Function.fromFunctionArn(scope, 'Mailer', arn));

  assert.equal(serverEnvironment(template).WEBHOOK_AUTH, 'aws-iam');
  assert.deepEqual(
    serverStatements(template, roleId)
      .filter((statement) => String(statement.Action).startsWith('lambda:'))
      .map((statement) => [statement.Action, statement.Resource]),
    [
      ['lambda:InvokeFunctionUrl', arn],
      ['lambda:InvokeFunction', arn],
    ],
  );
});

test('a receiver with the webhook secret, as before: no AWS IAM and no check for the secret', () => {
  const { template, roleId } = synth();

  assert.equal(serverEnvironment(template).WEBHOOK_AUTH, undefined);
  assert.deepEqual(
    serverStatements(template, roleId).filter((statement) => String(statement.Action).startsWith('lambda:')),
    [],
  );
  template.hasResourceProperties('Custom::MadAuthKmsKeys', { Deployment: 'example-com', WebhookAuth: Match.absent() });
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: { SIGNING_KEY_PARAMETER: '/madauth/MADAUTH_SIGNING_KEY', WEBHOOK_SECRET_PARAMETER: Match.absent(), WEBHOOK_PREVIOUS_SECRET_PARAMETER: Match.absent() },
    },
  });
});

test('an AWS_IAM receiver needs an installed server that knows WEBHOOK_AUTH', () => {
  assert.equal(signsWebhooksWithIam('0.6.0-beta.1'), false);
  assert.equal(signsWebhooksWithIam('0.6.0-beta.2'), false);
  assert.equal(signsWebhooksWithIam('0.6.0'), false);
  assert.equal(signsWebhooksWithIam('0.7.0-beta.1'), true);

  // The installed package, not this repository's (synth without serverPackageDir).
  const entry = import.meta.resolve('@madauth/server/aws-kms');
  const installed = (JSON.parse(readFileSync(new URL('../package.json', entry), 'utf8')) as { version: string }).version;
  const receiver = (scope: Stack) => lambda.Function.fromFunctionArn(scope, 'Mailer', 'arn:aws:lambda:eu-central-1:123456789012:function:madauth-mailer');
  if (signsWebhooksWithIam(installed)) {
    assert.doesNotThrow(() => synth(receiver, null));
  } else {
    assert.throws(() => synth(receiver, null), { message: new RegExp(`needs a madAuth server newer than 0\\.6\\.0,.*@madauth/server ${installed.replaceAll('.', '\\.')} is installed`) });
  }
  // Without AWS IAM, any version does.
  assert.doesNotThrow(() => synth(undefined, null));
});
