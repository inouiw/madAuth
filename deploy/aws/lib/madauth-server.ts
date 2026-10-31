import { deploymentOf, serverKmsPolicy } from '@madauth/server/aws-kms';
import { CfnOutput, CustomResource, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The events a receiver that sends the e-mails handles, e.g. the aws-ses-mailer of madAuth-webhooks. */
export const EMAIL_EVENTS = ['email.send_verification', 'email.send_password_reset', 'email.send_already_registered', 'email.send_password_reset_no_password'] as const;

/**
 * {@link EMAIL_EVENTS} and the sign-in e-mail of the e-mail link (`email.send_signin_link`), so an admin can
 * switch that method on. The receiver must send it, e.g. the aws-ses-mailer from madAuth 0.5 on.
 */
export const EMAIL_LINK_EVENTS = [...EMAIL_EVENTS, 'email.send_signin_link'] as const;

/**
 * How madAuth's Lambda functions are bundled: one ESM file, with the AWS SDK (`@aws-sdk/*`) left to the runtime. The
 * signer of WEBHOOK_AUTH=aws-iam (`@smithy/signature-v4`, a dependency of this package) is bundled: the runtime has
 * it only as a part of the SDK, which may change.
 */
export const lambdaBundling: nodejs.BundlingOptions = {
  format: nodejs.OutputFormat.ESM,
  target: 'node22',
  externalModules: ['@aws-sdk/*'],
  // Some bundled CommonJS code calls require(); give the ESM bundle one.
  banner: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
};

export interface MadAuthServerProps {
  /** MADAUTH_ISSUER: the public origin the server is reached at, e.g. `https://example.com`. */
  readonly issuer: string;
  /** ALLOWED_ORIGINS: the origins of your app(s). Default: the issuer. */
  readonly allowedOrigins?: string[];
  /**
   * The Parameter Store path of the secrets. Each SecureString parameter under it becomes the environment
   * variable of its name, e.g. `/madauth/WEBHOOK_SECRET`. `scripts/bootstrap-secrets.sh` creates them.
   * Default: `/madauth`.
   */
  readonly secretsPath?: string;
  /**
   * WEBHOOK_URL and WEBHOOK_EVENTS, e.g. the aws-ses-mailer of madAuth-webhooks. E-mail & password sign-in
   * is on when the events include the e-mails; default: {@link EMAIL_EVENTS}. The e-mail link needs
   * `email.send_signin_link` as well, e.g. {@link EMAIL_LINK_EVENTS}. Without a webhook, Google and GitHub only.
   */
  readonly webhook?: {
    readonly url: string;
    readonly events?: readonly string[];
    /**
     * The receiver's function, when `url` is its Function URL with AWS_IAM auth, in this account: madAuth signs the
     * calls with its role (WEBHOOK_AUTH=aws-iam), which may invoke the URL, instead of `<secretsPath>/WEBHOOK_SECRET`.
     * The receiver checks that the caller is {@link MadAuthServer.role}, e.g. the aws-ses-mailer with MADAUTH_ROLE_ARN.
     * Needs a madAuth server newer than 0.6.0: an older installed `@madauth/server` is refused at synth.
     */
    readonly awsIamReceiver?: lambda.IFunction;
  };
  /** More environment variables, e.g. `INITIAL_ADMIN_EMAIL`, `SESSION_TTL` or `AUTHENTICATOR_ISSUER` (see docs/server.md). */
  readonly environment?: Record<string, string>;
  /**
   * Also an RS256 signing key in KMS (`RSA_2048`, one more key and its rotations to pay for), for the ID tokens
   * of OpenID Connect clients that can't verify ES256; an admin then sets `idTokenAlg: 'RS256'` on such a client
   * (see "RS256 ID tokens" in docs/server.md). Default: false. Once created, the key stays and is rotated either way.
   * Needs madAuth 0.7.2 or newer: an older installed `@madauth/server` is refused at synth.
   */
  readonly rs256Signing?: boolean;
  /** Default: 512. madAuth needs at least 256 MB for password hashing; more memory is also more CPU. */
  readonly memorySize?: number;
  /** Caps the concurrent executions, e.g. to limit the cost of abuse on a public site. Default: no cap. */
  readonly reservedConcurrentExecutions?: number;
  /** What happens to the users' table when the stack is deleted. Default: RETAIN. */
  readonly tableRemovalPolicy?: RemovalPolicy;
  /**
   * Bundle `@madauth/server` from this directory (a built checkout of packages/server) instead of the
   * installed npm package. Used to deploy unreleased changes from the madAuth repository.
   */
  readonly serverPackageDir?: string;
}

/**
 * The madAuth server as an AWS Lambda function with a Function URL, its users in a DynamoDB table, its keys in
 * AWS KMS and its secrets in the Parameter Store. Put the URL behind your app's origin (e.g. a CloudFront behavior
 * for `/auth/*` and `/.well-known/*`), so madAuth's cookies are first-party.
 */
export class MadAuthServer extends Construct {
  readonly function: nodejs.NodejsFunction;
  readonly functionUrl: lambda.FunctionUrl;
  readonly table: dynamodb.Table;
  /** The server's role: the caller an AWS_IAM receiver accepts (`webhook.awsIamReceiver`). */
  readonly role: iam.IRole;
  /** Creates the KMS keys at the deploy and rotates them daily; a failed rotation is an error of this function. */
  readonly keyManager: nodejs.NodejsFunction;

  constructor(scope: Construct, id: string, props: MadAuthServerProps) {
    super(scope, id);
    const issuer = httpOrigin(props.issuer);
    if (!issuer) throw new Error(`MadAuthServer: issuer must be an http(s) origin, e.g. https://example.com, but is "${props.issuer}".`);
    const allowedOrigins = (props.allowedOrigins ?? [issuer]).map((origin) => {
      const parsed = httpOrigin(origin);
      if (!parsed) throw new Error(`MadAuthServer: allowedOrigins must be http(s) origins, but one is "${origin}".`);
      return parsed;
    });
    // The Parameter Store wants hierarchies as /a/b: one leading slash, no trailing one.
    const secretsPath = `/${(props.secretsPath ?? '/madauth').replace(/^\/+|\/+$/g, '')}`;
    const awsIamReceiver = props.webhook?.awsIamReceiver;
    // A server that doesn't know WEBHOOK_AUTH would ignore it and refuse to start without WEBHOOK_SECRET. A checkout
    // (serverPackageDir) may be ahead of its version, so only the installed package is checked.
    const installed = (awsIamReceiver || props.rs256Signing) && !props.serverPackageDir ? installedServerVersion() : undefined;
    if (installed && awsIamReceiver && !signsWebhooksWithIam(installed)) {
      throw new Error(
        `MadAuthServer: webhook.awsIamReceiver needs a madAuth server newer than 0.6.0, which signs its webhook calls with its role (WEBHOOK_AUTH=aws-iam), but @madauth/server ${installed} is installed. Update it.`,
      );
    }
    if (installed && props.rs256Signing && !signsRs256(installed)) {
      throw new Error(`MadAuthServer: rs256Signing needs madAuth ${RS256_FROM} or newer, which has an RS256 signing key, but @madauth/server ${installed} is installed. Update it.`);
    }

    // One table with the string keys pk and sk; every read is strongly consistent, so no index is needed.
    this.table = new dynamodb.Table(this, 'Table', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: props.tableRemovalPolicy ?? RemovalPolicy.RETAIN,
    });

    const environment: Record<string, string> = {
      MADAUTH_ISSUER: issuer,
      MADAUTH_KEY_SERVICE: 'aws-kms',
      ALLOWED_ORIGINS: allowedOrigins.join(','),
      DATABASE_URL: `dynamodb:${this.table.tableName}`,
      MADAUTH_SECRETS_PATH: secretsPath,
      ...(props.webhook ? { WEBHOOK_URL: props.webhook.url, WEBHOOK_EVENTS: (props.webhook.events ?? EMAIL_EVENTS).join(',') } : {}),
      ...(awsIamReceiver ? { WEBHOOK_AUTH: 'aws-iam' } : {}),
      ...props.environment,
    };

    this.function = new nodejs.NodejsFunction(this, 'Function', {
      entry: fileURLToPath(new URL('../lambda/server.ts', import.meta.url)),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: props.memorySize ?? 512,
      // madAuth waits up to 10 seconds for a webhook receiver.
      timeout: Duration.seconds(15),
      reservedConcurrentExecutions: props.reservedConcurrentExecutions,
      environment,
      logGroup: new logs.LogGroup(this, 'Logs', {
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
      bundling: {
        ...lambdaBundling,
        esbuildArgs: props.serverPackageDir
          ? { '--alias:@madauth/server/lambda': join(props.serverPackageDir, 'dist/entry/lambda.js') }
          : undefined,
      },
    });

    this.role = this.function.role!;

    // Exactly what the DynamoDB store uses (see "DynamoDB" in docs/server.md): no batch writes, and Scan only
    // for admins searching users.
    this.table.grant(
      this.function,
      'dynamodb:GetItem',
      'dynamodb:Query',
      'dynamodb:PutItem',
      'dynamodb:UpdateItem',
      'dynamodb:DeleteItem',
      'dynamodb:TransactWriteItems',
      'dynamodb:Scan',
    );
    // The hierarchy and the parameters in it: GetParametersByPath is checked against both.
    const parameterArn = (name: string) => Stack.of(this).formatArn({ service: 'ssm', resource: 'parameter', resourceName: name });
    this.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ssm:GetParametersByPath'],
        resources: [parameterArn(secretsPath.slice(1)), parameterArn(`${secretsPath.slice(1)}/*`)],
      }),
    );

    // The receiver's Function URL with AWS_IAM auth checks both actions. In the role's own policy, which is enough in
    // the same account; grantInvokeUrl would add a permission to the receiver instead when it can't tell the accounts
    // are the same, which fails for an imported function.
    if (awsIamReceiver) {
      const invokeUrl = [
        new iam.PolicyStatement({
          actions: ['lambda:InvokeFunctionUrl'],
          resources: [awsIamReceiver.functionArn],
          conditions: { StringEquals: { 'lambda:FunctionUrlAuthType': 'AWS_IAM' } },
        }),
        new iam.PolicyStatement({
          actions: ['lambda:InvokeFunction'],
          resources: [awsIamReceiver.functionArn],
          conditions: { Bool: { 'lambda:InvokedViaFunctionUrl': true } },
        }),
      ];
      for (const statement of invokeUrl) this.function.addToRolePolicy(statement);
    }

    // The keys in AWS KMS, under aliases named after the issuer (see "AWS KMS" in docs/server.md). The server may
    // only use them; a function with a role of its own creates them at the deploy and rotates them every day, so
    // whatever takes over the server can't make a key that madAuth trusts.
    const deployment = deploymentOf(issuer);
    for (const statement of serverKmsPolicy(deployment)) this.function.addToRolePolicy(iam.PolicyStatement.fromJson(statement));
    const signingKeyParameter = `${secretsPath}/MADAUTH_SIGNING_KEY`;
    // With AWS IAM, a webhook secret (or the previous one) left in the Parameter Store would keep the server from starting:
    // the deploy checks.
    const webhookSecretParameters: Record<string, string> = awsIamReceiver ? { WEBHOOK_SECRET_PARAMETER: `${secretsPath}/WEBHOOK_SECRET`, WEBHOOK_PREVIOUS_SECRET_PARAMETER: `${secretsPath}/WEBHOOK_PREVIOUS_SECRET` } : {};
    this.keyManager = new nodejs.NodejsFunction(this, 'Keys', {
      entry: fileURLToPath(new URL('../lambda/keys.ts', import.meta.url)),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: Duration.minutes(1),
      environment: {
        MADAUTH_ISSUER: issuer,
        SIGNING_KEY_PARAMETER: signingKeyParameter,
        ...webhookSecretParameters,
        ...(props.rs256Signing ? { RS256_SIGNING: 'true' } : {}),
      },
      // What was rotated when, for a year.
      logGroup: new logs.LogGroup(this, 'KeysLogs', {
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
      bundling: {
        ...lambdaBundling,
        esbuildArgs: props.serverPackageDir
          ? { '--alias:@madauth/server/aws-kms': join(props.serverPackageDir, 'dist/aws-kms.js') }
          : undefined,
      },
    });
    const kmsArn = (resource: 'key' | 'alias', resourceName: string) => Stack.of(this).formatArn({ service: 'kms', resource, resourceName });
    const deploymentAliases = { 'ForAnyValue:StringLike': { 'kms:ResourceAliases': `alias/madauth/${deployment}/*` } };
    // In the function's default policy, which the function and so the custom resource below wait for.
    const keyManagerStatements = [
      new iam.PolicyStatement({ actions: ['kms:CreateKey', 'kms:ListAliases'], resources: ['*'] }),
      // Right after CreateKey, before the new key has an alias; it only turns on KMS's own rotation.
      new iam.PolicyStatement({ actions: ['kms:EnableKeyRotation'], resources: [kmsArn('key', '*')] }),
      // Checked against the alias and against each key it points to.
      new iam.PolicyStatement({
        actions: ['kms:CreateAlias', 'kms:UpdateAlias', 'kms:DeleteAlias'],
        resources: [kmsArn('alias', `madauth/${deployment}/*`), kmsArn('key', '*')],
      }),
      new iam.PolicyStatement({ actions: ['kms:DescribeKey', 'kms:DisableKey'], resources: [kmsArn('key', '*')], conditions: deploymentAliases }),
      // Whether the local key service's key (and with AWS IAM the webhook secrets) is still there; no value is read.
      new iam.PolicyStatement({
        actions: ['ssm:GetParameters'],
        resources: [signingKeyParameter, ...Object.values(webhookSecretParameters)].map((name) => parameterArn(name.slice(1))),
      }),
    ];
    for (const statement of keyManagerStatements) this.keyManager.addToRolePolicy(statement);
    const provider = new cr.Provider(this, 'KeysProvider', {
      onEventHandler: this.keyManager,
      logGroup: new logs.LogGroup(this, 'KeysProviderLogs', {
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
    });
    const keys = new CustomResource(this, 'KmsKeys', {
      serviceToken: provider.serviceToken,
      resourceType: 'Custom::MadAuthKmsKeys',
      // A new property makes CloudFormation run the check again on the deploy that switches to AWS IAM, and the
      // setup again on the one that adds the RS256 key.
      properties: { Deployment: deployment, ...(awsIamReceiver ? { WebhookAuth: 'aws-iam' } : {}), ...(props.rs256Signing ? { Rs256Signing: 'true' } : {}) },
    });
    // The server's new configuration only once its keys exist.
    this.function.node.addDependency(keys);
    new events.Rule(this, 'KeysSchedule', {
      description: "Rotates the madAuth server's KMS keys",
      schedule: events.Schedule.rate(Duration.days(1)),
      targets: [new targets.LambdaFunction(this.keyManager, { retryAttempts: 2 })],
    });

    // Public, without AWS authentication: madAuth checks the Origin of every request itself (ALLOWED_ORIGINS).
    this.functionUrl = this.function.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });

    new CfnOutput(this, 'FunctionUrl', { value: this.functionUrl.url, description: 'The madAuth server' });
    new CfnOutput(this, 'RoleArn', {
      value: this.role.roleArn,
      description: "The madAuth server's role: the caller an AWS_IAM webhook receiver accepts, e.g. MADAUTH_ROLE_ARN of the aws-ses-mailer",
    });
  }
}

/** Whether a version of @madauth/server knows WEBHOOK_AUTH=aws-iam: every one the dependency allows but the three before it. */
export function signsWebhooksWithIam(version: string): boolean {
  return !['0.6.0-beta.1', '0.6.0-beta.2', '0.6.0'].includes(version);
}

/** The first version of @madauth/server with an RS256 signing key (`kms-setup --rs256`). */
const RS256_FROM = '0.7.2';

/** Whether a version of @madauth/server (`major.minor.patch`, maybe `-beta.n`) is {@link RS256_FROM} or newer. */
export function signsRs256(version: string): boolean {
  const numbers = (v: string) => v.split('-')[0]!.split('.').map(Number);
  const [a, b] = [numbers(version), numbers(RS256_FROM)];
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  }
  // 0.7.2-beta.1 is before 0.7.2.
  return !version.includes('-');
}

/** The version of the installed @madauth/server, from the package.json above its `dist/aws-kms.js`. */
function installedServerVersion(): string {
  const entry = fileURLToPath(import.meta.resolve('@madauth/server/aws-kms'));
  return (JSON.parse(readFileSync(join(dirname(entry), '../package.json'), 'utf8')) as { version: string }).version;
}

/** The origin of an http(s) URL, or undefined. */
function httpOrigin(value: string): string | undefined {
  const url = URL.canParse(value) ? new URL(value) : undefined;
  return url && (url.protocol === 'http:' || url.protocol === 'https:') ? url.origin : undefined;
}
