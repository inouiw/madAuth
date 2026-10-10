import { CfnOutput, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The events a receiver that sends the e-mails handles, e.g. the aws-ses-mailer of madAuth-webhooks. */
export const EMAIL_EVENTS = ['email.verify', 'email.reset', 'email.already_registered', 'email.no_password'] as const;

/** How madAuth's Lambda functions are bundled: one ESM file, with the AWS SDK left to the runtime. */
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
  /** GOOGLE_CLIENT_ID, for Google sign-in. Its secret, if any, goes into the Parameter Store. */
  readonly googleClientId?: string;
  /**
   * The Parameter Store path of the secrets. Each SecureString parameter under it becomes the environment
   * variable of its name, e.g. `/madauth/MADAUTH_SIGNING_KEY`. `scripts/bootstrap-secrets.sh` creates them.
   * Default: `/madauth`.
   */
  readonly secretsPath?: string;
  /**
   * WEBHOOK_URL and WEBHOOK_EVENTS, e.g. the aws-ses-mailer of madAuth-webhooks. E-mail & password sign-in
   * is on when the events include the e-mails; default: {@link EMAIL_EVENTS}. Without a webhook, Google only.
   */
  readonly webhook?: { readonly url: string; readonly events?: readonly string[] };
  /** More environment variables, e.g. `SESSION_TTL` or `PASSWORD_MIN_LENGTH` (see docs/server.md). */
  readonly environment?: Record<string, string>;
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
 * The madAuth server as an AWS Lambda function with a Function URL, its users in a DynamoDB table and its
 * secrets in the Parameter Store. Put the URL behind your app's origin (e.g. a CloudFront behavior for
 * `/auth/*` and `/.well-known/*`), so madAuth's cookies are first-party.
 */
export class MadAuthServer extends Construct {
  readonly function: nodejs.NodejsFunction;
  readonly functionUrl: lambda.FunctionUrl;
  readonly table: dynamodb.Table;

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
      ALLOWED_ORIGINS: allowedOrigins.join(','),
      DATABASE_URL: `dynamodb:${this.table.tableName}`,
      MADAUTH_SECRETS_PATH: secretsPath,
      ...(props.googleClientId ? { GOOGLE_CLIENT_ID: props.googleClientId } : {}),
      ...(props.webhook ? { WEBHOOK_URL: props.webhook.url, WEBHOOK_EVENTS: (props.webhook.events ?? EMAIL_EVENTS).join(',') } : {}),
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

    // Exactly what the DynamoDB store uses (see "DynamoDB" in docs/server.md): no Scan, no batch writes.
    this.table.grant(
      this.function,
      'dynamodb:GetItem',
      'dynamodb:Query',
      'dynamodb:PutItem',
      'dynamodb:UpdateItem',
      'dynamodb:DeleteItem',
      'dynamodb:TransactWriteItems',
    );
    // The hierarchy and the parameters in it: GetParametersByPath is checked against both.
    const parameterArn = (name: string) => Stack.of(this).formatArn({ service: 'ssm', resource: 'parameter', resourceName: name });
    this.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ssm:GetParametersByPath'],
        resources: [parameterArn(secretsPath.slice(1)), parameterArn(`${secretsPath.slice(1)}/*`)],
      }),
    );

    // Public, without AWS authentication: madAuth checks the Origin of every request itself (ALLOWED_ORIGINS).
    this.functionUrl = this.function.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });

    new CfnOutput(this, 'FunctionUrl', { value: this.functionUrl.url, description: 'The madAuth server' });
  }
}

/** The origin of an http(s) URL, or undefined. */
function httpOrigin(value: string): string | undefined {
  const url = URL.canParse(value) ? new URL(value) : undefined;
  return url && (url.protocol === 'http:' || url.protocol === 'https:') ? url.origin : undefined;
}
