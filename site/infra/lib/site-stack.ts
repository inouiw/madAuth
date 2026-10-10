import { EMAIL_EVENTS, MadAuthServer, lambdaBundling } from '@madauth/deploy-aws';
import { CfnOutput, Duration, RemovalPolicy, Stack, type StackProps } from 'aws-cdk-lib';
import * as budgets from 'aws-cdk-lib/aws-budgets';
import type * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as ses from 'aws-cdk-lib/aws-ses';
import type { Construct } from 'constructs';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const SECRETS_PATH = '/madauth-site';

export interface SiteProps extends StackProps {
  readonly domain: string;
  readonly zone: route53.IHostedZone;
  readonly certificate: acm.ICertificate;
  readonly googleClientId?: string;
  /** A checkout of github.com/inouiw/madAuth-webhooks, for its aws-ses-mailer. */
  readonly webhooksDir: string;
  /** Where the monthly budget alert goes. No budget without it. */
  readonly alertEmail?: string;
}

/**
 * madauth.com: the landing page (site/dist) at /, the demo (demo/dist) at /demo/, and the demo's madAuth server
 * at /auth/* and /.well-known/*, all on one origin, so madAuth's cookies are first-party.
 */
export class SiteStack extends Stack {
  constructor(scope: Construct, id: string, props: SiteProps) {
    super(scope, id, props);
    const { domain, zone } = props;
    const origin = `https://${domain}`;

    // E-mail: SES sends from noreply@<domain>; DKIM and the MAIL FROM records go into the zone.
    const identity = new ses.EmailIdentity(this, 'MailIdentity', {
      identity: ses.Identity.publicHostedZone(zone),
      mailFromDomain: `mail.${domain}`,
    });
    new route53.TxtRecord(this, 'Dmarc', {
      zone,
      recordName: `_dmarc.${domain}`,
      values: ['v=DMARC1; p=quarantine'],
    });

    const mailer = new nodejs.NodejsFunction(this, 'Mailer', {
      entry: fileURLToPath(new URL('../lambda/mailer.ts', import.meta.url)),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: Duration.seconds(8),
      reservedConcurrentExecutions: 2,
      environment: {
        MAIL_FROM: `"madAuth demo" <noreply@${domain}>`,
        WEBHOOK_SECRET_PARAMETER: `${SECRETS_PATH}/WEBHOOK_SECRET`,
      },
      logGroup: new logs.LogGroup(this, 'MailerLogs', {
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
      bundling: {
        ...lambdaBundling,
        esbuildArgs: {
          '--alias:madauth-ses-mailer': mailerSource(props.webhooksDir),
          '--alias:@madauth/server/webhook': join(repoRoot, 'packages/server/dist/webhook.js'),
        },
      },
    });
    mailer.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ses:SendEmail'],
        resources: [this.formatArn({ service: 'ses', resource: 'identity', resourceName: identity.emailIdentityName })],
      }),
    );
    mailer.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ssm:GetParameter'],
        resources: [this.formatArn({ service: 'ssm', resource: 'parameter', resourceName: `${SECRETS_PATH.slice(1)}/WEBHOOK_SECRET` })],
      }),
    );
    // Public: the mailer checks every call's signature (WEBHOOK_SECRET).
    const mailerUrl = mailer.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });

    // The demo's madAuth server, from this repository's packages/server (built before the deploy).
    const server = new MadAuthServer(this, 'MadAuth', {
      issuer: origin,
      googleClientId: props.googleClientId || undefined,
      secretsPath: SECRETS_PATH,
      webhook: { url: mailerUrl.url, events: EMAIL_EVENTS },
      // A public demo: cap what abuse can cost.
      reservedConcurrentExecutions: 5,
      serverPackageDir: join(repoRoot, 'packages/server'),
    });

    // The static files: site/dist at the root, demo/dist under demo/.
    const bucket = new s3.Bucket(this, 'Files', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // www → apex, and directory URLs → their index.html (/demo → /demo/, /demo/ → /demo/index.html).
    const rewrite = new cloudfront.Function(this, 'Rewrite', {
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
  var request = event.request;
  var host = request.headers.host ? request.headers.host.value : '';
  var redirect = function (location) {
    return { statusCode: 301, statusDescription: 'Moved Permanently', headers: { location: { value: location } } };
  };
  if (host.indexOf('www.') === 0) return redirect('https://' + host.slice(4) + request.uri);
  // The server's paths are passed through as they are.
  if (request.uri.indexOf('/auth/') === 0 || request.uri.indexOf('/.well-known/') === 0) return request;
  if (request.uri.endsWith('/')) {
    request.uri += 'index.html';
  } else if (request.uri.split('/').pop().indexOf('.') === -1) {
    return redirect(request.uri + '/');
  }
  return request;
}`),
    });

    const serverBehavior: cloudfront.BehaviorOptions = {
      origin: new origins.FunctionUrlOrigin(server.functionUrl),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      // Cookies, query strings and the Origin header (madAuth checks it), but not the Host header: the
      // Function URL only answers to its own host name.
      originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
      // The www redirect applies here too; the function passes the server's paths through otherwise.
      functionAssociations: [{ function: rewrite, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
    };

    const distribution = new cloudfront.Distribution(this, 'Distribution', {
      domainNames: [domain, `www.${domain}`],
      certificate: props.certificate,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(bucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
        functionAssociations: [{ function: rewrite, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
      },
      additionalBehaviors: {
        '/auth/*': serverBehavior,
        '/.well-known/*': serverBehavior,
      },
    });

    // The landing page; `exclude` keeps this deployment from deleting the demo's files.
    new s3deploy.BucketDeployment(this, 'DeploySite', {
      sources: [s3deploy.Source.asset(join(repoRoot, 'site/dist'))],
      destinationBucket: bucket,
      exclude: ['demo/*'],
      distribution,
      distributionPaths: ['/*'],
    });
    new s3deploy.BucketDeployment(this, 'DeployDemo', {
      sources: [s3deploy.Source.asset(join(repoRoot, 'demo/dist'))],
      destinationBucket: bucket,
      destinationKeyPrefix: 'demo/',
      distribution,
      distributionPaths: ['/demo/*'],
    });

    for (const recordName of [domain, `www.${domain}`]) {
      const target = route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(distribution));
      new route53.ARecord(this, `A ${recordName}`, { zone, recordName, target });
      new route53.AaaaRecord(this, `AAAA ${recordName}`, { zone, recordName, target });
    }

    if (props.alertEmail) {
      new budgets.CfnBudget(this, 'Budget', {
        budget: {
          budgetName: 'madauth-site',
          budgetType: 'COST',
          timeUnit: 'MONTHLY',
          budgetLimit: { amount: 10, unit: 'USD' },
        },
        notificationsWithSubscribers: [
          {
            notification: { notificationType: 'ACTUAL', comparisonOperator: 'GREATER_THAN', threshold: 80 },
            subscribers: [{ subscriptionType: 'EMAIL', address: props.alertEmail }],
          },
        ],
      });
    }

    new CfnOutput(this, 'Url', { value: `${origin}/demo/` });
    new CfnOutput(this, 'SecretsPath', { value: SECRETS_PATH, description: 'scripts/bootstrap-secrets.sh of deploy/aws' });
  }
}

function mailerSource(webhooksDir: string): string {
  const source = join(webhooksDir, 'aws-ses-mailer/src/handler.ts');
  if (!existsSync(source)) {
    throw new Error(`${source} not found. Clone github.com/inouiw/madAuth-webhooks there, or pass -c webhooksDir=<path>.`);
  }
  return source;
}
