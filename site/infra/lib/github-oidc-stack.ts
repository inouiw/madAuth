import { CfnOutput, Stack, type StackProps } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import type { Construct } from 'constructs';

export interface GithubOidcProps extends StackProps {
  /** e.g. `inouiw/madAuth`. */
  readonly repo: string;
  /** Only workflow jobs in this GitHub environment may deploy; give it required reviewers. */
  readonly environment: string;
  /** The account's GitHub OIDC provider, if it already has one (an account can have only one). */
  readonly existingProviderArn?: string;
}

/**
 * The role GitHub Actions deploys with, through OIDC: no AWS keys are stored in GitHub. The role may only
 * assume the CDK bootstrap roles, which do the deployment. Deployed once, by hand.
 */
export class GithubOidcStack extends Stack {
  constructor(scope: Construct, id: string, props: GithubOidcProps) {
    super(scope, id, props);
    const provider = props.existingProviderArn
      ? iam.OidcProviderNative.fromOidcProviderArn(this, 'Provider', props.existingProviderArn)
      : new iam.OidcProviderNative(this, 'Provider', {
          url: 'https://token.actions.githubusercontent.com',
          clientIds: ['sts.amazonaws.com'],
        });

    const role = new iam.Role(this, 'DeployRole', {
      roleName: 'madauth-site-deploy',
      assumedBy: new iam.WebIdentityPrincipal(provider.oidcProviderArn, {
        StringEquals: {
          'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          // Never a pull request: only jobs that run in the protected environment.
          'token.actions.githubusercontent.com:sub': `repo:${props.repo}:environment:${props.environment}`,
        },
      }),
    });
    role.addToPolicy(
      new iam.PolicyStatement({
        actions: ['sts:AssumeRole'],
        resources: [`arn:${this.partition}:iam::${this.account}:role/cdk-*`],
      }),
    );

    new CfnOutput(this, 'DeployRoleArn', { value: role.roleArn, description: 'The GitHub variable AWS_DEPLOY_ROLE_ARN' });
  }
}
