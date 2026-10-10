import { CfnOutput, Stack, type StackProps } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import type { Construct } from 'constructs';

export interface GithubOidcProps extends StackProps {
  /** e.g. `inouiw/madAuth`. */
  readonly repo: string;
  /**
   * GitHub's numeric ids of the owner and of the repository (`gh api repos/<owner>/<repo> --jq '[.owner.id, .id]'`).
   * A repository with "immutable subject claims" on (new repositories have it) identifies itself by them:
   * `repo:<owner>@<ownerId>/<repo>@<repoId>:environment:…`. Without the ids, such a repository's deploy fails
   * with "Not authorized to perform sts:AssumeRoleWithWebIdentity".
   */
  readonly ownerId?: string;
  readonly repoId?: string;
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

    // Never a pull request: only jobs that run in the protected environment. GitHub names the repository in
    // one of two ways, classic or immutable (with the ids); the role trusts both, they mean the same repository.
    const [owner, name] = props.repo.split('/');
    const subjects = [`repo:${props.repo}:environment:${props.environment}`];
    if (props.ownerId && props.repoId) {
      subjects.push(`repo:${owner}@${props.ownerId}/${name}@${props.repoId}:environment:${props.environment}`);
    }
    const role = new iam.Role(this, 'DeployRole', {
      roleName: 'madauth-site-deploy',
      assumedBy: new iam.WebIdentityPrincipal(provider.oidcProviderArn, {
        StringEquals: {
          'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          'token.actions.githubusercontent.com:sub': subjects,
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
