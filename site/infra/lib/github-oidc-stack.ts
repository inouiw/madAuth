import { CfnOutput, Stack, type StackProps } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import type { Construct } from 'constructs';

export interface GithubOidcProps extends StackProps {
  /** e.g. `inouiw/madAuth`. */
  readonly repo: string;
  /**
   * GitHub's numeric id of the owner (`gh api repos/<owner>/<repo> --jq '[.owner.id, .id]'` prints both ids).
   * A repository with "immutable subject claims" on (new repositories have it) identifies itself by the ids:
   * `repo:<owner>@<ownerId>/<repo>@<repoId>:environment:…`. With both ids the role trusts only that form,
   * so a repository that later takes over the name can't deploy; without them, such a repository's own
   * deploy fails with "Not authorized to perform sts:AssumeRoleWithWebIdentity".
   */
  readonly ownerId?: string;
  /** GitHub's numeric id of the repository; see `ownerId`. Set both or neither. */
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

    // Never a pull request: only jobs that run in the protected environment. With the ids, only the immutable
    // subject is trusted: the name-based one would let a repository that later takes over the name deploy.
    const parts = props.repo.split('/');
    const [owner, name] = parts;
    if (parts.length !== 2 || !owner || !name) throw new Error(`githubRepo must be "<owner>/<name>" but is "${props.repo}".`);
    if (!props.ownerId !== !props.repoId) throw new Error('Set both githubOwnerId and githubRepoId, or neither.');
    const subject =
      props.ownerId && props.repoId
        ? `repo:${owner}@${props.ownerId}/${name}@${props.repoId}:environment:${props.environment}`
        : `repo:${props.repo}:environment:${props.environment}`;
    const role = new iam.Role(this, 'DeployRole', {
      roleName: 'madauth-site-deploy',
      assumedBy: new iam.WebIdentityPrincipal(provider.oidcProviderArn, {
        StringEquals: {
          'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          'token.actions.githubusercontent.com:sub': subject,
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
