// madAuth's keys in AWS KMS (see "AWS KMS" in docs/server.md): this function creates them when the stack is deployed,
// as a CloudFormation custom resource, and rotates them on a daily schedule. It has a role of its own: the server's
// role may only use the keys, so whatever takes over the server can't make a key that madAuth trusts.
import { GetParametersCommand, SSMClient } from '@aws-sdk/client-ssm';
import { deploymentOf, kmsFromSdk, rotateKmsKeys, setUpKmsKeys } from '@madauth/server/aws-kms';

/** What CloudFormation sends through the custom resource provider; the daily schedule sends no RequestType. */
interface KeysEvent {
  RequestType?: 'Create' | 'Update' | 'Delete';
  PhysicalResourceId?: string;
}

const ssm = new SSMClient({});

/** Whether a parameter exists. GetParameters lists a missing one as invalid instead of failing. */
async function parameterExists(name: string): Promise<boolean> {
  const { Parameters } = await ssm.send(new GetParametersCommand({ Names: [name] }));
  return (Parameters ?? []).length > 0;
}

export async function handler(event: KeysEvent): Promise<{ PhysicalResourceId: string } | undefined> {
  const deployment = deploymentOf(process.env.MADAUTH_ISSUER!);
  const sdk = await kmsFromSdk();
  if ('problem' in sdk) throw new Error(sdk.problem);

  if (!event.RequestType) {
    const { done, problems } = await rotateKmsKeys(sdk.kms, deployment);
    for (const message of done) console.log(message);
    // A failed run is an error of the function (its Errors metric), which an alarm can watch.
    if (problems.length) throw new Error(problems.join(' '));
    return undefined;
  }
  // The keys stay when the stack is deleted, like its table: without them, nothing stored there can be read.
  if (event.RequestType === 'Delete') return { PhysicalResourceId: event.PhysicalResourceId ?? deployment };

  // The local key service's key: with it, the server would refuse to start. Failing here rolls the deploy back
  // while the running server still works.
  const signingKey = process.env.SIGNING_KEY_PARAMETER!;
  if (await parameterExists(signingKey)) {
    throw new Error(
      `${signingKey} is in the Parameter Store, but madAuth's keys are in AWS KMS now and it refuses to start while the old key is set. ` +
        `Delete it, which signs every user out (see "AWS KMS" in docs/server.md), then deploy again: aws ssm delete-parameter --name ${signingKey}`,
    );
  }
  for (const message of await setUpKmsKeys(sdk.kms, deployment)) console.log(message);
  return { PhysicalResourceId: deployment };
}
