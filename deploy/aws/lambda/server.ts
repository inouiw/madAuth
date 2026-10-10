// The madAuth server on AWS Lambda. The settings are environment variables of the function, except the secrets:
// every parameter under MADAUTH_SECRETS_PATH in the Parameter Store becomes the environment variable of its name,
// e.g. /madauth/MADAUTH_SIGNING_KEY → MADAUTH_SIGNING_KEY. So the secrets never show in the function's configuration.
import { GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';
import { createHandler } from '@madauth/server/lambda';

const ssm = new SSMClient({});

async function loadSecrets(path: string): Promise<Record<string, string>> {
  const secrets: Record<string, string> = {};
  let nextToken: string | undefined;
  do {
    const page = await ssm.send(
      new GetParametersByPathCommand({ Path: path, WithDecryption: true, NextToken: nextToken }),
    );
    for (const { Name, Value } of page.Parameters ?? []) {
      if (Name && Value !== undefined) secrets[Name.slice(Name.lastIndexOf('/') + 1)] = Value;
    }
    nextToken = page.NextToken;
  } while (nextToken);
  return secrets;
}

export const handler = createHandler({
  env: async () => {
    const path = process.env.MADAUTH_SECRETS_PATH;
    return path ? { ...process.env, ...(await loadSecrets(path)) } : process.env;
  },
});
