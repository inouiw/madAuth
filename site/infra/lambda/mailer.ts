// The aws-ses-mailer of github.com/inouiw/madAuth-webhooks, with WEBHOOK_SECRET from the Parameter Store instead
// of an environment variable. The import is an esbuild alias to that repository's src/handler.ts (lib/site-stack.ts).
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { SESv2Client } from '@aws-sdk/client-sesv2';
import type { LambdaFunctionURLEvent, LambdaFunctionURLResult } from 'aws-lambda';
import { createMailer } from 'madauth-ses-mailer';

const ssm = new SSMClient({});
let mailer: Promise<(event: LambdaFunctionURLEvent) => Promise<LambdaFunctionURLResult>> | undefined;

async function create() {
  const secret = await ssm.send(new GetParameterCommand({ Name: process.env.WEBHOOK_SECRET_PARAMETER, WithDecryption: true }));
  return createMailer({ secret: secret.Parameter?.Value ?? '', from: process.env.MAIL_FROM ?? '', ses: new SESv2Client({}) });
}

export const handler = async (event: LambdaFunctionURLEvent): Promise<LambdaFunctionURLResult> => {
  mailer ??= create();
  mailer.catch(() => (mailer = undefined));
  return (await mailer)(event);
};
