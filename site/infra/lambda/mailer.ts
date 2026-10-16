// The aws-ses-mailer of github.com/inouiw/madAuth-webhooks, behind a Function URL with AWS_IAM auth: it accepts only
// calls of the madAuth server's role (MADAUTH_ROLE_ARN) and needs no webhook secret. The import is an esbuild alias to
// that repository's src/handler.ts (lib/site-stack.ts).
import { SESv2Client } from '@aws-sdk/client-sesv2';
import { createMailer } from 'madauth-ses-mailer';

export const handler = createMailer({ madauthRoleArn: process.env.MADAUTH_ROLE_ARN ?? '', from: process.env.MAIL_FROM ?? '', ses: new SESv2Client({}) });
