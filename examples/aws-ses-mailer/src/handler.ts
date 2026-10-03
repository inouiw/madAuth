// A madAuth webhook receiver on AWS Lambda (Function URL): sends madAuth's e-mails with Amazon SES.
// It answers 200 only after SES has accepted an e-mail, so madAuth knows whether it went out.
import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';
import { verifyWebhook } from '@madauth/server/webhook';
import type { LambdaFunctionURLEvent, LambdaFunctionURLResult } from 'aws-lambda';
import { alreadyRegisteredMail, resetPasswordMail, verifyEmailMail, type Mail } from './templates.js';

export interface MailerOptions {
  /** The same WEBHOOK_SECRET madAuth uses. */
  secret: string;
  /** Sender, e.g. `"Example" <no-reply@example.com>`; its domain must be verified in SES. */
  from: string;
  /** Optional SES configuration set, e.g. to record bounces and complaints. */
  configurationSet?: string;
  ses: Pick<SESv2Client, 'send'>;
}

interface Call {
  type: string;
  data: Record<string, any>;
}

/** The e-mail for a webhook call, or null if the call is not an e-mail. */
function mailFor({ type, data }: Call): Mail | null {
  switch (type) {
    case 'email.verify':
      return verifyEmailMail(data.to, data.site, data.link, data.code);
    case 'email.reset':
      return resetPasswordMail(data.to, data.site, data.link, data.code);
    case 'email.already_registered':
      return alreadyRegisteredMail(data.to, data.site, data.link);
    default:
      return null;
  }
}

export function createMailer(options: MailerOptions) {
  return async (event: LambdaFunctionURLEvent): Promise<LambdaFunctionURLResult> => {
    // Verify the raw body exactly as it arrived: re-serialized JSON would not match the signature.
    const body = event.isBase64Encoded ? Buffer.from(event.body ?? '', 'base64').toString('utf8') : (event.body ?? '');
    if (!verifyWebhook(options.secret, event.headers, body)) {
      console.warn('Rejected a call with a wrong signature. Do madAuth and this function use the same WEBHOOK_SECRET?');
      return { statusCode: 401 };
    }
    let call: Call;
    try {
      call = JSON.parse(body) as Call;
    } catch {
      return { statusCode: 400 };
    }

    const mail = mailFor(call);
    // Other calls (the sign-up check, events) are not this function's business: an empty 2xx allows them.
    if (!mail) return { statusCode: 204 };

    try {
      await options.ses.send(
        new SendEmailCommand({
          FromEmailAddress: options.from,
          Destination: { ToAddresses: [mail.to] },
          Content: {
            Simple: {
              Subject: { Data: mail.subject, Charset: 'UTF-8' },
              Body: { Text: { Data: mail.text, Charset: 'UTF-8' }, Html: { Data: mail.html, Charset: 'UTF-8' } },
            },
          },
          ConfigurationSetName: options.configurationSet,
        }),
      );
    } catch (e) {
      // Not 2xx: madAuth then tells the user that e-mails can't be sent right now.
      console.error(`SES did not accept "${mail.subject}" to ${mail.to}:`, e);
      return { statusCode: 502 };
    }
    return { statusCode: 200 };
  };
}

export const handler = createMailer({
  secret: process.env.WEBHOOK_SECRET ?? '',
  from: process.env.MAIL_FROM ?? '',
  configurationSet: process.env.SES_CONFIGURATION_SET || undefined,
  ses: new SESv2Client({}),
});
