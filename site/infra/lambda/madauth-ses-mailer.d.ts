// The part of madAuth-webhooks/aws-ses-mailer/src/handler.ts that lambda/mailer.ts uses.
declare module 'madauth-ses-mailer' {
  import type { SESv2Client } from '@aws-sdk/client-sesv2';
  import type { LambdaFunctionURLEvent, LambdaFunctionURLResult } from 'aws-lambda';

  export function createMailer(options: {
    secret: string;
    from: string;
    configurationSet?: string;
    ses: Pick<SESv2Client, 'send'>;
  }): (event: LambdaFunctionURLEvent) => Promise<LambdaFunctionURLResult>;
}
