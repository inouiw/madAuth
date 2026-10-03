import type { LambdaFunctionURLEvent } from 'aws-lambda';
import { SendEmailCommand } from '@aws-sdk/client-sesv2';
import { describe, expect, it, vi } from 'vitest';
import { generateWebhookSecret, signWebhook } from '@madauth/server/webhook';
import { createMailer } from './handler.js';

const secret = generateWebhookSecret();

function event(type: string, data: Record<string, unknown>, options: { sign?: boolean; base64?: boolean } = {}): LambdaFunctionURLEvent {
  const body = JSON.stringify({ type, data });
  const timestamp = Math.floor(Date.now() / 1000);
  return {
    headers: {
      'webhook-id': 'msg_1',
      'webhook-timestamp': String(timestamp),
      'webhook-signature': options.sign === false ? 'v1,forged' : signWebhook(secret, 'msg_1', timestamp, body),
    },
    body: options.base64 ? Buffer.from(body).toString('base64') : body,
    isBase64Encoded: !!options.base64,
  } as unknown as LambdaFunctionURLEvent;
}

function setup(sendImpl: (command: unknown) => Promise<unknown> = async () => ({ MessageId: 'm1' })) {
  const send = vi.fn(sendImpl);
  const handler = createMailer({ secret, from: '"Example" <no-reply@example.com>', ses: { send } as never });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  return { handler, send };
}

const reset = { to: 'ada@example.com', link: 'https://app.example.com/#madauth_reset=T', code: '123456', site: 'app.example.com' };

describe('AWS SES mailer', () => {
  it('K10: sends the reset e-mail with link and code, and answers 200', async () => {
    const { handler, send } = setup();

    expect(await handler(event('email.reset', reset, { base64: true }))).toEqual({ statusCode: 200 });

    expect(send).toHaveBeenCalledOnce();
    const command = send.mock.calls[0][0] as unknown as SendEmailCommand;
    expect(command).toBeInstanceOf(SendEmailCommand);
    const input = command.input;
    expect(input.FromEmailAddress).toBe('"Example" <no-reply@example.com>');
    expect(input.Destination?.ToAddresses).toEqual(['ada@example.com']);
    const content = input.Content!.Simple!;
    expect(content.Subject?.Data).toBe('Reset your password for app.example.com');
    for (const part of [content.Body!.Text!.Data, content.Body!.Html!.Data]) {
      expect(part).toContain(reset.link);
      expect(part).toContain('123 456');
    }
  });

  it('K10: answers 502 when SES does not accept the e-mail, so madAuth reports it', async () => {
    const { handler } = setup(async () => {
      throw new Error('MessageRejected: Email address is not verified.');
    });

    expect(await handler(event('email.verify', reset))).toEqual({ statusCode: 502 });
  });

  it('K10: rejects a call with a wrong signature and sends nothing', async () => {
    const { handler, send } = setup();

    expect(await handler(event('email.reset', reset, { sign: false }))).toEqual({ statusCode: 401 });
    expect(send).not.toHaveBeenCalled();
  });

  it('K10: allows the sign-up check and accepts events without sending', async () => {
    const { handler, send } = setup();

    expect(await handler(event('signup.before', { email: 'ada@example.com' }))).toEqual({ statusCode: 204 });
    expect(await handler(event('user.created', { user: { id: 'usr_1' } }))).toEqual({ statusCode: 204 });
    expect(send).not.toHaveBeenCalled();
  });

  it('sends the "already registered" e-mail', async () => {
    const { handler, send } = setup();

    await handler(event('email.already_registered', { to: 'ada@example.com', link: 'https://app.example.com/', site: 'app.example.com' }));

    const input = (send.mock.calls[0][0] as unknown as SendEmailCommand).input;
    expect(input.Content!.Simple!.Subject?.Data).toBe('You already have an account on app.example.com');
  });
});
