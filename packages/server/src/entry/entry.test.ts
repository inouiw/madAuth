import { HttpRequest } from '@azure/functions';
import type { LambdaContext, LambdaEvent } from 'hono/aws-lambda';
import { importJWK, SignJWT } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { runCli } from '../cli.js';
import { APP_ORIGIN, CLIENT_ID, signingKey, testApp } from '../test/helpers.js';
import { handleAzureRequest, parseSetCookie } from './azure-handler.js';

vi.stubEnv('MADAUTH_ISSUER', 'https://auth.example.com');
vi.stubEnv('MADAUTH_SIGNING_KEY', JSON.stringify(signingKey));
vi.stubEnv('ALLOWED_ORIGINS', APP_ORIGIN);
vi.stubEnv('GOOGLE_CLIENT_ID', CLIENT_ID);

function apiGatewayV2Event(method: string, path: string, headers: Record<string, string> = {}): LambdaEvent {
  return {
    version: '2.0',
    routeKey: '$default',
    rawPath: path,
    rawQueryString: '',
    headers: { host: 'abc.lambda-url.eu-central-1.on.aws', ...headers },
    body: null,
    isBase64Encoded: false,
    requestContext: {
      accountId: '123',
      apiId: 'abc',
      domainName: 'abc.lambda-url.eu-central-1.on.aws',
      domainPrefix: 'abc',
      authentication: null,
      authorizer: {},
      http: { method, path, protocol: 'HTTP/1.1', sourceIp: '127.0.0.1', userAgent: 'test' },
      requestId: 'r1',
      routeKey: '$default',
      stage: '$default',
      time: '',
      timeEpoch: 0,
    },
  };
}

describe('deployment entry points', () => {
  it('H1: the Lambda handler serves the app', async () => {
    const { handler } = await import('./lambda.js');

    const config = await handler(apiGatewayV2Event('GET', '/auth/config'), {} as LambdaContext);
    const nonce = await handler(apiGatewayV2Event('POST', '/auth/google/nonce', { origin: APP_ORIGIN }), {} as LambdaContext);

    expect(config).toMatchObject({ statusCode: 200 });
    expect(JSON.parse((config as { body: string }).body)).toEqual({ google: { clientId: CLIENT_ID, codeFlow: false } });
    expect(nonce).toMatchObject({ statusCode: 200 });
    expect((nonce as { cookies: string[] }).cookies[0]).toMatch(/^madauth_nonce=/);
  });

  it('H2: the Azure Functions handler serves the app and passes cookies separately', async () => {
    const app = testApp();
    const request = new HttpRequest({
      method: 'POST',
      url: 'https://madauth.azurewebsites.net/auth/google/nonce',
      headers: { origin: APP_ORIGIN },
    });

    const response = await handleAzureRequest(app, request);

    expect(response.status).toBe(200);
    expect(JSON.parse(new TextDecoder().decode(response.body as Uint8Array))).toHaveProperty('nonce');
    expect(response.cookies).toEqual([
      expect.objectContaining({ name: 'madauth_nonce', path: '/auth/google', httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 300 }),
    ]);
    expect((response.headers as Headers).get('set-cookie')).toBeNull();
  });

  it('parses Set-Cookie attributes for Azure', () => {
    expect(parseSetCookie('a=b=c; Domain=.example.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax')).toEqual({
      name: 'a',
      value: 'b=c',
      domain: '.example.com',
      path: '/',
      expires: new Date(0),
      sameSite: 'Lax',
    });
  });

  it('H4: generate-key prints a private ES256 key that can sign', async () => {
    const { output, exitCode } = await runCli(['generate-key']);

    expect(exitCode).toBe(0);
    const key = await importJWK(JSON.parse(output), 'ES256');
    await expect(new SignJWT({}).setProtectedHeader({ alg: 'ES256' }).sign(key)).resolves.toBeTruthy();
  });

  it('prints usage for unknown commands', async () => {
    expect(await runCli(['nope'])).toMatchObject({ exitCode: 1, output: expect.stringContaining('generate-key') });
  });
});
