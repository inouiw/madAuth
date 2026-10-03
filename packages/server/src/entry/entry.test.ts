import { HttpRequest } from '@azure/functions';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { LambdaContext, LambdaEvent } from 'hono/aws-lambda';
import { importJWK, SignJWT } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { runCli } from '../cli.js';
import type { StoreAdapter } from '../store/schema.js';
import { createTablesSql } from '../store/sql.js';
import { createSqliteAdapter } from '../store/sqlite.js';
import { APP_ORIGIN, CLIENT_ID, WEBHOOK_SECRET, WEBHOOK_URL, passwordApp, post, signingKey, testApp } from '../test/helpers.js';
import { handleAzureRequest, parseSetCookie } from './azure-handler.js';

vi.stubEnv('MADAUTH_ISSUER', 'https://auth.example.com');
vi.stubEnv('MADAUTH_SIGNING_KEY', JSON.stringify(signingKey));
vi.stubEnv('ALLOWED_ORIGINS', APP_ORIGIN);
vi.stubEnv('GOOGLE_CLIENT_ID', CLIENT_ID);
vi.stubEnv('WEBHOOK_URL', WEBHOOK_URL);
vi.stubEnv('WEBHOOK_SECRET', WEBHOOK_SECRET);

/** A store adapter that records which models are read. */
function recordingAdapter(): StoreAdapter & { models: string[] } {
  const real = createSqliteAdapter(':memory:');
  const models: string[] = [];
  return { ...real, models, findOne: (model, where) => (models.push(model), real.findOne(model, where)) };
}

function apiGatewayV2Event(
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body: string | null = null,
): LambdaEvent {
  return {
    version: '2.0',
    routeKey: '$default',
    rawPath: path,
    rawQueryString: '',
    headers: { host: 'abc.lambda-url.eu-central-1.on.aws', ...headers },
    body,
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
    expect(JSON.parse((config as { body: string }).body)).toEqual({ google: { clientId: CLIENT_ID, codeFlow: false }, password: null });
    expect(nonce).toMatchObject({ statusCode: 200 });
    expect((nonce as { cookies: string[] }).cookies[0]).toMatch(/^madauth_nonce=/);
  });

  it('A16: a store passed to createHandler is used without DATABASE_URL', async () => {
    const { createHandler } = await import('./lambda.js');
    const store = recordingAdapter();
    const handler = createHandler({ store });
    const body = JSON.stringify({ email: 'ada@example.com', password: 'whatever pass' });

    const res = await handler(
      apiGatewayV2Event('POST', '/auth/password/signin', { origin: APP_ORIGIN, 'content-type': 'application/json' }, body),
      {} as LambdaContext,
    );

    expect(res).toMatchObject({ statusCode: 401 });
    expect(store.models).toContain('user');
  });

  it('A16: a store passed to the Azure registration is used', async () => {
    vi.resetModules();
    const registered: { handler: (request: HttpRequest) => Promise<unknown> }[] = [];
    vi.doMock('@azure/functions', async (importOriginal) => ({
      ...(await importOriginal<typeof import('@azure/functions')>()),
      app: { http: (_name: string, options: (typeof registered)[number]) => registered.push(options) },
    }));
    const { register } = await import('./azure.js');
    const store = recordingAdapter();

    register({ store });
    const response = (await registered[0].handler(
      new HttpRequest({
        method: 'POST',
        url: 'https://madauth.azurewebsites.net/auth/password/signin',
        headers: { origin: APP_ORIGIN, 'content-type': 'application/json' },
        body: { string: JSON.stringify({ email: 'ada@example.com', password: 'whatever pass' }) },
      }),
    )) as { status: number };

    expect(response.status).toBe(401);
    expect(store.models).toContain('user');
    vi.doUnmock('@azure/functions');
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

  it('A17: create-user asks for a password and creates a verified user, without needing the webhook', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'madauth-'));
    const env = { DATABASE_URL: `sqlite:${join(dir, 'madauth.db')}` };
    const io = { askSecret: async () => 'correct horse battery' };

    const created = await runCli(['create-user', 'Ada@Example.com'], io, env);
    const duplicate = await runCli(['create-user', 'ada@example.com'], io, env);
    const short = await runCli(['create-user', 'grace@example.com'], { askSecret: async () => 'short' }, env);

    expect(created).toMatchObject({ exitCode: 0, output: expect.stringMatching(/^Created user usr_\S+ \(Ada@Example.com\)/) });
    expect(duplicate).toMatchObject({ exitCode: 1, output: expect.stringContaining('already exists') });
    expect(short).toMatchObject({ exitCode: 1, output: expect.stringContaining('at least 8') });
    const store = createSqliteAdapter(env.DATABASE_URL.slice('sqlite:'.length));
    const { app } = passwordApp({ password: { minLength: 8, store } });
    const res = await post(app, '/auth/password/signin', { email: 'ada@example.com', password: 'correct horse battery' });
    expect(res.status).toBe(200);
    rmSync(dir, { recursive: true, force: true });
  });

  it('A17: schema prints the SQL for a dialect', async () => {
    expect(await runCli(['schema', '--dialect', 'mysql'])).toEqual({ exitCode: 0, output: createTablesSql('mysql') });
    expect(await runCli(['schema'])).toEqual({ exitCode: 0, output: createTablesSql('postgres') });
    expect(await runCli(['schema', '--dialect', 'oracle'])).toMatchObject({ exitCode: 1 });
  });

  it('schema --from prints only the changes since a schema version', async () => {
    expect(await runCli(['schema', '--dialect', 'sqlite', '--from', '1'])).toEqual({
      exitCode: 0,
      output: 'ALTER TABLE madauth_user ADD COLUMN wrong_codes INTEGER NOT NULL DEFAULT 0;',
    });
    expect(await runCli(['schema', '--from', '1'])).toMatchObject({ output: expect.stringContaining('wrong_codes DOUBLE PRECISION NOT NULL DEFAULT 0') });
    expect(await runCli(['schema', '--from', '2'])).toEqual({ exitCode: 0, output: '-- The tables are up to date.' });
    expect(await runCli(['schema', '--from', 'x'])).toMatchObject({ exitCode: 1 });
  });

  it('generate-webhook-secret prints a usable secret', async () => {
    const { output, exitCode } = await runCli(['generate-webhook-secret']);

    expect(exitCode).toBe(0);
    expect(output).toMatch(/^whsec_[A-Za-z0-9+/]+=*$/);
  });

  it('prints usage for unknown commands', async () => {
    expect(await runCli(['nope'])).toMatchObject({ exitCode: 1, output: expect.stringContaining('generate-key') });
  });
});
