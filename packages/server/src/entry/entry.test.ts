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
vi.stubEnv('DATABASE_URL', 'sqlite::memory:');
vi.stubEnv('WEBHOOK_URL', WEBHOOK_URL);
vi.stubEnv('WEBHOOK_SECRET', WEBHOOK_SECRET);
vi.stubEnv('WEBHOOK_EVENTS', 'email.verify,email.reset');

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
    expect(JSON.parse((config as { body: string }).body)).toEqual({
      google: { clientId: CLIENT_ID, codeFlow: false, secondFactor: 'none' },
      password: { minLength: 8, secondFactor: 'none' },
      totp: null,
      email: { verification: true },
    });
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

  it('env can be a function that loads the settings; it runs once, and again after a failure', async () => {
    const { createHandler } = await import('./lambda.js');
    const settings = {
      MADAUTH_ISSUER: 'https://login.example.com',
      MADAUTH_SIGNING_KEY: JSON.stringify(signingKey),
      ALLOWED_ORIGINS: APP_ORIGIN,
      GOOGLE_CLIENT_ID: CLIENT_ID,
      DATABASE_URL: 'sqlite::memory:',
    };
    const env = vi.fn(async () => settings);
    const handler = createHandler({ env });

    const first = await handler(apiGatewayV2Event('GET', '/auth/config'), {} as LambdaContext);
    await handler(apiGatewayV2Event('GET', '/auth/config'), {} as LambdaContext);

    expect(first).toMatchObject({ statusCode: 200 });
    expect(env).toHaveBeenCalledTimes(1);

    // E.g. the parameter store could not be reached: the next invocation tries again.
    const flaky = vi.fn().mockRejectedValueOnce(new Error('parameter store unreachable')).mockResolvedValue(settings);
    const recovering = createHandler({ env: flaky });
    await expect(recovering(apiGatewayV2Event('GET', '/auth/config'), {} as LambdaContext)).rejects.toThrow('parameter store unreachable');
    expect(await recovering(apiGatewayV2Event('GET', '/auth/config'), {} as LambdaContext)).toMatchObject({ statusCode: 200 });
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
    const io = { ask: async () => '', askSecret: async () => 'correct horse battery' };

    const created = await runCli(['create-user', 'Ada@Example.com'], io, env);
    const duplicate = await runCli(['create-user', 'ada@example.com'], io, env);
    const short = await runCli(['create-user', 'grace@example.com'], { ...io, askSecret: async () => 'short' }, env);

    expect(created).toMatchObject({ exitCode: 0, output: expect.stringMatching(/^Created user usr_\S+ \(Ada@Example.com\)/) });
    expect(duplicate).toMatchObject({ exitCode: 1, output: expect.stringContaining('already exists') });
    expect(short).toMatchObject({ exitCode: 1, output: expect.stringContaining('at least 8') });
    const store = createSqliteAdapter(env.DATABASE_URL.slice('sqlite:'.length));
    const { app } = passwordApp({ store });
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
    const fromOne = await runCli(['schema', '--dialect', 'sqlite', '--from', '1']);
    expect(fromOne.exitCode).toBe(0);
    expect(fromOne.output.split('\n')[0]).toBe('ALTER TABLE madauth_user ADD COLUMN wrong_codes INTEGER NOT NULL DEFAULT 0;');
    expect(fromOne.output).toContain('CREATE TABLE madauth_role (');
    expect(await runCli(['schema', '--from', '1'])).toMatchObject({ output: expect.stringContaining('wrong_codes DOUBLE PRECISION NOT NULL DEFAULT 0') });
    const fromTwo = await runCli(['schema', '--from', '2']);
    expect(fromTwo.output).toMatch(/^CREATE TABLE madauth_role \(/);
    expect(fromTwo.output).not.toContain('wrong_codes');
    const fromThree = await runCli(['schema', '--from', '3']);
    expect(fromThree.output).toMatch(/^ALTER TABLE madauth_user ADD COLUMN claims TEXT;/);
    expect(fromThree.output).toContain('DROP TABLE madauth_role;');
    expect(fromThree.output).toContain('CREATE TABLE madauth_setting (');
    const fromFour = await runCli(['schema', '--from', '4']);
    expect(fromFour.output).toMatch(/^ALTER TABLE madauth_account ADD COLUMN last_used_step DOUBLE PRECISION NOT NULL DEFAULT 0;/);
    expect(fromFour.output).toContain('CREATE TABLE madauth_recovery_code (');
    expect(await runCli(['schema', '--from', '5'])).toEqual({ exitCode: 0, output: '-- The tables are up to date.' });
    expect(await runCli(['schema', '--from', 'x'])).toMatchObject({ exitCode: 1 });
    // A version this madAuth does not know yet.
    expect(await runCli(['schema', '--from', '6'])).toMatchObject({ exitCode: 1 });
  });

  it('set-roles makes the first admin without a running server, and get-roles prints the roles', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'madauth-'));
    const env = { DATABASE_URL: `sqlite:${join(dir, 'madauth.db')}` };
    const io = { ask: async () => '', askSecret: async () => 'correct horse battery' };

    // The user must exist: signed in once, or created here.
    expect(await runCli(['get-roles', 'ada@example.com'], io, env)).toMatchObject({ exitCode: 1, output: expect.stringContaining('No user') });
    await runCli(['create-user', 'Ada@Example.com'], io, env);
    expect(await runCli(['get-roles', 'ada@example.com'], io, env)).toEqual({ exitCode: 0, output: 'ada@example.com has no roles.' });
    expect(await runCli(['set-roles', 'Ada@Example.com', 'editor', 'admin'], io, env)).toEqual({
      exitCode: 0,
      output: 'ada@example.com: admin editor',
    });
    expect(await runCli(['get-roles', 'ADA@example.com'], io, env)).toEqual({ exitCode: 0, output: 'ada@example.com: admin editor' });
    // Roles are the claim "roles"; set-roles leaves the other claims alone.
    expect(await runCli(['set-claims', 'ada@example.com', '{"plan":"pro","roles":["editor"]}'], io, env)).toEqual({
      exitCode: 0,
      output: 'ada@example.com: {"plan":"pro","roles":["editor"]}',
    });
    expect(await runCli(['set-roles', 'ada@example.com', 'admin'], io, env)).toEqual({ exitCode: 0, output: 'ada@example.com: admin' });
    expect(await runCli(['get-claims', 'ada@example.com'], io, env)).toEqual({ exitCode: 0, output: 'ada@example.com: {"plan":"pro","roles":["admin"]}' });

    expect(await runCli(['set-roles', 'ada@example.com', 'Admin!'], io, env)).toMatchObject({ exitCode: 1, output: expect.stringContaining('lower-case') });
    expect(await runCli(['set-claims', 'ada@example.com', 'not json'], io, env)).toMatchObject({ exitCode: 1, output: expect.stringContaining('JSON') });
    expect(await runCli(['set-claims', 'ada@example.com', '{"1st":true}'], io, env)).toMatchObject({ exitCode: 1, output: expect.stringContaining('names') });
    expect(await runCli(['set-roles', 'not-an-address', 'admin'], io, env)).toMatchObject({ exitCode: 1 });
    expect(await runCli(['set-roles', 'ada@example.com'], io, env)).toEqual({ exitCode: 0, output: 'ada@example.com has no roles.' });
    expect(await runCli(['get-claims', 'ada@example.com'], io, env)).toEqual({ exitCode: 0, output: 'ada@example.com: {"plan":"pro"}' });
    expect(await runCli(['set-roles', 'ada@example.com', 'admin'], io, {})).toMatchObject({ exitCode: 1, output: expect.stringContaining('DATABASE_URL') });
    rmSync(dir, { recursive: true, force: true });
  });

  it('set-methods switches sign-in methods off and on without a running server, but never all off', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'madauth-'));
    // The server's whole configuration, as with --env-file: both methods.
    const env = {
      MADAUTH_ISSUER: 'https://auth.example.com',
      MADAUTH_SIGNING_KEY: JSON.stringify(signingKey),
      ALLOWED_ORIGINS: APP_ORIGIN,
      GOOGLE_CLIENT_ID: CLIENT_ID,
      WEBHOOK_URL,
      WEBHOOK_SECRET,
      WEBHOOK_EVENTS: 'email.verify,email.reset',
      DATABASE_URL: `sqlite:${join(dir, 'madauth.db')}`,
    };
    const io = { ask: async () => '', askSecret: async () => '' };

    // Until set: the configured methods, without the authenticator app on its own (which is always configured).
    expect(await runCli(['get-methods'], io, env)).toEqual({ exitCode: 0, output: 'Switched on: google, password. Switched off: totp.' });
    expect(await runCli(['set-methods', 'google'], io, env)).toEqual({ exitCode: 0, output: 'Switched on: google. Switched off: password, totp.' });
    expect(await runCli(['get-methods'], io, env)).toEqual({ exitCode: 0, output: 'Switched on: google. Switched off: password, totp.' });
    // The list says what is on, with the policy for the authenticator app as a second factor.
    expect(await runCli(['set-methods', 'google', 'password=required', 'totp'], io, env)).toEqual({
      exitCode: 0,
      output: 'Switched on: google, password (authenticator app required), totp.',
    });
    expect(await runCli(['set-methods', 'sms'], io, env)).toMatchObject({ exitCode: 1, output: expect.stringContaining('Unknown sign-in method "sms"') });
    expect(await runCli(['set-methods', 'password=maybe'], io, env)).toMatchObject({ exitCode: 1, output: expect.stringContaining('none, optional, required') });
    expect(await runCli(['set-methods', 'totp=required'], io, env)).toMatchObject({ exitCode: 1 });
    // Nothing listed: that would switch everything off.
    expect(await runCli(['set-methods'], io, env)).toMatchObject({ exitCode: 1, output: expect.stringContaining('switch off every sign-in method') });

    // A password-only server: "set-methods google" would switch off the only method there is.
    const passwordOnly = { ...env, GOOGLE_CLIENT_ID: undefined };
    expect(await runCli(['set-methods', 'google'], io, passwordOnly)).toEqual({
      exitCode: 1,
      output: 'That would switch off every sign-in method. The server is configured for: password, totp.',
    });
    // What was set above holds: Google is simply not configured here.
    expect(await runCli(['get-methods'], io, passwordOnly)).toEqual({ exitCode: 0, output: 'Switched on: password (authenticator app required), totp.' });
    expect(await runCli(['get-methods'], io, { DATABASE_URL: env.DATABASE_URL })).toMatchObject({ exitCode: 1, output: expect.stringContaining('MADAUTH_ISSUER') });
    rmSync(dir, { recursive: true, force: true });
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
