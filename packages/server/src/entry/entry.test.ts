import { HttpRequest } from '@azure/functions';
import type { LambdaContext, LambdaEvent } from 'hono/aws-lambda';
import { importJWK, SignJWT } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { runCli } from '../cli.js';
import type { StoreAdapter } from '../store/schema.js';
import { createTablesSql } from '../store/sql.js';
import { createSqliteAdapter } from '../store/sqlite.js';
import { APP_ORIGIN, CLIENT_ID, WEBHOOK_SECRET, WEBHOOK_URL, signingKey, testApp } from '../test/helpers.js';
import { handleAzureRequest, parseSetCookie } from './azure-handler.js';

vi.stubEnv('MADAUTH_ISSUER', 'https://auth.example.com');
vi.stubEnv('MADAUTH_KEY_SERVICE', 'local');
vi.stubEnv('MADAUTH_SIGNING_KEY', JSON.stringify(signingKey));
vi.stubEnv('ALLOWED_ORIGINS', APP_ORIGIN);
vi.stubEnv('GOOGLE_CLIENT_ID', CLIENT_ID);
vi.stubEnv('DATABASE_URL', 'sqlite::memory:');
vi.stubEnv('WEBHOOK_URL', WEBHOOK_URL);
vi.stubEnv('WEBHOOK_SECRET', WEBHOOK_SECRET);
vi.stubEnv('WEBHOOK_EVENTS', 'email.send_verification,email.send_password_reset');

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
    const nonce = await handler(apiGatewayV2Event('POST', '/auth/providers/google/nonce', { origin: APP_ORIGIN }), {} as LambdaContext);

    expect(config).toMatchObject({ statusCode: 200 });
    expect(JSON.parse((config as { body: string }).body)).toEqual({
      google: { clientId: CLIENT_ID, codeFlow: false, secondFactor: 'none' },
      github: null,
      password: { minLength: 8, minScore: 2, secondFactor: 'none' },
      authenticator: null,
      email: { verification: true },
      emailLink: null,
      sms: false,
      passkey: null,
      providers: [{ id: 'google', kind: 'google', name: 'Google', secondFactor: 'none' }],
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
      MADAUTH_KEY_SERVICE: 'local',
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
      url: 'https://madauth.azurewebsites.net/auth/providers/google/nonce',
      headers: { origin: APP_ORIGIN },
    });

    const response = await handleAzureRequest(app, request);

    expect(response.status).toBe(200);
    expect(JSON.parse(new TextDecoder().decode(response.body as Uint8Array))).toHaveProperty('nonce');
    expect(response.cookies).toEqual([
      expect.objectContaining({ name: 'madauth_nonce', path: '/auth/providers/google', httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 300 }),
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
    const V13 = "ALTER TABLE madauth_oidc_client ADD COLUMN device_flow BOOLEAN;\nALTER TABLE madauth_user ADD COLUMN wrong_device_codes DOUBLE PRECISION;\nALTER TABLE madauth_user ADD COLUMN wrong_device_code_at DOUBLE PRECISION;\nCREATE TABLE madauth_oidc_device_code (\n  id TEXT PRIMARY KEY,\n  user_code TEXT NOT NULL UNIQUE,\n  client_id TEXT NOT NULL,\n  scope TEXT NOT NULL,\n  status TEXT NOT NULL,\n  user_id TEXT,\n  auth_time DOUBLE PRECISION,\n  amr TEXT,\n  session_version DOUBLE PRECISION,\n  created_at DOUBLE PRECISION NOT NULL,\n  expires_at DOUBLE PRECISION NOT NULL,\n  last_polled_at DOUBLE PRECISION NOT NULL\n);\nCREATE INDEX madauth_oidc_device_code_user_id ON madauth_oidc_device_code (user_id);";
    const V12 = "CREATE TABLE madauth_oidc_client (\n  id TEXT PRIMARY KEY,\n  name TEXT NOT NULL,\n  secret_hash TEXT,\n  redirect_uris TEXT NOT NULL,\n  post_logout_redirect_uris TEXT NOT NULL,\n  created_at DOUBLE PRECISION NOT NULL,\n  updated_at DOUBLE PRECISION NOT NULL,\n  updated_by TEXT\n);\nCREATE TABLE madauth_oidc_code (\n  id TEXT PRIMARY KEY,\n  client_id TEXT NOT NULL,\n  user_id TEXT NOT NULL,\n  redirect_uri TEXT NOT NULL,\n  scope TEXT NOT NULL,\n  nonce TEXT,\n  code_challenge TEXT NOT NULL,\n  auth_time DOUBLE PRECISION NOT NULL,\n  amr TEXT NOT NULL,\n  session_version DOUBLE PRECISION NOT NULL,\n  expires_at DOUBLE PRECISION NOT NULL\n);\nCREATE INDEX madauth_oidc_code_user_id ON madauth_oidc_code (user_id);\nCREATE TABLE madauth_oidc_refresh_token (\n  id TEXT PRIMARY KEY,\n  hash TEXT NOT NULL,\n  client_id TEXT NOT NULL,\n  user_id TEXT NOT NULL,\n  scope TEXT NOT NULL,\n  auth_time DOUBLE PRECISION NOT NULL,\n  amr TEXT NOT NULL,\n  session_version DOUBLE PRECISION NOT NULL,\n  created_at DOUBLE PRECISION NOT NULL,\n  expires_at DOUBLE PRECISION NOT NULL,\n  last_used_at DOUBLE PRECISION NOT NULL\n);\nCREATE INDEX madauth_oidc_refresh_token_client_id ON madauth_oidc_refresh_token (client_id);\nCREATE INDEX madauth_oidc_refresh_token_user_id ON madauth_oidc_refresh_token (user_id);\n" + V13;
    const V11 = 'ALTER TABLE madauth_user ADD COLUMN preferred_second_factor TEXT;\n' + V12;
    const V10 = 'CREATE TABLE madauth_api_key (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  hash TEXT NOT NULL UNIQUE,\n  name TEXT NOT NULL,\n  scopes TEXT NOT NULL,\n  created_at DOUBLE PRECISION NOT NULL,\n  expires_at DOUBLE PRECISION,\n  last_used_at DOUBLE PRECISION NOT NULL\n);\nCREATE INDEX madauth_api_key_user_id ON madauth_api_key (user_id);\n' + V11;
    const V8 = '\nALTER TABLE madauth_account ADD COLUMN name TEXT;\nALTER TABLE madauth_account ADD COLUMN credential_id TEXT;\nALTER TABLE madauth_account ADD COLUMN sign_count DOUBLE PRECISION;\nALTER TABLE madauth_account ADD COLUMN transports TEXT;\nALTER TABLE madauth_account ADD COLUMN last_used_at DOUBLE PRECISION;\nALTER TABLE madauth_account ADD COLUMN rp_id TEXT;\nALTER TABLE madauth_user ADD COLUMN sign_up_method TEXT;\n' + V10;
    expect(await runCli(['schema', '--from', '5'])).toEqual({
      exitCode: 0,
      output: 'ALTER TABLE madauth_account ADD COLUMN phone TEXT;\nALTER TABLE madauth_user ADD COLUMN last_sms_at DOUBLE PRECISION;\n' +
        'ALTER TABLE madauth_user ADD COLUMN signed_up_at DOUBLE PRECISION;\nALTER TABLE madauth_account ADD COLUMN primary_user_id TEXT;\nCREATE UNIQUE INDEX madauth_account_primary_user_id ON madauth_account (primary_user_id);\nALTER TABLE madauth_account ADD COLUMN second_factor BOOLEAN;' +
        V8,
    });
    expect(await runCli(['schema', '--from', '6'])).toEqual({ exitCode: 0, output: 'ALTER TABLE madauth_user ADD COLUMN signed_up_at DOUBLE PRECISION;\nALTER TABLE madauth_account ADD COLUMN primary_user_id TEXT;\nCREATE UNIQUE INDEX madauth_account_primary_user_id ON madauth_account (primary_user_id);\nALTER TABLE madauth_account ADD COLUMN second_factor BOOLEAN;' + V8 });
    expect(await runCli(['schema', '--from', '7'])).toEqual({ exitCode: 0, output: V8.slice(1) });
    expect(await runCli(['schema', '--from', '8'])).toEqual({ exitCode: 0, output: 'ALTER TABLE madauth_user ADD COLUMN sign_up_method TEXT;\n' + V10 });
    expect(await runCli(['schema', '--from', '9'])).toEqual({ exitCode: 0, output: V10 });
    expect(await runCli(['schema', '--from', '10'])).toEqual({ exitCode: 0, output: V11 });
    expect(await runCli(['schema', '--from', '11'])).toEqual({ exitCode: 0, output: V12 });
    expect(await runCli(['schema', '--from', '12'])).toEqual({ exitCode: 0, output: V13 });
    expect(await runCli(['schema', '--from', '13'])).toEqual({ exitCode: 0, output: '-- The tables are up to date.' });
    expect(await runCli(['schema', '--from', 'x'])).toMatchObject({ exitCode: 1 });
    // A version this madAuth does not know yet.
    expect(await runCli(['schema', '--from', '14'])).toMatchObject({ exitCode: 1 });
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
