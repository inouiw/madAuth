import { importJWK } from 'jose';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ConfigError, envVars, loadConfig, methodConfig } from './config.js';
import { CLIENT_ID, WEBHOOK_SECRET, WEBHOOK_URL, signingKey } from './test/helpers.js';
import { createSqliteAdapter } from './store/sqlite.js';
import { checkWebhookSecret } from './webhooks.js';

const env = {
  MADAUTH_ISSUER: 'https://auth.example.com/',
  MADAUTH_SIGNING_KEY: JSON.stringify(signingKey),
  ALLOWED_ORIGINS: 'https://app.example.com, https://admin.example.com/',
  GOOGLE_CLIENT_ID: CLIENT_ID,
  DATABASE_URL: 'sqlite::memory:',
};

describe('loadConfig', () => {
  it('starts with the methods madAuth before 0.6 saved with the app on its own: an admin chooses while it runs', async () => {
    const store = createSqliteAdapter(':memory:');
    await store.create('setting', { id: 'methods', value: '{"google":{},"password":{"secondFactor":"optional"},"totp":{}}', updatedAt: 1, updatedBy: null });

    // Refusing to start would leave nobody to choose: the admin API needs a running server.
    expect((await loadConfig(env, { store })).store).toBe(store);
  });

  it('INITIAL_ADMIN_EMAIL is an e-mail address, kept normalized', async () => {
    expect((await loadConfig({ ...env, INITIAL_ADMIN_EMAIL: ' Grace@Example.com ' })).initialAdminEmail).toBe('grace@example.com');
    expect((await loadConfig(env)).initialAdminEmail).toBeUndefined();
    await expect(loadConfig({ ...env, INITIAL_ADMIN_EMAIL: 'grace' })).rejects.toThrow(new ConfigError('INITIAL_ADMIN_EMAIL must be an e-mail address, e.g. you@example.com, but is "grace".'));
  });

  it('API_KEY_SCOPES_URL is an https URL, or http on the local machine', async () => {
    for (const url of ['https://app.example.com/api/scopes', 'http://localhost:3000/api-scopes.json']) {
      expect((await loadConfig({ ...env, API_KEY_SCOPES_URL: url })).apiKeyScopesUrl).toBe(url);
    }
    for (const url of ['http://app.example.com/api/scopes', 'scopes.json']) {
      await expect(loadConfig({ ...env, API_KEY_SCOPES_URL: url })).rejects.toThrow(new ConfigError(`API_KEY_SCOPES_URL must be an https URL (http only for localhost) but is "${url}".`));
    }
  });

  it('reads a valid configuration with defaults', async () => {
    const config = await loadConfig(env);

    expect(config).toEqual({
      issuer: 'https://auth.example.com',
      signingKey,
      allowedOrigins: ['https://app.example.com', 'https://admin.example.com'],
      sessionTtlSeconds: 28800,
      renewalTtlSeconds: 2592000,
      cookieDomain: undefined,
      authenticatorIssuer: undefined,
      google: { clientId: CLIENT_ID, clientSecret: undefined },
      store: expect.any(Object),
      password: undefined,
      webhook: undefined,
    });
    expect(await config.store.findOne('user', { id: 'x' })).toBeNull();
  });

  it('needs DATABASE_URL: every user is stored, whichever way they sign in', async () => {
    await expect(loadConfig({ ...env, DATABASE_URL: undefined })).rejects.toThrow(/DATABASE_URL is not set.*sqlite:\.\/madauth\.db/s);
  });

  it('accepts values wrapped in quotes, as Docker’s --env-file passes them', async () => {
    const config = await loadConfig({ ...env, MADAUTH_SIGNING_KEY: `'${JSON.stringify(signingKey)}'`, GOOGLE_CLIENT_ID: `"${CLIENT_ID}"` });

    expect(config.signingKey).toEqual(signingKey);
    expect(config.google?.clientId).toBe(CLIENT_ID);
  });

  it('X6: names a missing variable', async () => {
    await expect(loadConfig({ ...env, ALLOWED_ORIGINS: '' })).rejects.toThrow(
      new ConfigError('ALLOWED_ORIGINS is not set. See docs/server.md.'),
    );
  });

  it('X6: prints a freshly generated, usable key when MADAUTH_SIGNING_KEY is missing', async () => {
    const error = await loadConfig({ ...env, MADAUTH_SIGNING_KEY: undefined }).catch((e: Error) => e);

    expect(error).toBeInstanceOf(ConfigError);
    const jwk = JSON.parse((error as Error).message.match(/MADAUTH_SIGNING_KEY='(.*)'/)![1]);
    expect(jwk).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256' });
    await expect(importJWK(jwk, 'ES256')).resolves.toBeTruthy();
  });

  it('X6: rejects an invalid signing key', async () => {
    await expect(loadConfig({ ...env, MADAUTH_SIGNING_KEY: 'nope' })).rejects.toThrow(/MADAUTH_SIGNING_KEY is not valid JSON/);
    const { d: _d, ...publicKey } = signingKey;
    await expect(loadConfig({ ...env, MADAUTH_SIGNING_KEY: JSON.stringify(publicKey) })).rejects.toThrow(
      /MADAUTH_SIGNING_KEY must be a private EC P-256 JWK/,
    );
  });

  it('rejects an invalid origin, client ID or session TTL', async () => {
    await expect(loadConfig({ ...env, ALLOWED_ORIGINS: 'app.example.com' })).rejects.toThrow(/ALLOWED_ORIGINS/);
    await expect(loadConfig({ ...env, GOOGLE_CLIENT_ID: 'abc' })).rejects.toThrow(/GOOGLE_CLIENT_ID must end with/);
    await expect(loadConfig({ ...env, SESSION_TTL: '5' })).rejects.toThrow(/SESSION_TTL/);
  });

  it('A14: needs at least one sign-in method', async () => {
    await expect(loadConfig({ ...env, GOOGLE_CLIENT_ID: undefined })).rejects.toThrow(/No sign-in method.*GOOGLE_CLIENT_ID.*WEBHOOK_URL/s);
  });

  const hook = { WEBHOOK_URL, WEBHOOK_SECRET, WEBHOOK_EVENTS: 'email.send_verification,email.send_password_reset' };

  it('A14: GitHub sign-in takes the client ID and the secret of the OAuth App together, and counts as a sign-in method', async () => {
    const github = { GITHUB_CLIENT_ID: 'Iv1.abc', GITHUB_CLIENT_SECRET: 'shh' };

    const config = await loadConfig({ ...env, GOOGLE_CLIENT_ID: undefined, ...github });

    expect(config.github).toEqual({ clientId: 'Iv1.abc', clientSecret: 'shh' });
    expect(config.google).toBeUndefined();
    expect((await loadConfig({ ...env, ...github })).github).toEqual({ clientId: 'Iv1.abc', clientSecret: 'shh' });
    expect((await loadConfig(env)).github).toBeUndefined();
    await expect(loadConfig({ ...env, GITHUB_CLIENT_ID: 'Iv1.abc' })).rejects.toThrow(/GITHUB_CLIENT_ID needs GITHUB_CLIENT_SECRET/);
    // A secret alone is ignored, like Google's: a secrets store may hold one for a server that has GitHub off.
    expect((await loadConfig({ ...env, GITHUB_CLIENT_SECRET: 'shh' })).github).toBeUndefined();
    await expect(loadConfig({ ...env, GOOGLE_CLIENT_ID: undefined })).rejects.toThrow(/No sign-in method.*GITHUB_CLIENT_ID/s);
  });

  it('A14: turns on e-mail & password sign-in with a webhook that sends the e-mails', async () => {
    const config = await loadConfig({ ...env, ...hook, GOOGLE_CLIENT_ID: undefined });

    expect(config.google).toBeUndefined();
    expect(config.password).toEqual({});
    expect(config.webhook).toEqual({ url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: new Set(['email.send_verification', 'email.send_password_reset']) });
  });

  it('A14: names what is missing or wrong for e-mail & password sign-in', async () => {
    await expect(loadConfig({ ...env, ...hook, DATABASE_URL: 'postgres://db/madauth' })).rejects.toThrow(
      /must start with "sqlite:".*or "dynamodb:".*own store adapter/s,
    );
  });

  it('DATABASE_URL=dynamodb:<table> uses the DynamoDB adapter, which only reaches AWS on first use', async () => {
    const config = await loadConfig({ ...env, ...hook, DATABASE_URL: 'dynamodb:madauth' });

    expect(config.store).toBeDefined();
    await expect(loadConfig({ ...env, ...hook, DATABASE_URL: 'dynamodb:' })).rejects.toThrow(/needs a table name/);
    await expect(loadConfig({ ...env, ...hook, DATABASE_URL: 'dynamodb://madauth' })).rejects.toThrow(/DynamoDB table name/);
  });

  it('K7: without a webhook there is no e-mail & password sign-in, and Google alone is fine', async () => {
    expect((await loadConfig(env)).password).toBeUndefined();
  });

  it('K7: prints a usable secret when WEBHOOK_SECRET is missing, and rejects a bad one', async () => {
    const error = await loadConfig({ ...env, WEBHOOK_URL }).catch((e: Error) => e);

    expect(error).toBeInstanceOf(ConfigError);
    const secret = (error as Error).message.match(/WEBHOOK_SECRET=(\S+)/)![1];
    expect(checkWebhookSecret(secret)).toBeNull();
    await expect(loadConfig({ ...env, WEBHOOK_URL, WEBHOOK_SECRET: 'not-a-secret' })).rejects.toThrow(/WEBHOOK_SECRET must start with/);
  });

  it('K7: the webhook must use https, except on the local machine', async () => {
    await expect(loadConfig({ ...env, ...hook, WEBHOOK_URL: 'http://hooks.example.com/x' })).rejects.toThrow(/must be an https URL/);
    for (const url of ['http://localhost:8790/webhook', 'http://127.0.0.1:8790/', 'http://host.docker.internal:8790/webhook']) {
      expect((await loadConfig({ ...env, ...hook, WEBHOOK_URL: url })).webhook?.url).toBe(url);
    }
  });

  it('K6: WEBHOOK_EVENTS lists the types that are sent and rejects unknown ones', async () => {
    const config = await loadConfig({ ...env, ...hook, WEBHOOK_EVENTS: 'user.email_verified, user.signed_up' });

    expect(config.webhook?.events).toEqual(new Set(['user.email_verified', 'user.signed_up']));
    await expect(loadConfig({ ...env, ...hook, WEBHOOK_EVENTS: 'user.renamed' })).rejects.toThrow(/unknown type user.renamed/);
  });

  it('K6: a webhook without WEBHOOK_EVENTS is an error that says what to set', async () => {
    const withDb = { ...env, WEBHOOK_URL, WEBHOOK_SECRET, DATABASE_URL: 'sqlite::memory:' };

    const error = await loadConfig(withDb).catch((e: Error) => e);

    expect(error).toBeInstanceOf(ConfigError);
    expect((error as Error).message).toContain('\n\nWEBHOOK_EVENTS=email.send_verification,email.send_password_reset,email.send_signin_link,email.send_already_registered,email.send_password_reset_no_password\n\n');
    await expect(loadConfig({ ...withDb, WEBHOOK_EVENTS: ' , ' })).rejects.toThrow(/WEBHOOK_EVENTS is not set/);
    // Without e-mail & password sign-in no e-mail type is needed, but the list still is.
    await expect(loadConfig({ ...env, WEBHOOK_URL, WEBHOOK_SECRET })).rejects.toThrow(/WEBHOOK_EVENTS is not set.*WEBHOOK_EVENTS=user.signed_in/s);
  });

  it('K6: e-mail & password sign-in is on exactly when email.send_verification and email.send_password_reset are among the events', async () => {
    expect((await loadConfig({ ...env, ...hook, WEBHOOK_EVENTS: 'email.send_verification,user.signed_up' })).password).toBeUndefined();
    expect((await loadConfig({ ...env, ...hook, WEBHOOK_EVENTS: 'email.send_password_reset,email.send_verification' })).password).toEqual({});
    // A receiver that only wants events, on a Google-only server.
    expect((await loadConfig({ ...env, ...hook, WEBHOOK_EVENTS: 'user.signed_in' })).password).toBeUndefined();
    await expect(loadConfig({ ...env, ...hook, GOOGLE_CLIENT_ID: undefined, WEBHOOK_EVENTS: 'user.signed_in' })).rejects.toThrow(/No sign-in method/);
  });

  it('K6: the e-mail link is configured exactly when email.send_signin_link is among the events, and counts as a way to create users', async () => {
    const linkOnly = await loadConfig({ ...env, ...hook, GOOGLE_CLIENT_ID: undefined, WEBHOOK_EVENTS: 'email.send_signin_link' });
    expect(linkOnly.password).toBeUndefined();
    expect(methodConfig(linkOnly)).toEqual({ google: undefined, password: undefined, emailVerification: false, emailLink: true, sms: false });
    expect(methodConfig(await loadConfig({ ...env, ...hook, WEBHOOK_EVENTS: 'email.send_verification,email.send_password_reset' }))).toMatchObject({ emailLink: false });
  });

  it('K6: names the new name of a type that was renamed', async () => {
    await expect(loadConfig({ ...env, ...hook, WEBHOOK_EVENTS: 'email.send_verification,password.reset' })).rejects.toThrow(
      /unknown type password.reset. password.reset is now user.password_reset/,
    );
    // The names of madAuth 0.5: each says what it is now, and user.created what replaces it.
    const old = 'email.verify,email.reset,email.signin,email.already_registered,email.no_password,sms.code,signup.before,user.created,email.verified,email.password_reset,totp.enabled,totp.disabled,sms.enabled,sms.disabled,totp.recovery_code_used';
    const message = String(await loadConfig({ ...env, ...hook, WEBHOOK_EVENTS: old }).catch((e: Error) => e.message));
    for (const hint of [
      'email.verify is now email.send_verification',
      'email.reset is now email.send_password_reset',
      'email.signin is now email.send_signin_link',
      'email.already_registered is now email.send_already_registered',
      'email.no_password is now email.send_password_reset_no_password',
      'sms.code is now sms.send_code',
      'signup.before is now user.signing_up',
      'user.created is gone: user.signed_up tells when a user can sign in',
      'email.verified is now user.email_verified',
      'email.password_reset is now user.password_reset',
      'totp.enabled is now user.second_factor_enabled (with method "authenticator")',
      'sms.disabled is now user.second_factor_disabled (with method "sms")',
      'totp.recovery_code_used is now user.recovery_code_used',
    ]) {
      expect(message).toContain(hint);
    }
  });

  it('SESSION_RENEWAL_TTL is 30 days by default and never shorter than SESSION_TTL', async () => {
    expect((await loadConfig({ ...env, SESSION_TTL: '900', SESSION_RENEWAL_TTL: '86400' })).renewalTtlSeconds).toBe(86400);
    // A session token that lives longer than 30 days can be renewed for as long as it lives.
    expect((await loadConfig({ ...env, SESSION_TTL: '5184000' })).renewalTtlSeconds).toBe(5184000);
    await expect(loadConfig({ ...env, SESSION_TTL: '3600', SESSION_RENEWAL_TTL: '600' })).rejects.toThrow(
      /SESSION_RENEWAL_TTL must be .* not less than SESSION_TTL \(3600\)/,
    );
    await expect(loadConfig({ ...env, SESSION_RENEWAL_TTL: 'soon' })).rejects.toThrow(/SESSION_RENEWAL_TTL/);
  });

  it('A16: a store passed in replaces DATABASE_URL', async () => {
    const store = createSqliteAdapter(':memory:');

    const config = await loadConfig({ ...env, ...hook }, { store });

    expect(config.store).toBe(store);
  });

  it('refuses to start with PASSWORD_MIN_LENGTH, which is a setting now, and says how to set it', async () => {
    await expect(loadConfig({ ...env, ...hook, PASSWORD_MIN_LENGTH: '12' })).rejects.toThrow(
      /PASSWORD_MIN_LENGTH was removed.*Madauth\.admin\.setSettings\(\{ password: \{ minLength: 12 \} \}\)/,
    );
  });

  it('refuses to start with TOTP_ISSUER, which is AUTHENTICATOR_ISSUER now', async () => {
    await expect(loadConfig({ ...env, ...hook, TOTP_ISSUER: 'My App' })).rejects.toThrow(/TOTP_ISSUER is now AUTHENTICATOR_ISSUER/);
    // Empty, as Docker's --env-file keeps it (quotes and all), it is not set.
    expect((await loadConfig({ ...env, ...hook, TOTP_ISSUER: '""' })).authenticatorIssuer).toBeUndefined();
    expect((await loadConfig({ ...env, ...hook, AUTHENTICATOR_ISSUER: 'My App' })).authenticatorIssuer).toBe('My App');
  });

  it('documents every environment variable in docs/server.md', () => {
    const docs = readFileSync(new URL('../../../docs/server.md', import.meta.url), 'utf8');
    for (const name of Object.keys(envVars)) expect(docs).toContain(`\`${name}\``);
  });
});
