import { importJWK } from 'jose';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ConfigError, envVars, loadConfig } from './config.js';
import { consoleMailer } from './mail.js';
import { CLIENT_ID, recordingMailer, signingKey } from './test/helpers.js';
import { createSqliteAdapter } from './store/sqlite.js';

const env = {
  MADAUTH_ISSUER: 'https://auth.example.com/',
  MADAUTH_SIGNING_KEY: JSON.stringify(signingKey),
  ALLOWED_ORIGINS: 'https://app.example.com, https://admin.example.com/',
  GOOGLE_CLIENT_ID: CLIENT_ID,
};

describe('loadConfig', () => {
  it('reads a valid configuration with defaults', async () => {
    expect(await loadConfig(env)).toEqual({
      issuer: 'https://auth.example.com',
      signingKey,
      allowedOrigins: ['https://app.example.com', 'https://admin.example.com'],
      sessionTtlSeconds: 28800,
      cookieDomain: undefined,
      google: { clientId: CLIENT_ID, clientSecret: undefined },
    });
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
    await expect(loadConfig({ ...env, GOOGLE_CLIENT_ID: undefined })).rejects.toThrow(/GOOGLE_CLIENT_ID.*DATABASE_URL/s);
  });

  it('A14: turns on e-mail & password sign-in with DATABASE_URL and SMTP_URL', async () => {
    const config = await loadConfig({ ...env, GOOGLE_CLIENT_ID: undefined, DATABASE_URL: 'sqlite::memory:', SMTP_URL: 'console' });

    expect(config.google).toBeUndefined();
    expect(config.password).toMatchObject({ minLength: 8, mailer: consoleMailer });
    expect(await config.password!.store.findOne('user', { id: 'x' })).toBeNull();
  });

  it('A14: names what is missing or wrong for e-mail & password sign-in', async () => {
    const withDb = { ...env, DATABASE_URL: 'sqlite::memory:' };
    await expect(loadConfig(withDb)).rejects.toThrow(/SMTP_URL is not set/);
    await expect(loadConfig({ ...withDb, SMTP_URL: 'smtp://localhost:25' })).rejects.toThrow(/MAIL_FROM is not set/);
    await expect(loadConfig({ ...withDb, SMTP_URL: 'mail.example.com' })).rejects.toThrow(/SMTP_URL must start with/);
    await expect(loadConfig({ ...withDb, SMTP_URL: 'console', PASSWORD_MIN_LENGTH: '0' })).rejects.toThrow(/PASSWORD_MIN_LENGTH/);
    await expect(loadConfig({ ...env, DATABASE_URL: 'postgres://db/madauth', SMTP_URL: 'console' })).rejects.toThrow(
      /must start with "sqlite:".*own store adapter/s,
    );
  });

  it('A16: a store or mailer passed in replaces DATABASE_URL and SMTP_URL', async () => {
    const store = createSqliteAdapter(':memory:');
    const mailer = recordingMailer();

    const config = await loadConfig({ ...env, PASSWORD_MIN_LENGTH: '12' }, { store, mailer });

    expect(config.password).toEqual({ minLength: 12, store, mailer });
  });

  it('documents every environment variable in docs/server.md', () => {
    const docs = readFileSync(new URL('../../../docs/server.md', import.meta.url), 'utf8');
    for (const name of Object.keys(envVars)) expect(docs).toContain(`\`${name}\``);
  });
});
