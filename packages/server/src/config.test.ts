import { importJWK } from 'jose';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ConfigError, envVars, loadConfig } from './config.js';
import { CLIENT_ID, signingKey } from './test/helpers.js';

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
    expect(config.google.clientId).toBe(CLIENT_ID);
  });

  it('X6: names a missing variable', async () => {
    await expect(loadConfig({ ...env, GOOGLE_CLIENT_ID: '' })).rejects.toThrow(
      new ConfigError('GOOGLE_CLIENT_ID is not set. See docs/server.md.'),
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

  it('documents every environment variable in docs/server.md', () => {
    const docs = readFileSync(new URL('../../../docs/server.md', import.meta.url), 'utf8');
    for (const name of Object.keys(envVars)) expect(docs).toContain(`\`${name}\``);
  });
});
