import type { JWK, JWTVerifyGetKey } from 'jose';
import { assertPrivateSigningJwk, generateSigningKey } from './keys.js';

export interface MadauthConfig {
  /** Public base URL of the server (MADAUTH_ISSUER). */
  issuer: string;
  /** Private ES256 JWK (MADAUTH_SIGNING_KEY). */
  signingKey: JWK;
  /** App origins allowed to call the server (ALLOWED_ORIGINS). */
  allowedOrigins: string[];
  /** Session lifetime in seconds (SESSION_TTL). */
  sessionTtlSeconds: number;
  /** Cookie domain, e.g. `.example.com` (COOKIE_DOMAIN). */
  cookieDomain?: string;
  google: {
    /** OAuth web client ID (GOOGLE_CLIENT_ID). */
    clientId: string;
    /** Enables the server-side code flow (GOOGLE_CLIENT_SECRET). */
    clientSecret?: string;
  };
  /** Test hook: resolves Google's signing keys. Defaults to Google's published JWKS. */
  jwksResolver?: JWTVerifyGetKey;
}

/** Every environment variable read by {@link loadConfig}, with whether it is required. */
export const envVars = {
  MADAUTH_ISSUER: true,
  MADAUTH_SIGNING_KEY: true,
  ALLOWED_ORIGINS: true,
  GOOGLE_CLIENT_ID: true,
  GOOGLE_CLIENT_SECRET: false,
  SESSION_TTL: false,
  COOKIE_DOMAIN: false,
} as const;

const DEFAULT_SESSION_TTL = 8 * 60 * 60;

export class ConfigError extends Error {
  override name = 'ConfigError';
}

function parseOrigin(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(`${name}: "${value}" is not a URL.`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConfigError(`${name}: "${value}" must be an http(s) URL.`);
  }
  return url.origin;
}

/**
 * Reads and validates the madAuth configuration from environment variables.
 * Throws a {@link ConfigError} naming the variable that is missing or invalid.
 */
export async function loadConfig(env: Record<string, string | undefined>): Promise<MadauthConfig> {
  const read = (name: keyof typeof envVars) => env[name]?.trim() || undefined;
  const require = (name: keyof typeof envVars) => {
    const value = read(name);
    if (!value) throw new ConfigError(`${name} is not set. See docs/server.md.`);
    return value;
  };

  const issuerValue = require('MADAUTH_ISSUER');
  parseOrigin('MADAUTH_ISSUER', issuerValue);
  const issuer = issuerValue.replace(/\/+$/, '');

  const keyValue = read('MADAUTH_SIGNING_KEY');
  if (!keyValue) {
    const key = await generateSigningKey();
    throw new ConfigError(
      'MADAUTH_SIGNING_KEY is not set. Here is a newly generated key you can use ' +
        '(keep it secret and use the same key on every instance):\n\n' +
        `MADAUTH_SIGNING_KEY='${JSON.stringify(key)}'\n`,
    );
  }
  let signingKey: JWK;
  try {
    signingKey = JSON.parse(keyValue) as JWK;
    assertPrivateSigningJwk(signingKey);
  } catch (e) {
    const reason = e instanceof SyntaxError ? 'is not valid JSON' : (e as Error).message;
    throw new ConfigError(`MADAUTH_SIGNING_KEY ${reason}. Generate one with: npx @madauth/server generate-key`);
  }

  const allowedOrigins = require('ALLOWED_ORIGINS')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean)
    .map((o) => parseOrigin('ALLOWED_ORIGINS', o));

  const clientId = require('GOOGLE_CLIENT_ID');
  if (!clientId.endsWith('.apps.googleusercontent.com')) {
    throw new ConfigError(`GOOGLE_CLIENT_ID must end with ".apps.googleusercontent.com" but is "${clientId}".`);
  }

  const ttlValue = read('SESSION_TTL');
  const sessionTtlSeconds = ttlValue ? Number(ttlValue) : DEFAULT_SESSION_TTL;
  if (!Number.isInteger(sessionTtlSeconds) || sessionTtlSeconds < 60) {
    throw new ConfigError(`SESSION_TTL must be a whole number of seconds (at least 60) but is "${ttlValue}".`);
  }

  return {
    issuer,
    signingKey,
    allowedOrigins,
    sessionTtlSeconds,
    cookieDomain: read('COOKIE_DOMAIN'),
    google: { clientId, clientSecret: read('GOOGLE_CLIENT_SECRET') },
  };
}
