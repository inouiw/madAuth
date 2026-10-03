import type { JWK, JWTVerifyGetKey } from 'jose';
import { assertPrivateSigningJwk, generateSigningKey } from './keys.js';
import { consoleMailer, createSmtpMailer, type Mailer } from './mail.js';
import type { StoreAdapter } from './store/schema.js';

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
  /** Google sign-in; off when GOOGLE_CLIENT_ID is not set. */
  google?: {
    /** OAuth web client ID (GOOGLE_CLIENT_ID). */
    clientId: string;
    /** Enables the server-side code flow (GOOGLE_CLIENT_SECRET). */
    clientSecret?: string;
  };
  /** E-mail & password sign-in; off without a store (DATABASE_URL or the `store` option). */
  password?: {
    /** PASSWORD_MIN_LENGTH. */
    minLength: number;
    store: StoreAdapter;
    mailer: Mailer;
  };
  /** Test hook: resolves Google's signing keys. Defaults to Google's published JWKS. */
  jwksResolver?: JWTVerifyGetKey;
}

/** Every environment variable read by {@link loadConfig}, with whether it is required. */
export const envVars = {
  MADAUTH_ISSUER: true,
  MADAUTH_SIGNING_KEY: true,
  ALLOWED_ORIGINS: true,
  GOOGLE_CLIENT_ID: false,
  GOOGLE_CLIENT_SECRET: false,
  DATABASE_URL: false,
  SMTP_URL: false,
  MAIL_FROM: false,
  PASSWORD_MIN_LENGTH: false,
  SESSION_TTL: false,
  COOKIE_DOMAIN: false,
} as const;

/** Instead of environment variables: your own store adapter or mailer. */
export interface ConfigOverrides {
  /** Stores users; replaces DATABASE_URL. */
  store?: StoreAdapter;
  /** Sends e-mails; replaces SMTP_URL and MAIL_FROM. */
  mailer?: Mailer;
}

const DEFAULT_SESSION_TTL = 8 * 60 * 60;
const DEFAULT_PASSWORD_MIN_LENGTH = 8;

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
export async function loadConfig(
  env: Record<string, string | undefined>,
  overrides: ConfigOverrides = {},
): Promise<MadauthConfig> {
  // Docker's --env-file keeps quotes around values (NAME='value'); Node's --env-file removes them.
  const read = (name: keyof typeof envVars) => env[name]?.trim().replace(/^(['"])(.*)\1$/s, '$2').trim() || undefined;
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

  const clientId = read('GOOGLE_CLIENT_ID');
  if (clientId && !clientId.endsWith('.apps.googleusercontent.com')) {
    throw new ConfigError(`GOOGLE_CLIENT_ID must end with ".apps.googleusercontent.com" but is "${clientId}".`);
  }

  const store = overrides.store ?? (await storeFromDatabaseUrl(read('DATABASE_URL')));
  let password: MadauthConfig['password'];
  if (store) {
    const mailer = overrides.mailer ?? mailerFromEnv(read('SMTP_URL'), read('MAIL_FROM'));
    const minValue = read('PASSWORD_MIN_LENGTH');
    const minLength = minValue ? Number(minValue) : DEFAULT_PASSWORD_MIN_LENGTH;
    if (!Number.isInteger(minLength) || minLength < 1 || minLength > 128) {
      throw new ConfigError(`PASSWORD_MIN_LENGTH must be a whole number from 1 to 128 but is "${minValue}".`);
    }
    password = { minLength, store, mailer };
  }

  if (!clientId && !password) {
    throw new ConfigError(
      'No sign-in method is configured. Set GOOGLE_CLIENT_ID for Google sign-in and/or DATABASE_URL ' +
        '(e.g. sqlite:./madauth.db) for e-mail & password sign-in. See docs/server.md.',
    );
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
    google: clientId ? { clientId, clientSecret: read('GOOGLE_CLIENT_SECRET') } : undefined,
    password,
  };
}

/** `DATABASE_URL=sqlite:<path>` creates the built-in SQLite adapter, just as passing it as `store` would. */
async function storeFromDatabaseUrl(url: string | undefined): Promise<StoreAdapter | undefined> {
  if (!url) return undefined;
  if (!url.startsWith('sqlite:')) {
    throw new ConfigError(
      `DATABASE_URL must start with "sqlite:" (e.g. sqlite:/data/madauth.db) but is "${url}". ` +
        'For other databases, pass your own store adapter (see "Custom store adapter" in docs/server.md).',
    );
  }
  const path = url.slice('sqlite:'.length);
  if (!path) throw new ConfigError('DATABASE_URL needs a file path, e.g. sqlite:/data/madauth.db');
  const { createSqliteAdapter } = await import('./store/sqlite.js');
  try {
    return createSqliteAdapter(path);
  } catch (e) {
    throw new ConfigError(`DATABASE_URL: could not open "${path}": ${(e as Error).message}`);
  }
}

function mailerFromEnv(url: string | undefined, from: string | undefined): Mailer {
  if (!url) {
    throw new ConfigError(
      'SMTP_URL is not set. E-mail & password sign-in sends e-mails: set SMTP_URL (e.g. ' +
        'smtps://user:password@smtp.example.com:465), or SMTP_URL=console to print them during development.',
    );
  }
  if (url === 'console') return consoleMailer;
  if (!/^smtps?:\/\//.test(url)) throw new ConfigError('SMTP_URL must start with smtp:// or smtps://, or be "console".');
  if (!from) throw new ConfigError('MAIL_FROM is not set, e.g. MAIL_FROM="Example" <no-reply@example.com>');
  return createSmtpMailer(url, from);
}
