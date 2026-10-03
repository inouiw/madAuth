import type { JWK, JWTVerifyGetKey } from 'jose';
import { assertPrivateSigningJwk, generateSigningKey } from './keys.js';
import type { StoreAdapter } from './store/schema.js';
import { WEBHOOK_TYPES, checkWebhookSecret, generateWebhookSecret, type WebhookSettings } from './webhooks.js';

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
  };
  /** Where madAuth sends e-mails, sign-up checks and events (WEBHOOK_URL); required for password sign-in. */
  webhook?: WebhookSettings;
  /** Test hook: resolves Google's signing keys. Defaults to Google's published JWKS. */
  jwksResolver?: JWTVerifyGetKey;
  /** Test hook: the fetch used for webhook calls. */
  webhookFetch?: typeof fetch;
}

/** Every environment variable read by {@link loadConfig}, with whether it is required. */
export const envVars = {
  MADAUTH_ISSUER: true,
  MADAUTH_SIGNING_KEY: true,
  ALLOWED_ORIGINS: true,
  GOOGLE_CLIENT_ID: false,
  GOOGLE_CLIENT_SECRET: false,
  DATABASE_URL: false,
  PASSWORD_MIN_LENGTH: false,
  WEBHOOK_URL: false,
  WEBHOOK_SECRET: false,
  WEBHOOK_EVENTS: false,
  SESSION_TTL: false,
  COOKIE_DOMAIN: false,
} as const;

/** Instead of environment variables: your own store adapter. */
export interface ConfigOverrides {
  /** Stores users; replaces DATABASE_URL. */
  store?: StoreAdapter;
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

/** Docker's --env-file keeps quotes around values (NAME='value'); Node's --env-file removes them. */
function readEnv(env: Record<string, string | undefined>, name: keyof typeof envVars): string | undefined {
  return env[name]?.trim().replace(/^(['"])(.*)\1$/s, '$2').trim() || undefined;
}

/**
 * Reads and validates the madAuth configuration from environment variables.
 * Throws a {@link ConfigError} naming the variable that is missing or invalid.
 */
export async function loadConfig(
  env: Record<string, string | undefined>,
  overrides: ConfigOverrides = {},
): Promise<MadauthConfig> {
  const read = (name: keyof typeof envVars) => readEnv(env, name);
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

  const webhook = webhookFromEnv(read('WEBHOOK_URL'), read('WEBHOOK_SECRET'), read('WEBHOOK_EVENTS'));

  const store = overrides.store ?? (await storeFromDatabaseUrl(read('DATABASE_URL')));
  let password: MadauthConfig['password'];
  if (store) {
    if (!webhook) {
      throw new ConfigError(
        'WEBHOOK_URL is not set. E-mail & password sign-in sends its e-mails through your webhook. For ' +
          'development, run the example receiver (npm run dev:webhooks) and set ' +
          'WEBHOOK_URL=http://localhost:8790/webhook. See "Webhooks" in docs/server.md.',
      );
    }
    password = { minLength: passwordMinLength(read('PASSWORD_MIN_LENGTH')), store };
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
    webhook,
  };
}

/**
 * Only the settings needed to manage users from the command line (DATABASE_URL, PASSWORD_MIN_LENGTH), so
 * `create-user` works without a running webhook receiver.
 */
export async function loadUserStoreConfig(env: Record<string, string | undefined>): Promise<NonNullable<MadauthConfig['password']>> {
  const store = await storeFromDatabaseUrl(readEnv(env, 'DATABASE_URL'));
  if (!store) throw new ConfigError('Set DATABASE_URL to manage users.');
  return { store, minLength: passwordMinLength(readEnv(env, 'PASSWORD_MIN_LENGTH')) };
}

function passwordMinLength(value: string | undefined): number {
  const minLength = value ? Number(value) : DEFAULT_PASSWORD_MIN_LENGTH;
  if (!Number.isInteger(minLength) || minLength < 1 || minLength > 128) {
    throw new ConfigError(`PASSWORD_MIN_LENGTH must be a whole number from 1 to 128 but is "${value}".`);
  }
  return minLength;
}

/**
 * `DATABASE_URL=sqlite:<path>` or `DATABASE_URL=dynamodb:<table>` creates the built-in adapter, just as
 * passing it as `store` would.
 */
async function storeFromDatabaseUrl(url: string | undefined): Promise<StoreAdapter | undefined> {
  if (!url) return undefined;
  if (url.startsWith('dynamodb:')) return dynamoDbStore(url.slice('dynamodb:'.length));
  if (!url.startsWith('sqlite:')) {
    throw new ConfigError(
      `DATABASE_URL must start with "sqlite:" (e.g. sqlite:/data/madauth.db) or "dynamodb:" (e.g. ` +
        `dynamodb:madauth) but is "${url}". For other databases, pass your own store adapter (see "Custom ` +
        'store adapter" in docs/server.md).',
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

async function dynamoDbStore(tableName: string): Promise<StoreAdapter> {
  if (!tableName) throw new ConfigError('DATABASE_URL needs a table name, e.g. dynamodb:madauth');
  // The adapter loads the AWS SDK on first use; check here that it is installed, so a missing package
  // stops the start-up instead of the first sign-in.
  try {
    await import('@aws-sdk/client-dynamodb');
  } catch (e) {
    throw new ConfigError(
      'DATABASE_URL=dynamodb: needs the AWS SDK. Install it next to madAuth: npm install @aws-sdk/client-dynamodb ' +
        `(${(e as Error).message})`,
    );
  }
  const { createDynamoDbAdapter } = await import('./store/dynamodb.js');
  return createDynamoDbAdapter({ tableName });
}

/** Hosts that may be called over plain http, e.g. a receiver on the developer's machine. */
const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]', 'host.docker.internal'];

function webhookFromEnv(
  url: string | undefined,
  secret: string | undefined,
  events: string | undefined,
): WebhookSettings | undefined {
  if (!url) {
    if (secret || events) throw new ConfigError('WEBHOOK_SECRET and WEBHOOK_EVENTS need WEBHOOK_URL.');
    return undefined;
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ConfigError(`WEBHOOK_URL: "${url}" is not a URL.`);
  }
  // The calls carry e-mail links and codes, so they must be encrypted unless they stay on this machine.
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && LOCAL_HOSTS.includes(parsed.hostname))) {
    throw new ConfigError(`WEBHOOK_URL must be an https URL (http only for localhost) but is "${url}".`);
  }
  if (!secret) {
    throw new ConfigError(
      'WEBHOOK_SECRET is not set. Here is a newly generated secret you can use (keep it secret; your ' +
        `webhook receiver needs the same one):\n\nWEBHOOK_SECRET=${generateWebhookSecret()}\n`,
    );
  }
  const problem = checkWebhookSecret(secret);
  if (problem) {
    throw new ConfigError(`WEBHOOK_SECRET ${problem}. Generate one with: npx @madauth/server generate-webhook-secret`);
  }
  let selected: Set<string> | null = null;
  if (events) {
    selected = new Set(events.split(',').map((e) => e.trim()).filter(Boolean));
    const unknown = [...selected].filter((e) => !(WEBHOOK_TYPES as readonly string[]).includes(e));
    if (unknown.length) {
      throw new ConfigError(`WEBHOOK_EVENTS: unknown type ${unknown.join(', ')}. Known types: ${WEBHOOK_TYPES.join(', ')}.`);
    }
  }
  return { url: parsed.href, secret, events: selected };
}
