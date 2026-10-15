import type { JWK, JWTVerifyGetKey } from 'jose';
import { assertPrivateSigningJwk, generateSigningKey } from './keys.js';
import { METHODS_SETTING, Settings, legacyAppProblem, type MethodConfig } from './settings.js';
import type { StoreAdapter } from './store/schema.js';
import {
  DEV_WEBHOOK_RECEIVER_URL,
  REQUIRED_EMAIL_TYPES,
  WEBHOOK_TYPES,
  checkWebhookSecret,
  generateWebhookSecret,
  type WebhookSettings,
} from './webhooks.js';

export interface MadauthConfig {
  /** Public base URL of the server (MADAUTH_ISSUER). */
  issuer: string;
  /** Private ES256 JWK (MADAUTH_SIGNING_KEY). */
  signingKey: JWK;
  /** App origins allowed to call the server (ALLOWED_ORIGINS). */
  allowedOrigins: string[];
  /** Lifetime of a session token in seconds (SESSION_TTL): how long backends accept it. */
  sessionTtlSeconds: number;
  /** How long a session can be renewed without signing in again, counted from its last renewal (SESSION_RENEWAL_TTL). */
  renewalTtlSeconds: number;
  /** Cookie domain, e.g. `.example.com` (COOKIE_DOMAIN). */
  cookieDomain?: string;
  /** The name authenticator apps show next to the account (AUTHENTICATOR_ISSUER). Default: the host of the app that asked for the setup. */
  authenticatorIssuer?: string;
  /**
   * The domain passkeys belong to (PASSKEY_RP_ID), e.g. `example.com` for apps on `example.com` and its
   * subdomains. Default: the host of the app that asks, so a passkey works on that host only.
   */
  passkeyRpId?: string;
  /** Google sign-in; off when GOOGLE_CLIENT_ID is not set. */
  google?: {
    /** OAuth web client ID (GOOGLE_CLIENT_ID). */
    clientId: string;
    /** Enables the server-side code flow (GOOGLE_CLIENT_SECRET). */
    clientSecret?: string;
  };
  /** GitHub sign-in; off when GITHUB_CLIENT_ID is not set. GitHub only has the redirect flow, so the secret is needed too. */
  github?: {
    /** The client ID of the OAuth App (GITHUB_CLIENT_ID). */
    clientId: string;
    /** Its client secret (GITHUB_CLIENT_SECRET). */
    clientSecret: string;
  };
  /** Where the users, their accounts, claims and the settings are kept (DATABASE_URL or the `store` option). */
  store: StoreAdapter;
  /**
   * E-mail & password sign-in; off unless the webhook sends the e-mails (`email.send_verification` and `email.send_password_reset`).
   * Its rules for new passwords are a setting, see `Settings.passwordRules`.
   */
  password?: Record<string, never>;
  /** Where madAuth sends e-mails, sign-up checks and events (WEBHOOK_URL). */
  webhook?: WebhookSettings;
  /** Test hook: resolves Google's signing keys. Defaults to Google's published JWKS. */
  jwksResolver?: JWTVerifyGetKey;
  /** Test hook: the fetch used for webhook calls. */
  webhookFetch?: typeof fetch;
}

/** Whether the webhook sends the e-mails that confirm an address (`email.send_verification`), so people can sign up with one. */
export function sendsVerificationEmails(config: Pick<MadauthConfig, 'webhook'>): boolean {
  return !!config.webhook?.events.has('email.send_verification');
}

/** Whether the webhook sends the sign-in e-mails of the e-mail link (`email.send_signin_link`), so the method can be on. */
export function sendsSignInEmails(config: Pick<MadauthConfig, 'webhook'>): boolean {
  return !!config.webhook?.events.has('email.send_signin_link');
}

/** Whether the webhook sends the SMS (`sms.send_code`), so SMS codes can be a second factor. */
export function sendsSms(config: Pick<MadauthConfig, 'webhook'>): boolean {
  return !!config.webhook?.events.has('sms.send_code');
}

/** What decides which methods the server is configured for, see `isConfigured` and `initialMethods`. */
export function methodConfig(config: MadauthConfig): MethodConfig {
  return {
    google: config.google,
    github: config.github,
    password: config.password,
    emailVerification: sendsVerificationEmails(config),
    emailLink: sendsSignInEmails(config),
    sms: sendsSms(config),
  };
}

/** Every environment variable read by {@link loadConfig}, with whether it is required. */
export const envVars = {
  MADAUTH_ISSUER: true,
  MADAUTH_SIGNING_KEY: true,
  ALLOWED_ORIGINS: true,
  GOOGLE_CLIENT_ID: false,
  GOOGLE_CLIENT_SECRET: false,
  GITHUB_CLIENT_ID: false,
  GITHUB_CLIENT_SECRET: false,
  DATABASE_URL: true,
  AUTHENTICATOR_ISSUER: false,
  PASSKEY_RP_ID: false,
  WEBHOOK_URL: false,
  WEBHOOK_SECRET: false,
  WEBHOOK_EVENTS: false,
  SESSION_TTL: false,
  SESSION_RENEWAL_TTL: false,
  COOKIE_DOMAIN: false,
} as const;

/** Instead of environment variables: your own store adapter. */
export interface ConfigOverrides {
  /** Stores users; replaces DATABASE_URL. */
  store?: StoreAdapter;
}

type Env = Record<string, string | undefined>;

/** Options of the hosting entry points: `start` (Node), `createHandler` (AWS Lambda) and `register` (Azure). */
export interface EntryOptions extends ConfigOverrides {
  /**
   * The environment variables to read, or a function that loads them, e.g. to add secrets from a
   * parameter store. The function runs once, before the first request. Default: `process.env`.
   */
  env?: Env | (() => Env | Promise<Env>);
}

/** The environment variables an entry point reads its configuration from. */
export async function resolveEnv(source: EntryOptions['env'] = process.env): Promise<Env> {
  return typeof source === 'function' ? source() : source;
}

const DEFAULT_SESSION_TTL = 8 * 60 * 60;
const DEFAULT_RENEWAL_TTL = 30 * 24 * 60 * 60;

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
 * A variable's value, or undefined if it is empty. Docker's --env-file keeps quotes around values
 * (NAME='value'); Node's --env-file removes them.
 */
const unquote = (value: string | undefined): string | undefined => value?.trim().replace(/^(['"])(.*)\1$/s, '$2').trim() || undefined;

function readEnv(env: Record<string, string | undefined>, name: keyof typeof envVars): string | undefined {
  return unquote(env[name]);
}

/**
 * Reads and validates the madAuth configuration from environment variables, and checks that the settings in
 * the store can be used as they are. Throws a {@link ConfigError} naming the variable that is missing or
 * invalid, or the setting an admin has to set again.
 */
export async function loadConfig(env: Record<string, string | undefined>, overrides: ConfigOverrides = {}): Promise<MadauthConfig> {
  const config = await readConfig(env, overrides);
  // A setting whose meaning changed is not guessed at: the admin chooses (the command line reads the configuration with readConfig).
  const problem = legacyAppProblem(await new Settings(config.store).get(METHODS_SETTING));
  if (problem) throw new ConfigError(problem);
  return config;
}

/** {@link loadConfig} without the check of the stored settings: for the command line, which sets them. */
export async function readConfig(
  env: Record<string, string | undefined>,
  overrides: ConfigOverrides = {},
): Promise<MadauthConfig> {
  const read = (name: keyof typeof envVars) => readEnv(env, name);
  const require = (name: keyof typeof envVars) => {
    const value = read(name);
    if (!value) throw new ConfigError(`${name} is not set. See docs/server.md.`);
    return value;
  };

  // Removed after 0.4.0-beta.1. Ignoring it could lower the minimum an operator chose, so the server doesn't start with it.
  if (env.PASSWORD_MIN_LENGTH?.trim()) {
    throw new ConfigError(
      'PASSWORD_MIN_LENGTH was removed: the password rules are a setting now (default: at least 8 characters). ' +
        'Remove the variable and set the rules with `npx @madauth/server set-password-rules min-length=' +
        `${env.PASSWORD_MIN_LENGTH.trim()}\` or Madauth.admin.setSettings. See docs/upgrading.md.`,
    );
  }
  // Renamed in 0.6. Ignored, it would change the name new authenticator apps show without a word.
  if (unquote(env.TOTP_ISSUER)) {
    throw new ConfigError('TOTP_ISSUER is now AUTHENTICATOR_ISSUER: rename the variable. See docs/upgrading.md.');
  }

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
  // GitHub has no browser-only flow: the server exchanges the code itself, which takes the secret. A secret
  // without the ID is ignored, like Google's: a secrets store may hold one for a server that has GitHub off.
  const githubClientId = read('GITHUB_CLIENT_ID');
  const githubClientSecret = read('GITHUB_CLIENT_SECRET');
  if (githubClientId && !githubClientSecret) {
    throw new ConfigError(
      'GITHUB_CLIENT_ID needs GITHUB_CLIENT_SECRET: GitHub only has the redirect flow, in which the server exchanges the code. Set both from your OAuth App at https://github.com/settings/developers.',
    );
  }

  // Validate the webhook before opening the store, so a configuration error doesn't leave a database open.
  const webhook = webhookFromEnv(read('WEBHOOK_URL'), read('WEBHOOK_SECRET'), read('WEBHOOK_EVENTS'));
  // E-mail & password sign-in needs its e-mails sent, so it is on exactly when the webhook handles them.
  const sendsEmails = !!webhook && REQUIRED_EMAIL_TYPES.every((type) => webhook.events.has(type));
  const password = sendsEmails ? {} : undefined;
  // Sign-up with the authenticator app only needs the address confirmed; the e-mail link needs its own e-mail.
  const emailVerification = !!webhook && webhook.events.has('email.send_verification');
  const emailLink = !!webhook && webhook.events.has('email.send_signin_link');

  if (!clientId && !githubClientId && !password && !emailVerification && !emailLink) {
    throw new ConfigError(
      'No sign-in method is configured. Set GOOGLE_CLIENT_ID for Google sign-in, GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET for GitHub sign-in, and/or a webhook that sends ' +
        'the e-mails: e-mail & password sign-in needs email.send_verification and email.send_password_reset, the passwordless e-mail link ' +
        `needs email.send_signin_link, sign-up with the authenticator app needs email.send_verification. For development, run the ` +
        `receiver at ${DEV_WEBHOOK_RECEIVER_URL} and set WEBHOOK_URL=http://localhost:8790/webhook and ` +
        `WEBHOOK_EVENTS=${REQUIRED_EMAIL_TYPES.join(',')},email.send_signin_link,email.send_already_registered,email.send_password_reset_no_password. See docs/server.md.`,
    );
  }
  const store = overrides.store ?? (await storeFromDatabaseUrl(read('DATABASE_URL')));
  if (!store) {
    throw new ConfigError(
      'DATABASE_URL is not set. madAuth stores every user, whichever way they sign in: set e.g. ' +
        'DATABASE_URL=sqlite:./madauth.db or DATABASE_URL=dynamodb:<table>. See docs/server.md.',
    );
  }

  const ttlValue = read('SESSION_TTL');
  const sessionTtlSeconds = ttlValue ? Number(ttlValue) : DEFAULT_SESSION_TTL;
  if (!Number.isInteger(sessionTtlSeconds) || sessionTtlSeconds < 60) {
    throw new ConfigError(`SESSION_TTL must be a whole number of seconds (at least 60) but is "${ttlValue}".`);
  }
  const renewalValue = read('SESSION_RENEWAL_TTL');
  // A session token that outlives the default renewal time is renewable for as long as it lives.
  const renewalTtlSeconds = renewalValue ? Number(renewalValue) : Math.max(DEFAULT_RENEWAL_TTL, sessionTtlSeconds);
  if (!Number.isInteger(renewalTtlSeconds) || renewalTtlSeconds < sessionTtlSeconds) {
    throw new ConfigError(
      `SESSION_RENEWAL_TTL must be a whole number of seconds, not less than SESSION_TTL (${sessionTtlSeconds}), but is "${renewalValue}".`,
    );
  }

  const passkeyRpId = read('PASSKEY_RP_ID')?.toLowerCase();
  if (passkeyRpId && !allowedOrigins.some((origin) => isWithin(new URL(origin).hostname, passkeyRpId))) {
    throw new ConfigError(
      `PASSKEY_RP_ID must be the host of an app in ALLOWED_ORIGINS or a domain above it (e.g. example.com for https://app.example.com), but "${passkeyRpId}" is neither.`,
    );
  }

  return {
    issuer,
    signingKey,
    allowedOrigins,
    passkeyRpId,
    sessionTtlSeconds,
    renewalTtlSeconds,
    cookieDomain: read('COOKIE_DOMAIN'),
    authenticatorIssuer: read('AUTHENTICATOR_ISSUER'),
    google: clientId ? { clientId, clientSecret: read('GOOGLE_CLIENT_SECRET') } : undefined,
    github: githubClientId && githubClientSecret ? { clientId: githubClientId, clientSecret: githubClientSecret } : undefined,
    store,
    password,
    webhook,
  };
}

/** Only the store from DATABASE_URL, e.g. to manage claims and settings from the command line. */
export async function loadStore(env: Record<string, string | undefined>): Promise<StoreAdapter> {
  const store = await storeFromDatabaseUrl(readEnv(env, 'DATABASE_URL'));
  if (!store) throw new ConfigError('Set DATABASE_URL to manage users.');
  return store;
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
  if (!/^[\w.-]{3,255}$/.test(tableName)) {
    throw new ConfigError(
      `DATABASE_URL=dynamodb: needs a DynamoDB table name (3 to 255 letters, digits, _ . -) but has "${tableName}"`,
    );
  }
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

/** Types of older madAuth versions and what they are now, so an old WEBHOOK_EVENTS gets a helpful error. */
const RENAMED_TYPES: Record<string, string> = {
  'password.reset': 'user.password_reset',
  'roles.changed': 'user.claims_changed',
  'email.verify': 'email.send_verification',
  'email.reset': 'email.send_password_reset',
  'email.signin': 'email.send_signin_link',
  'email.already_registered': 'email.send_already_registered',
  'email.no_password': 'email.send_password_reset_no_password',
  'sms.code': 'sms.send_code',
  'signup.before': 'user.signing_up',
  'email.verified': 'user.email_verified',
  'email.password_reset': 'user.password_reset',
  'totp.enabled': 'user.second_factor_enabled (with method "authenticator")',
  'totp.disabled': 'user.second_factor_disabled (with method "authenticator")',
  'sms.enabled': 'user.second_factor_enabled (with method "sms")',
  'sms.disabled': 'user.second_factor_disabled (with method "sms")',
  'totp.recovery_code_used': 'user.recovery_code_used',
};

/** Types that are gone, and what to use instead. */
const REMOVED_TYPES: Record<string, string> = {
  'user.created': 'user.created is gone: user.signed_up tells when a user can sign in (an unconfirmed sign-up is no user yet)',
};

/** Hosts that may be called over plain http, e.g. a receiver on the developer's machine. */
const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]', 'host.docker.internal'];

function webhookFromEnv(url: string | undefined, secret: string | undefined, events: string | undefined): WebhookSettings | undefined {
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
  // Nothing is sent that the receiver did not ask for: a type it does not know could make it answer with an
  // error, and an unanswered user.signing_up refuses every sign-up.
  const selected = new Set((events ?? '').split(',').map((e) => e.trim()).filter(Boolean));
  const allTypes = `All types: ${WEBHOOK_TYPES.join(', ')}. See "Webhooks" in docs/server.md.`;
  if (!selected.size) {
    throw new ConfigError(
      'WEBHOOK_EVENTS is not set. List the types your webhook receiver handles; only these are sent. ' +
        `E-mail & password sign-in is on when they include ${REQUIRED_EMAIL_TYPES.join(' and ')}, the passwordless ` +
        'e-mail link when they include email.send_signin_link. For a receiver that sends the e-mails:\n\n' +
        'WEBHOOK_EVENTS=email.send_verification,email.send_password_reset,email.send_signin_link,email.send_already_registered,email.send_password_reset_no_password\n\n' +
        'SMS codes as a second factor need a receiver that sends the SMS: add sms.send_code,user.second_factor_enabled,user.second_factor_disabled. ' +
        'For one that only wants to know who signed in:\n\nWEBHOOK_EVENTS=user.signed_in\n\n' +
        allTypes,
    );
  }
  const unknown = [...selected].filter((e) => !(WEBHOOK_TYPES as readonly string[]).includes(e));
  if (unknown.length) {
    const renamed = unknown.flatMap((e) => (e in RENAMED_TYPES ? [`${e} is now ${RENAMED_TYPES[e]}`] : e in REMOVED_TYPES ? [REMOVED_TYPES[e]] : []));
    throw new ConfigError(
      `WEBHOOK_EVENTS: unknown type ${unknown.join(', ')}. ${renamed.length ? `${renamed.join('; ')}. ` : ''}` +
        `Known types: ${WEBHOOK_TYPES.join(', ')}.`,
    );
  }
  return { url: parsed.href, secret, events: selected };
}

/** Whether `host` is `domain` or one of its subdomains, as WebAuthn requires of a page and its passkeys' domain. */
export function isWithin(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}
