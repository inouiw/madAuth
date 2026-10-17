import type { JWTVerifyGetKey } from 'jose';
import { awsIamSignerFromSdk, functionUrlRegion } from './aws-iam.js';
import { createAwsKmsKeyService, deploymentOf, kmsFromSdk } from './aws-kms.js';
import { createLocalKeyService, parseSigningKeys, type KeyService } from './key-service.js';
import { generateSigningKey } from './keys.js';
import { isValidEmail, normalizeEmail } from './password.js';
import type { MethodConfig } from './settings.js';
import type { StoreAdapter } from './store/schema.js';
import {
  REQUIRED_EMAIL_TYPES,
  WEBHOOK_TYPES,
  checkWebhookSecret,
  generateWebhookSecret,
  type WebhookAuth,
  type WebhookSettings,
} from './webhooks.js';

export interface MadauthConfig {
  /** Public base URL of the server (MADAUTH_ISSUER). */
  issuer: string;
  /**
   * Signs the tokens, hashes the codes and encrypts the secrets (see key-service.ts). `loadConfig` makes the
   * local one from MADAUTH_SIGNING_KEY: one private ES256 JWK, or a set of them, the newest first.
   */
  keyService: KeyService;
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
  /**
   * Google sign-in from GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, as before madAuth 0.7: imported once into the
   * store's providers when it has no Google provider (see `importProviders` in providers.ts), and ignored otherwise.
   */
  google?: {
    /** OAuth web client ID (GOOGLE_CLIENT_ID). */
    clientId: string;
    /** Enables the server-side code flow (GOOGLE_CLIENT_SECRET). */
    clientSecret?: string;
  };
  /** GitHub sign-in from GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, imported once like {@link google}. */
  github?: {
    /** The client ID of the OAuth App (GITHUB_CLIENT_ID). */
    clientId: string;
    /** Its client secret (GITHUB_CLIENT_SECRET). */
    clientSecret: string;
  };
  /** Where the users, their accounts, claims and the settings are kept (DATABASE_URL or the `store` option). */
  store: StoreAdapter;
  /**
   * The address whose user gets the role `admin` when they sign in with it, once it is proven
   * (INITIAL_ADMIN_EMAIL, normalized). Once per value: see `Admins.applyInitial`.
   */
  initialAdminEmail?: string;
  /**
   * E-mail & password sign-in; off unless the webhook sends the e-mails (`email.send_verification` and `email.send_password_reset`).
   * Its rules for new passwords are a setting, see `Settings.passwordRules`.
   */
  password?: Record<string, never>;
  /** Where madAuth sends e-mails, sign-up checks and events (WEBHOOK_URL), and how it signs them (WEBHOOK_SECRET or WEBHOOK_AUTH). */
  webhook?: WebhookSettings;
  /**
   * Where your app lists the scopes of its API, which API keys can have next to madAuth's own
   * (API_KEY_SCOPES_URL). Without it, keys only have madAuth's scopes. See docs/api-keys.md.
   */
  apiKeyScopesUrl?: string;
  /** Test hook: resolves Google's signing keys. Defaults to Google's published JWKS. */
  jwksResolver?: JWTVerifyGetKey;
  /** Test hook: the fetch used for webhook calls. */
  webhookFetch?: typeof fetch;
  /** Test hook: the fetch that reads API_KEY_SCOPES_URL. */
  scopesFetch?: typeof fetch;
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

/**
 * What of the server's configuration decides which methods it has, see `isConfigured` and `initialMethods`.
 * Google and GitHub come from the providers in the store, on every request.
 */
export function methodConfig(config: MadauthConfig): MethodConfig {
  return {
    password: config.password,
    emailVerification: sendsVerificationEmails(config),
    emailLink: sendsSignInEmails(config),
    sms: sendsSms(config),
  };
}

/** Every environment variable read by {@link loadConfig}, with whether it is required. */
export const envVars = {
  MADAUTH_ISSUER: true,
  MADAUTH_KEY_SERVICE: true,
  MADAUTH_SIGNING_KEY: false,
  ALLOWED_ORIGINS: true,
  GOOGLE_CLIENT_ID: false,
  GOOGLE_CLIENT_SECRET: false,
  GITHUB_CLIENT_ID: false,
  GITHUB_CLIENT_SECRET: false,
  DATABASE_URL: true,
  DATABASE_MIGRATE: false,
  INITIAL_ADMIN_EMAIL: false,
  AUTHENTICATOR_ISSUER: false,
  PASSKEY_RP_ID: false,
  WEBHOOK_URL: false,
  WEBHOOK_SECRET: false,
  WEBHOOK_AUTH: false,
  WEBHOOK_EVENTS: false,
  API_KEY_SCOPES_URL: false,
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
export const unquote = (value: string | undefined): string | undefined => value?.trim().replace(/^(['"])(.*)\1$/s, '$2').trim() || undefined;

function readEnv(env: Record<string, string | undefined>, name: keyof typeof envVars): string | undefined {
  return unquote(env[name]);
}

/**
 * Reads and validates the madAuth configuration from environment variables. Throws a {@link ConfigError}
 * naming the variable that is missing or invalid.
 */
export async function loadConfig(env: Record<string, string | undefined>, overrides: ConfigOverrides = {}): Promise<MadauthConfig> {
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
        `Remove the variable, and an admin sets the rules with Madauth.admin.setSettings({ password: { minLength: ${env.PASSWORD_MIN_LENGTH.trim()} } }). ` +
        'See docs/upgrading.md.',
    );
  }
  // Renamed in 0.6. Ignored, it would change the name new authenticator apps show without a word.
  if (unquote(env.TOTP_ISSUER)) {
    throw new ConfigError('TOTP_ISSUER is now AUTHENTICATOR_ISSUER: rename the variable. See docs/upgrading.md.');
  }

  const issuerValue = require('MADAUTH_ISSUER');
  parseOrigin('MADAUTH_ISSUER', issuerValue);
  const issuer = issuerValue.replace(/\/+$/, '');

  const keyService = await keyServiceFromEnv(read, issuer);

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

  const webhook = await webhookFromEnv(read('WEBHOOK_URL'), read('WEBHOOK_SECRET'), read('WEBHOOK_AUTH'), read('WEBHOOK_EVENTS'));
  // E-mail & password sign-in needs its e-mails sent, so it is on exactly when the webhook handles them.
  const sendsEmails = !!webhook && REQUIRED_EMAIL_TYPES.every((type) => webhook.events.has(type));
  const password = sendsEmails ? {} : undefined;
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

  const initialAdminEmail = read('INITIAL_ADMIN_EMAIL');
  if (initialAdminEmail && !isValidEmail(initialAdminEmail)) {
    throw new ConfigError(`INITIAL_ADMIN_EMAIL must be an e-mail address, e.g. you@example.com, but is "${initialAdminEmail}".`);
  }

  const apiKeyScopesUrl = read('API_KEY_SCOPES_URL');
  if (apiKeyScopesUrl && !isServiceUrl(apiKeyScopesUrl)) {
    throw new ConfigError(`API_KEY_SCOPES_URL must be an https URL (http only for localhost) but is "${apiKeyScopesUrl}".`);
  }

  const passkeyRpId = read('PASSKEY_RP_ID')?.toLowerCase();
  if (passkeyRpId && !allowedOrigins.some((origin) => isWithin(new URL(origin).hostname, passkeyRpId))) {
    throw new ConfigError(
      `PASSKEY_RP_ID must be the host of an app in ALLOWED_ORIGINS or a domain above it (e.g. example.com for https://app.example.com), but "${passkeyRpId}" is neither.`,
    );
  }

  // The store is opened last, so a configuration error doesn't leave a database connection open. A server may
  // start without any sign-in method: its providers are added in the store, by the setup token's holder until
  // the first admin exists (see setup.ts).
  const migrate = read('DATABASE_MIGRATE')?.toLowerCase() ?? 'true';
  if (migrate !== 'true' && migrate !== 'false') {
    throw new ConfigError(`DATABASE_MIGRATE must be true or false but is "${read('DATABASE_MIGRATE')}".`);
  }
  const store = overrides.store ?? (await storeFromDatabaseUrl(read('DATABASE_URL'), { migrate: migrate === 'true' }));
  if (!store) {
    throw new ConfigError(
      'DATABASE_URL is not set. madAuth stores every user, whichever way they sign in: set e.g. ' +
        'DATABASE_URL=sqlite:./madauth.db, DATABASE_URL=postgres://<user>:<password>@<host>/<database> or ' +
        'DATABASE_URL=dynamodb:<table>. See docs/server.md.',
    );
  }

  return {
    issuer,
    keyService,
    allowedOrigins,
    passkeyRpId,
    sessionTtlSeconds,
    renewalTtlSeconds,
    cookieDomain: read('COOKIE_DOMAIN'),
    authenticatorIssuer: read('AUTHENTICATOR_ISSUER'),
    google: clientId ? { clientId, clientSecret: read('GOOGLE_CLIENT_SECRET') } : undefined,
    github: githubClientId && githubClientSecret ? { clientId: githubClientId, clientSecret: githubClientSecret } : undefined,
    store,
    initialAdminEmail: initialAdminEmail ? normalizeEmail(initialAdminEmail) : undefined,
    apiKeyScopesUrl,
    password,
    webhook,
  };
}

/**
 * `DATABASE_URL=sqlite:<path>`, `postgres://…` or `dynamodb:<table>` creates the built-in adapter, just as
 * passing it as `store` would.
 */
async function storeFromDatabaseUrl(url: string | undefined, options: { migrate: boolean }): Promise<StoreAdapter | undefined> {
  if (!url) return undefined;
  if (url.startsWith('dynamodb:')) return dynamoDbStore(url.slice('dynamodb:'.length));
  if (/^postgres(ql)?:\/\//.test(url)) return postgresStore(url, options);
  if (!url.startsWith('sqlite:')) {
    throw new ConfigError(
      `DATABASE_URL must start with "sqlite:" (e.g. sqlite:/data/madauth.db), "postgres://" or "postgresql://" ` +
        `(e.g. postgres://madauth:<password>@db:5432/madauth) or "dynamodb:" (e.g. dynamodb:madauth) but is ` +
        `"${redactUrl(url)}". For other databases, pass your own store adapter (see "Custom store adapter" in docs/server.md).`,
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

/** The URL without its user name and password, for error messages. */
function redactUrl(url: string): string {
  return url.replace(/^([a-z][\w+.-]*:\/\/)[^/?#]*@/i, '$1');
}

async function postgresStore(url: string, options: { migrate: boolean }): Promise<StoreAdapter> {
  // Checked here, so a missing package stops the start-up with a hint.
  const pg = await import('pg').catch((e: unknown) => e as Error);
  if (pg instanceof Error) {
    throw new ConfigError(`DATABASE_URL=postgres:// needs the pg package. Install it next to madAuth: npm install pg (${pg.message})`);
  }
  const { openPostgresAdapter } = await import('./store/postgres.js');
  const opened = await openPostgresAdapter(url, options).catch((e: unknown) => e as Error);
  if (opened instanceof Error) {
    // The driver's messages name the host, never the password.
    throw new ConfigError(`DATABASE_URL: could not open "${redactUrl(url)}": ${opened.message}`);
  }
  return opened;
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

/**
 * The key service MADAUTH_KEY_SERVICE chooses: `aws-kms`, whose keys never leave KMS, or `local`, whose keys
 * (MADAUTH_SIGNING_KEY) are in the process's memory. There is no default: the operator chooses where the keys are.
 */
async function keyServiceFromEnv(read: (name: keyof typeof envVars) => string | undefined, issuer: string): Promise<KeyService> {
  const choice = read('MADAUTH_KEY_SERVICE');
  const signingKey = read('MADAUTH_SIGNING_KEY');
  if (choice === 'aws-kms') {
    // A clean cut: no key in a variable, also not an old one to read what it made.
    if (signingKey) {
      throw new ConfigError(
        'MADAUTH_SIGNING_KEY is set, but with MADAUTH_KEY_SERVICE=aws-kms the keys are in KMS and in no variable: remove it ' +
          '(from .env, or on AWS from the Parameter Store). What the switch ends is in "AWS KMS" in docs/server.md.',
      );
    }
    const sdk = await kmsFromSdk();
    if ('problem' in sdk) throw new ConfigError(`MADAUTH_KEY_SERVICE=aws-kms: ${sdk.problem}. AWS Lambda has the SDK; elsewhere, install it next to madAuth.`);
    const made = await createAwsKmsKeyService(sdk.kms, deploymentOf(issuer));
    if ('problem' in made) throw new ConfigError(`MADAUTH_KEY_SERVICE=aws-kms: ${made.problem}. See "AWS KMS" in docs/server.md.`);
    return made.keyService;
  }
  if (choice !== 'local') {
    throw new ConfigError(
      (choice ? `MADAUTH_KEY_SERVICE must be aws-kms or local, but is "${choice}". ` : 'MADAUTH_KEY_SERVICE is not set. ') +
        'Choose where madAuth keeps its keys: aws-kms (in AWS KMS, where they never leave it; the AWS template sets it up) or ' +
        `local (MADAUTH_SIGNING_KEY, in the server's memory${signingKey ? ': set MADAUTH_KEY_SERVICE=local to keep using yours' : ''}). ` +
        'See "Key service" in docs/server.md.',
    );
  }
  if (!signingKey) {
    const key = await generateSigningKey();
    throw new ConfigError(
      'MADAUTH_SIGNING_KEY is not set. Here is a newly generated key you can use ' +
        '(keep it secret and use the same key on every instance):\n\n' +
        `MADAUTH_SIGNING_KEY='${JSON.stringify(key)}'\n`,
    );
  }
  const signingKeys = await parseSigningKeys(signingKey);
  if ('problem' in signingKeys) {
    throw new ConfigError(`MADAUTH_SIGNING_KEY ${signingKeys.problem}. Generate a key with: npx @madauth/server generate-key`);
  }
  console.warn(
    "[madauth] MADAUTH_KEY_SERVICE=local: madAuth's keys are in this process's memory, where whoever can read it can read them " +
      'and sign sessions for anyone. A key service keeps them out, e.g. MADAUTH_KEY_SERVICE=aws-kms: see "Key service" in docs/server.md.',
  );
  return createLocalKeyService(signingKeys.keys);
}

/** Hosts that may be called over plain http, e.g. a receiver on the developer's machine. */
const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]', 'host.docker.internal'];

/** Whether madAuth may call a URL: https, or http on this machine. */
function isServiceUrl(value: string): boolean {
  const url = URL.canParse(value) ? new URL(value) : null;
  return !!url && (url.protocol === 'https:' || (url.protocol === 'http:' && LOCAL_HOSTS.includes(url.hostname)));
}

async function webhookFromEnv(
  url: string | undefined,
  secret: string | undefined,
  auth: string | undefined,
  events: string | undefined,
): Promise<WebhookSettings | undefined> {
  if (!url) {
    if (secret || auth || events) throw new ConfigError('WEBHOOK_SECRET, WEBHOOK_AUTH and WEBHOOK_EVENTS need WEBHOOK_URL.');
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
  const signing = await webhookSigning(parsed.href, secret, auth);
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
  return { url: parsed.href, events: selected, ...signing };
}

/**
 * How the webhook calls are signed: with WEBHOOK_SECRET, or with WEBHOOK_AUTH=aws-iam with madAuth's AWS credentials,
 * for a receiver behind a Lambda Function URL with AWS_IAM auth.
 */
async function webhookSigning(url: string, secret: string | undefined, auth: string | undefined): Promise<WebhookAuth> {
  if (auth === 'aws-iam') {
    // As with MADAUTH_KEY_SERVICE=aws-kms: no secret is left in a variable, where it would still let others call the receiver.
    if (secret) {
      throw new ConfigError(
        'WEBHOOK_SECRET is set, but with WEBHOOK_AUTH=aws-iam madAuth signs the webhook calls with its AWS role and no secret: remove it ' +
          '(from .env, or on AWS from the Parameter Store), and the receiver checks the caller instead. See "AWS IAM" in docs/server.md.',
      );
    }
    const region = functionUrlRegion(url);
    if (!region) {
      throw new ConfigError(
        `WEBHOOK_AUTH=aws-iam signs the calls for a Lambda Function URL with AWS_IAM auth, so WEBHOOK_URL must be one, e.g. https://<id>.lambda-url.<region>.on.aws/, but is "${url}".`,
      );
    }
    const sdk = await awsIamSignerFromSdk(region);
    if ('problem' in sdk) throw new ConfigError(`WEBHOOK_AUTH=aws-iam: ${sdk.problem}. AWS Lambda has the SDK; elsewhere, install it next to madAuth.`);
    return { awsIam: sdk.signer };
  }
  if (auth) throw new ConfigError(`WEBHOOK_AUTH must be aws-iam, or not set to sign the calls with WEBHOOK_SECRET, but is "${auth}".`);
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
  return { secret };
}

/** Whether `host` is `domain` or one of its subdomains, as WebAuthn requires of a page and its passkeys' domain. */
export function isWithin(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}
