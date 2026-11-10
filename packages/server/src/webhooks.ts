// Webhooks: how madAuth asks your code to send e-mails, decide on sign-ups and learn about events.
// Calls are signed in the Standard Webhooks format (https://www.standardwebhooks.com/): `v1a` with the key service's
// Ed25519 webhook key, whose public keys receivers fetch from /.well-known/webhook-keys.json, and `v1` with
// WEBHOOK_SECRET, which madAuth and the receiver share; or with AWS IAM (aws-iam.ts).
import { createHmac, createPublicKey, randomBytes, randomUUID, timingSafeEqual, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import type { WebhookSigner } from './aws-iam.js';

/**
 * Every `type` madAuth sends: `email.send_*` and `sms.send_*` hand over a message to send, `user.signing_up`
 * asks whether someone may sign up, and the other `user.*` types tell what happened.
 */
export const WEBHOOK_TYPES = [
  'email.send_verification',
  'email.send_password_reset',
  'email.send_signin_link',
  'email.send_already_registered',
  'email.send_password_reset_no_password',
  'sms.send_code',
  'user.signing_up',
  'user.signed_up',
  'user.email_verified',
  'user.password_reset',
  'user.password_changed',
  'user.signed_in',
  'user.deleted',
  'user.claims_changed',
  'user.second_factor_enabled',
  'user.second_factor_disabled',
  'user.recovery_code_used',
  'user.method_added',
  'user.method_removed',
  'user.sign_in_reset',
  'user.api_key_created',
  'user.api_key_revoked',
  'provider.added',
  'provider.changed',
  'provider.removed',
] as const;

/** The calls that hand over an e-mail (as opposed to events and checks). */
export const EMAIL_TYPES = ['email.send_verification', 'email.send_password_reset', 'email.send_signin_link', 'email.send_already_registered', 'email.send_password_reset_no_password'] as const satisfies readonly WebhookType[];

/** The calls that hand over an SMS: `sms.send_code`, the code a user confirms their number or signs in with. */
export const SMS_TYPES = ['sms.send_code'] as const satisfies readonly WebhookType[];

export type WebhookType = (typeof WEBHOOK_TYPES)[number];

/** How long madAuth waits for the webhook to accept an e-mail or to decide on a sign-up. */
export const WEBHOOK_TIMEOUT_MS = 10_000;

const MAX_LOCALE_LENGTH = 35;

/** The user's locale as a request sent it, for the webhook; undefined if it is missing or too long to be one. */
export function localeOf(value: unknown): string | undefined {
  return typeof value === 'string' && value.length <= MAX_LOCALE_LENGTH ? value : undefined;
}

/** The e-mails that e-mail & password sign-in can't work without: WEBHOOK_EVENTS must contain them. */
export const REQUIRED_EMAIL_TYPES = ['email.send_verification', 'email.send_password_reset'] as const satisfies readonly WebhookType[];

const SECRET_PREFIX = 'whsec_';
/** Where the webhook receiver for development is, which prints the e-mails instead of sending them. */
export const DEV_WEBHOOK_RECEIVER_URL = 'https://github.com/inouiw/madAuth-webhooks/tree/main/dev-receiver';

/** How old a call may be before receivers reject it, so a captured call can't be replayed. */
export const WEBHOOK_TOLERANCE_SECONDS = 5 * 60;

/** Where madAuth publishes the public keys of the `v1a` signatures, under its MADAUTH_ISSUER. */
export const WEBHOOK_KEYS_PATH = '/.well-known/webhook-keys.json';

/** A new secret for WEBHOOK_SECRET: `whsec_` and 32 random bytes in base64. */
export function generateWebhookSecret(): string {
  return `${SECRET_PREFIX}${randomBytes(32).toString('base64')}`;
}

/** Why a WEBHOOK_SECRET is not usable, or null. */
export function checkWebhookSecret(secret: string): string | null {
  if (!secret.startsWith(SECRET_PREFIX)) return `must start with "${SECRET_PREFIX}"`;
  const key = Buffer.from(secret.slice(SECRET_PREFIX.length), 'base64');
  if (key.length < 24 || key.length > 64) return 'must contain 24 to 64 bytes in base64';
  return null;
}

function hmac(secret: string, content: string): string {
  const key = Buffer.from(secret.slice(SECRET_PREFIX.length), 'base64');
  return createHmac('sha256', key).update(content).digest('base64');
}

/** The `webhook-signature` header value for a call: `v1,<base64 HMAC-SHA256 of "id.timestamp.body">`. */
export function signWebhook(secret: string, id: string, timestamp: number, body: string): string {
  return `v1,${hmac(secret, signedContent(id, timestamp, body))}`;
}

/** What a call's signatures are made of, `<id>.<timestamp>.<body>`, for `v1` and `v1a` alike. */
function signedContent(id: string, timestamp: number, body: string): string {
  return `${id}.${timestamp}.${body}`;
}

type HeaderSource = Headers | Record<string, string | string[] | undefined>;

function header(headers: HeaderSource, name: string): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  // Some hosts keep the sender's casing (e.g. `Webhook-Id` in an API Gateway event).
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  const value = key === undefined ? undefined : headers[key];
  return Array.isArray(value) ? value[0] : value;
}

type VerifyOptions = { now?: number; toleranceSeconds?: number };

/** A call's signed content and signatures (`[version, signature]`), if it has them and is at most `toleranceSeconds` old. */
function signedCall(headers: HeaderSource, body: string, options: VerifyOptions): { content: string; signatures: [string, string][] } | null {
  const id = header(headers, 'webhook-id');
  const timestamp = Number(header(headers, 'webhook-timestamp'));
  const signatures = header(headers, 'webhook-signature');
  if (!id || !Number.isInteger(timestamp) || !signatures) return null;
  const now = Math.floor((options.now ?? Date.now()) / 1000);
  if (Math.abs(now - timestamp) > (options.toleranceSeconds ?? WEBHOOK_TOLERANCE_SECONDS)) return null;
  // The header may hold several space-separated signatures: v1a and v1, or two of one while a key is being changed.
  const entries = signatures.split(' ').map((entry): [string, string] => {
    const [version = '', signature = ''] = entry.split(',');
    return [version, signature];
  });
  return { content: signedContent(id, timestamp, body), signatures: entries };
}

/** Whether one of the `v1` signatures is the HMAC of `content` with `secret`. */
function hasV1(secret: string, signatures: [string, string][], content: string): boolean {
  if (checkWebhookSecret(secret)) return false;
  const expected = Buffer.from(hmac(secret, content));
  return signatures.some(([version, signature]) => {
    const actual = Buffer.from(signature);
    return version === 'v1' && actual.length === expected.length && timingSafeEqual(actual, expected);
  });
}

/** Whether one of the `v1a` signatures is an Ed25519 signature of `content` by one of `keys`. */
function hasV1a(keys: KeyObject[], signatures: string[], content: string): boolean {
  const data = Buffer.from(content);
  return signatures.some((signature) => {
    const bytes = Buffer.from(signature, 'base64');
    return bytes.length === 64 && keys.some((key) => cryptoVerify(null, data, key, bytes));
  });
}

/**
 * Checks that a webhook call came from madAuth: a signature matches `body` (the raw request body, as received) and
 * the call is at most five minutes old. For receivers written in JavaScript.
 *
 * With the public keys madAuth publishes (`v1a`, no shared secret), from {@link webhookKeys}. It answers a promise:
 * always await it.
 *
 * ```ts
 * import { verifyWebhook, webhookKeys } from '@madauth/server/webhook';
 * const keys = webhookKeys('https://app.example.com/.well-known/webhook-keys.json'); // once, at start
 * if (!(await verifyWebhook({ keys }, request.headers, rawBody))) return new Response(null, { status: 401 });
 * ```
 *
 * `{ keys, secret }` accepts either signature, e.g. while a receiver moves from `WEBHOOK_SECRET` to `v1a`. With
 * `WEBHOOK_SECRET` alone (`v1`), as a string, it answers at once:
 *
 * ```ts
 * if (!verifyWebhook(process.env.WEBHOOK_SECRET!, request.headers, rawBody)) return new Response(null, { status: 401 });
 * ```
 */
export function verifyWebhook(secret: string, headers: HeaderSource, body: string, options?: VerifyOptions): boolean;
export function verifyWebhook(by: { keys?: WebhookKeys; secret?: string }, headers: HeaderSource, body: string, options?: VerifyOptions): Promise<boolean>;
export function verifyWebhook(by: string | { keys?: WebhookKeys; secret?: string }, headers: HeaderSource, body: string, options: VerifyOptions = {}): boolean | Promise<boolean> {
  const call = signedCall(headers, body, options);
  if (typeof by === 'string') return !!call && hasV1(by, call.signatures, call.content);
  // Not a string and no object, e.g. an unset WEBHOOK_SECRET: false at once. A promise here would be truthy, and the
  // sync form `if (!verifyWebhook(secret, …))` would accept every call.
  if (!by || typeof by !== 'object') return false;
  const check = async (): Promise<boolean> => {
    if (!call) return false;
    if (by.secret !== undefined && hasV1(by.secret, call.signatures, call.content)) return true;
    const v1a = call.signatures.filter(([version]) => version === 'v1a').map(([, signature]) => signature);
    if (!by.keys || !v1a.length) return false;
    const cached = await by.keys.keys();
    if (hasV1a(cached, v1a, call.content)) return true;
    // Maybe signed with a key published since the list was fetched: fetch it again (at most every `cooldownSeconds`).
    const fresh = await by.keys.refresh();
    return fresh !== cached && hasV1a(fresh, v1a, call.content);
  };
  return check();
}

/** The public keys of madAuth's `v1a` signatures, as {@link webhookKeys} fetches and caches them. */
export interface WebhookKeys {
  /** The keys as fetched last; fetched again once they are older than `maxAgeSeconds`. */
  keys(): Promise<KeyObject[]>;
  /** The keys fetched again now, unless they were fetched within `cooldownSeconds`: then the same list as before. */
  refresh(): Promise<KeyObject[]>;
}

/** Hosts that may be called over plain http, e.g. a receiver, or madAuth's keys, on the same machine. */
export const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]', 'host.docker.internal'];

/** An Ed25519 public key from a JWK (`kty` OKP, `crv` Ed25519, `x` 32 bytes in base64url); null for anything else. */
function ed25519Key(jwk: unknown): KeyObject | null {
  const { kty, crv, x } = (jwk && typeof jwk === 'object' ? jwk : {}) as { kty?: unknown; crv?: unknown; x?: unknown };
  if (kty !== 'OKP' || crv !== 'Ed25519' || typeof x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(x)) return null;
  return createPublicKey({ key: { kty, crv, x }, format: 'jwk' });
}

/**
 * The public keys of madAuth's `v1a` signatures from `url`, `<MADAUTH_ISSUER>/.well-known/webhook-keys.json`, for
 * {@link verifyWebhook}. Fetched at the first call, kept for `maxAgeSeconds` (default 600), and fetched again
 * sooner when a call's `v1a` signature matches none of them, at most every `cooldownSeconds` (default 30), since
 * madAuth may have begun to sign with a new key. When a fetch fails, the keys fetched before stay, and `onError` is
 * told (default: `console.error`). The URL must be https, or http on this machine (`localhost`, `127.0.0.1`, `[::1]`,
 * `host.docker.internal`): the keys decide which calls are madAuth's.
 */
export function webhookKeys(
  url: string,
  options: { maxAgeSeconds?: number; cooldownSeconds?: number; fetch?: typeof fetch; onError?: (message: string) => void } = {},
): WebhookKeys {
  const parsed = URL.canParse(url) ? new URL(url) : null;
  if (!parsed || !(parsed.protocol === 'https:' || (parsed.protocol === 'http:' && LOCAL_HOSTS.includes(parsed.hostname)))) {
    throw new Error(`webhookKeys: the URL must be https (http only for localhost), e.g. https://app.example.com${WEBHOOK_KEYS_PATH}, but is "${url}".`);
  }
  const { maxAgeSeconds = 600, cooldownSeconds = 30, fetch: fetchImpl = fetch, onError = (message: string) => console.error(message) } = options;
  let cached: KeyObject[] = [];
  /** When the keys were last fetched, or a fetch last failed, so a failing URL isn't asked on every call. */
  let fetchedAt = -Infinity;
  let fetching: Promise<KeyObject[]> | undefined;

  /** The keys `url` lists now, or why there are none. */
  const load = async (): Promise<KeyObject[] | string> => {
    const response = await fetchImpl(parsed.href, { signal: AbortSignal.timeout(5000) }).catch((e: Error) => e);
    if (response instanceof Error) return response.message;
    if (!response.ok) return `HTTP ${response.status}`;
    const json: unknown = await response.json().catch(() => undefined);
    const list = json && typeof json === 'object' && Array.isArray((json as { keys?: unknown }).keys) ? (json as { keys: unknown[] }).keys : null;
    if (!list) return 'the answer is not {"keys": [...]}';
    return list.map(ed25519Key).filter((key): key is KeyObject => key !== null);
  };
  const fetchKeys = (): Promise<KeyObject[]> => {
    // A key that can't be imported counts as a failed fetch too: verifyWebhook resolves false and never rejects.
    fetching ??= load()
      .catch((e: unknown) => (e instanceof Error ? e.message : String(e)))
      .then((loaded) => {
        if (typeof loaded !== 'string') return (cached = loaded);
        onError(`[madauth] Could not fetch the webhook keys from ${parsed.href}: ${loaded}. ${cached.length ? 'The keys fetched before stay.' : 'No v1a signature can be checked until it works.'}`);
        return cached;
      })
      .finally(() => {
        fetchedAt = Date.now();
        fetching = undefined;
      });
    return fetching;
  };
  const after = (seconds: number) => fetching ?? (Date.now() - fetchedAt >= seconds * 1000 ? fetchKeys() : Promise.resolve(cached));
  return { keys: () => after(maxAgeSeconds), refresh: () => after(cooldownSeconds) };
}

/** Makes the `v1a` signature of a call's content: the key service's Ed25519 webhook key (`KeyService.signWebhook`). */
export type WebhookKeySigner = (content: Uint8Array) => Promise<{ signature: Uint8Array } | { problem: string }>;

/**
 * How the calls are signed: in the Standard Webhooks format, with the key service's webhook key (`v1a`, Ed25519),
 * which receivers check with its public key alone, and with the secret the receiver shares (WEBHOOK_SECRET, `v1`),
 * either or both; or with AWS IAM (WEBHOOK_AUTH=aws-iam): with madAuth's AWS credentials, which AWS checks before the
 * receiver runs. While the secret is being changed, `previousSecret` (WEBHOOK_PREVIOUS_SECRET) signs every call as
 * well, so a receiver that still has it accepts them.
 */
export type WebhookAuth = { ed25519?: WebhookKeySigner; secret?: string; previousSecret?: string } | { awsIam: WebhookSigner };

export type WebhookSettings = {
  url: string;
  /** The types that are sent (WEBHOOK_EVENTS); all others are skipped. */
  events: ReadonlySet<string>;
} & WebhookAuth;

export type WebhookResult = { ok: true; body: unknown } | { ok: false; reason: string };

export interface WebhookClient {
  /** Whether calls of this type are sent at all. */
  wants(type: WebhookType): boolean;
  /** Sends a signed call. Succeeds on a 2xx answer within `timeoutMs`; the answer's JSON body is returned. */
  call(type: WebhookType, data: Record<string, unknown>, timeoutMs: number): Promise<WebhookResult>;
}

export function createWebhookClient(settings: WebhookSettings, fetchImpl: typeof fetch = fetch): WebhookClient {
  const wants = (type: WebhookType) => settings.events.has(type);
  // The secrets that sign each call: the current one, and the previous one while it is set.
  const secrets = 'awsIam' in settings ? [] : [settings.secret, settings.previousSecret].filter((secret): secret is string => !!secret);
  const ed25519 = 'awsIam' in settings ? undefined : settings.ed25519;
  /**
   * Space-separated, as Standard Webhooks allows: `v1a` first, then `v1` with each secret; a receiver that checks any
   * one of them accepts the call. Without its `v1a` signature (e.g. a call too long for KMS), the `v1` ones go alone;
   * with no signature at all, the call isn't sent.
   */
  const signatureOf = async (id: string, timestamp: number, body: string): Promise<{ header: string } | { problem: string }> => {
    const v1 = secrets.map((secret) => signWebhook(secret, id, timestamp, body));
    const v1a = ed25519 ? await ed25519(new TextEncoder().encode(signedContent(id, timestamp, body))) : undefined;
    if (v1a && 'problem' in v1a) {
      if (!v1.length) return { problem: `could not sign the call with the webhook key (v1a): ${v1a.problem}` };
      console.warn(`[madauth] A webhook call goes without its v1a signature, with WEBHOOK_SECRET's (v1) alone: ${v1a.problem}.`);
    }
    const signatures = [...(v1a && 'signature' in v1a ? [`v1a,${Buffer.from(v1a.signature).toString('base64')}`] : []), ...v1];
    return { header: signatures.join(' ') };
  };
  return {
    wants,
    async call(type, data, timeoutMs) {
      if (!wants(type)) return { ok: true, body: undefined };
      const id = `msg_${randomUUID()}`;
      const timestamp = Math.floor(Date.now() / 1000);
      const body = JSON.stringify({ type, data });
      // One time limit for the whole call: with AWS IAM, getting the credentials (e.g. from the instance metadata) counts too.
      const signal = AbortSignal.timeout(timeoutMs);
      // The id and the time also with AWS IAM: the id tells a receiver that two calls are the same.
      const headers = { 'Content-Type': 'application/json', 'webhook-id': id, 'webhook-timestamp': String(timestamp) };
      const signed = await (async () => {
        if ('awsIam' in settings) return settings.awsIam({ url: settings.url, headers, body });
        const signature = await signatureOf(id, timestamp, body);
        return 'problem' in signature ? signature : { headers: { ...headers, 'webhook-signature': signature.header } };
      })();
      if ('problem' in signed) return { ok: false, reason: signed.problem };
      let response: Response;
      try {
        response = await fetchImpl(settings.url, {
          method: 'POST',
          headers: signed.headers,
          body,
          signal,
        });
      } catch (e) {
        const reason = (e as Error).name === 'TimeoutError' ? `no answer within ${timeoutMs} ms` : (e as Error).message;
        return { ok: false, reason };
      }
      const text = await response.text().catch(() => '');
      if (!response.ok) return { ok: false, reason: `HTTP ${response.status}` };
      let parsed: unknown;
      try {
        parsed = text ? JSON.parse(text) : undefined;
      } catch {
        parsed = undefined;
      }
      return { ok: true, body: parsed };
    },
  };
}
