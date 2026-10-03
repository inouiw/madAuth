// Webhooks: how madAuth asks your code to send e-mails, decide on sign-ups and learn about events.
// Calls are signed in the Standard Webhooks format (https://www.standardwebhooks.com/).
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

/** Every `type` madAuth sends. */
export const WEBHOOK_TYPES = [
  'email.verify',
  'email.reset',
  'email.already_registered',
  'signup.before',
  'user.created',
  'email.verified',
  'password.reset',
  'user.signed_in',
  'user.deleted',
] as const;

export type WebhookType = (typeof WEBHOOK_TYPES)[number];

/** The e-mails that e-mail & password sign-in can't work without: WEBHOOK_EVENTS must contain them. */
export const REQUIRED_EMAIL_TYPES = ['email.verify', 'email.reset'] as const satisfies readonly WebhookType[];

const SECRET_PREFIX = 'whsec_';
/** How old a call may be before receivers reject it, so a captured call can't be replayed. */
export const WEBHOOK_TOLERANCE_SECONDS = 5 * 60;

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
  return `v1,${hmac(secret, `${id}.${timestamp}.${body}`)}`;
}

type HeaderSource = Headers | Record<string, string | string[] | undefined>;

function header(headers: HeaderSource, name: string): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  // Some hosts keep the sender's casing (e.g. `Webhook-Id` in an API Gateway event).
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  const value = key === undefined ? undefined : headers[key];
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Checks that a webhook call came from madAuth: the signature matches `body` (the raw request body, as
 * received) and the call is at most five minutes old. For receivers written in JavaScript:
 *
 * ```ts
 * import { verifyWebhook } from '@madauth/server/webhook';
 * if (!verifyWebhook(process.env.WEBHOOK_SECRET!, request.headers, rawBody)) return new Response(null, { status: 401 });
 * ```
 */
export function verifyWebhook(
  secret: string,
  headers: HeaderSource,
  body: string,
  options: { now?: number; toleranceSeconds?: number } = {},
): boolean {
  const id = header(headers, 'webhook-id');
  const timestamp = Number(header(headers, 'webhook-timestamp'));
  const signatures = header(headers, 'webhook-signature');
  if (!id || !Number.isInteger(timestamp) || !signatures || checkWebhookSecret(secret)) return false;
  const now = Math.floor((options.now ?? Date.now()) / 1000);
  if (Math.abs(now - timestamp) > (options.toleranceSeconds ?? WEBHOOK_TOLERANCE_SECONDS)) return false;
  const expected = Buffer.from(hmac(secret, `${id}.${timestamp}.${body}`));
  // The header may hold several space-separated signatures, e.g. while a secret is being rotated.
  return signatures.split(' ').some((entry) => {
    const [version, signature] = entry.split(',');
    const actual = Buffer.from(signature ?? '');
    return version === 'v1' && actual.length === expected.length && timingSafeEqual(actual, expected);
  });
}

export interface WebhookSettings {
  url: string;
  secret: string;
  /** The types that are sent (WEBHOOK_EVENTS); all others are skipped. */
  events: ReadonlySet<string>;
}

export type WebhookResult = { ok: true; body: unknown } | { ok: false; reason: string };

export interface WebhookClient {
  /** Whether calls of this type are sent at all. */
  wants(type: WebhookType): boolean;
  /** Sends a signed call. Succeeds on a 2xx answer within `timeoutMs`; the answer's JSON body is returned. */
  call(type: WebhookType, data: Record<string, unknown>, timeoutMs: number): Promise<WebhookResult>;
}

export function createWebhookClient(settings: WebhookSettings, fetchImpl: typeof fetch = fetch): WebhookClient {
  const wants = (type: WebhookType) => settings.events.has(type);
  return {
    wants,
    async call(type, data, timeoutMs) {
      if (!wants(type)) return { ok: true, body: undefined };
      const id = `msg_${randomUUID()}`;
      const timestamp = Math.floor(Date.now() / 1000);
      const body = JSON.stringify({ type, data });
      let response: Response;
      try {
        response = await fetchImpl(settings.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'webhook-id': id,
            'webhook-timestamp': String(timestamp),
            'webhook-signature': signWebhook(settings.secret, id, timestamp, body),
          },
          body,
          signal: AbortSignal.timeout(timeoutMs),
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
