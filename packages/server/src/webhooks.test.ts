import { generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { SignatureV4 } from '@smithy/signature-v4';
import { describe, expect, it, vi } from 'vitest';
import { Sha256, createAwsIamSigner } from './aws-iam.js';
import { WEBHOOK_TYPES, createWebhookClient, generateWebhookSecret, signWebhook, verifyWebhook, webhookKeys, type WebhookKeySigner } from './webhooks.js';

// The example from the Standard Webhooks specification, so other implementations can verify our calls.
// It is a public example key; it is split so secret scanners don't mistake it for a real (e.g. Stripe) secret.
const spec = {
  secret: ['whsec', 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'].join('_'),
  id: 'msg_p5jXN8AQM9LWM0D4loKWxJek',
  timestamp: 1614265330,
  body: '{"test": 2432232314}',
  signature: 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=',
};
const specHeaders = (overrides: Record<string, string> = {}) => ({
  'webhook-id': spec.id,
  'webhook-timestamp': String(spec.timestamp),
  'webhook-signature': spec.signature,
  ...overrides,
});
const atSpecTime = { now: spec.timestamp * 1000 };

describe('webhook signatures', () => {
  it('K1: signs like the Standard Webhooks reference', () => {
    expect(signWebhook(spec.secret, spec.id, spec.timestamp, spec.body)).toBe(spec.signature);
  });

  it('K1: verifies a valid call and rejects changed, foreign or old ones', () => {
    expect(verifyWebhook(spec.secret, specHeaders(), spec.body, atSpecTime)).toBe(true);
    expect(verifyWebhook(spec.secret, new Headers(specHeaders()), spec.body, atSpecTime)).toBe(true);
    // Several signatures, e.g. while the secret is being rotated.
    expect(verifyWebhook(spec.secret, specHeaders({ 'webhook-signature': `v1,AAAA ${spec.signature}` }), spec.body, atSpecTime)).toBe(true);

    expect(verifyWebhook(spec.secret, specHeaders(), '{"test": 1}', atSpecTime)).toBe(false);
    expect(verifyWebhook(generateWebhookSecret(), specHeaders(), spec.body, atSpecTime)).toBe(false);
    expect(verifyWebhook(spec.secret, specHeaders(), spec.body, { now: (spec.timestamp + 301) * 1000 })).toBe(false);
    expect(verifyWebhook(spec.secret, specHeaders({ 'webhook-signature': 'v2,abc' }), spec.body, atSpecTime)).toBe(false);
    expect(verifyWebhook(spec.secret, {}, spec.body, atSpecTime)).toBe(false);
  });
});

describe('webhook client', () => {
  const settings = { url: 'https://hooks.example.com/x', secret: generateWebhookSecret(), events: new Set<string>(WEBHOOK_TYPES) };

  it('finds the headers of a plain object whatever their casing', async () => {
    const now = Date.now();
    const timestamp = Math.floor(now / 1000);
    const headers = {
      'Webhook-Id': 'msg_1',
      'Webhook-Timestamp': String(timestamp),
      'Webhook-Signature': signWebhook(settings.secret, 'msg_1', timestamp, '{}'),
    };

    expect(verifyWebhook(settings.secret, headers, '{}', { now })).toBe(true);
  });

  it('sends a signed JSON call and returns the answer', async () => {
    let received: { headers: Headers; body: string } | undefined;
    const client = createWebhookClient(settings, (async (_url: string, init: RequestInit) => {
      received = { headers: new Headers(init.headers), body: String(init.body) };
      return new Response('{"allow":false}', { status: 200 });
    }) as typeof fetch);

    const result = await client.call('user.signing_up', { email: 'a@example.com' }, 1000);

    expect(result).toEqual({ ok: true, body: { allow: false } });
    expect(JSON.parse(received!.body)).toEqual({ type: 'user.signing_up', data: { email: 'a@example.com' } });
    expect(verifyWebhook(settings.secret, received!.headers, received!.body)).toBe(true);
  });

  it('signs every call with the previous secret too while it is set: a receiver with either one accepts it', async () => {
    const previousSecret = generateWebhookSecret();
    let received: { headers: Headers; body: string } | undefined;
    const client = createWebhookClient({ ...settings, previousSecret }, (async (_url: string, init: RequestInit) => {
      received = { headers: new Headers(init.headers), body: String(init.body) };
      return new Response(null, { status: 204 });
    }) as typeof fetch);

    await client.call('user.signed_in', {}, 1000);

    expect(received!.headers.get('webhook-signature')).toMatch(/^v1,\S+ v1,\S+$/);
    expect(verifyWebhook(settings.secret, received!.headers, received!.body)).toBe(true);
    expect(verifyWebhook(previousSecret, received!.headers, received!.body)).toBe(true);
    expect(verifyWebhook(generateWebhookSecret(), received!.headers, received!.body)).toBe(false);
  });

  it('reports error statuses, network errors and timeouts', async () => {
    const answer = (status: number) => (async () => new Response('', { status })) as typeof fetch;
    expect(await createWebhookClient(settings, answer(500)).call('email.send_verification', {}, 1000)).toEqual({ ok: false, reason: 'HTTP 500' });

    const offline = (async () => {
      throw new TypeError('fetch failed');
    }) as typeof fetch;
    expect(await createWebhookClient(settings, offline).call('email.send_verification', {}, 1000)).toEqual({ ok: false, reason: 'fetch failed' });

    const slow = ((_url: string, init: RequestInit) =>
      new Promise((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason)))) as typeof fetch;
    expect(await createWebhookClient(settings, slow).call('email.send_verification', {}, 20)).toEqual({ ok: false, reason: 'no answer within 20 ms' });
  });

  it('K6: sends only the selected types, e-mails included', async () => {
    const sent: string[] = [];
    const client = createWebhookClient({ ...settings, events: new Set(['email.send_verification', 'user.email_verified']) }, (async (_url: string, init: RequestInit) => {
      sent.push(JSON.parse(String(init.body)).type);
      return new Response(null, { status: 204 });
    }) as typeof fetch);

    for (const type of ['email.send_verification', 'email.send_password_reset', 'email.send_already_registered', 'user.email_verified', 'user.signed_up', 'user.signing_up'] as const) {
      await client.call(type, {}, 1000);
    }

    expect(sent).toEqual(['email.send_verification', 'user.email_verified']);
    expect(client.wants('email.send_password_reset')).toBe(false);
  });
});

describe('webhook client with AWS IAM (WEBHOOK_AUTH=aws-iam)', () => {
  const url = 'https://abcdefghijklmnopqrstuvwxyz012345.lambda-url.eu-central-1.on.aws/';
  // A Lambda function's role: temporary credentials with a session token.
  const credentials = { accessKeyId: 'ASIAEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', sessionToken: 'session-token' };
  const now = new Date('2026-10-17T12:00:00Z');
  const sigv4 = () => new SignatureV4({ service: 'lambda', region: 'eu-central-1', credentials, sha256: Sha256 });

  it('signs the call it sends with SigV4, as AWS checks it at the Function URL', async () => {
    let received: { url: string; headers: Headers; body: string } | undefined;
    const client = createWebhookClient({ url, events: new Set(WEBHOOK_TYPES), awsIam: createAwsIamSigner(sigv4()) }, (async (to: string, init: RequestInit) => {
      received = { url: to, headers: new Headers(init.headers), body: String(init.body) };
      return new Response('{"allow":false}', { status: 200 });
    }) as typeof fetch);

    vi.useFakeTimers({ toFake: ['Date'], now });
    const result = await client.call('user.signing_up', { email: 'a@example.com' }, 1000).finally(() => vi.useRealTimers());

    expect(result).toEqual({ ok: true, body: { allow: false } });
    const { headers, body } = received!;
    expect(JSON.parse(body)).toEqual({ type: 'user.signing_up', data: { email: 'a@example.com' } });
    expect(headers.get('x-amz-date')).toBe('20261017T120000Z');
    expect(headers.get('x-amz-security-token')).toBe('session-token');
    expect(headers.get('authorization')).toMatch(
      /^AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE\/20261017\/eu-central-1\/lambda\/aws4_request, SignedHeaders=content-type;host;webhook-id;webhook-timestamp;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$/,
    );
    expect(headers.get('webhook-id')).toMatch(/^msg_/);
    expect(headers.get('webhook-signature')).toBeNull();

    // What AWS does: sign the request as it arrived (its host from the URL, as fetch sends it) and compare.
    const added = ['authorization', 'x-amz-date', 'x-amz-security-token', 'x-amz-content-sha256'];
    const unsigned = Object.fromEntries([...headers].filter(([name]) => !added.includes(name)));
    const target = new URL(received!.url);
    const expected = (sent: string) =>
      sigv4().sign(
        { method: 'POST', protocol: target.protocol, hostname: target.hostname, path: target.pathname, query: {}, headers: { ...unsigned, host: target.host }, body: sent },
        { signingDate: now },
      );
    expect(headers.get('authorization')).toBe((await expected(body)).headers.authorization);
    expect(headers.get('authorization')).not.toBe((await expected(body.replace('a@example.com', 'b@example.com'))).headers.authorization);
  });

  it('counts the signing, e.g. getting the credentials, into the time limit', async () => {
    // As fetch does: an aborted signal fails at once.
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      if (init.signal?.aborted) throw init.signal.reason;
      return new Response(null, { status: 204 });
    }) as typeof fetch;
    const slowSigner = async ({ headers }: { headers: Record<string, string> }) => {
      await new Promise((resolve) => setTimeout(resolve, 50));
      return { headers };
    };
    const client = createWebhookClient({ url, events: new Set(WEBHOOK_TYPES), awsIam: slowSigner }, fetchImpl);

    expect(await client.call('user.signing_up', {}, 20)).toEqual({ ok: false, reason: 'no answer within 20 ms' });
    expect(await client.call('user.signing_up', {}, 1000)).toEqual({ ok: true, body: undefined });
  });

  it('sends nothing when it can not sign, and says why', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    const client = createWebhookClient({ url, events: new Set(WEBHOOK_TYPES), awsIam: async () => ({ problem: 'could not sign the call with AWS IAM: no credentials' }) }, fetchImpl);

    expect(await client.call('email.send_verification', {}, 1000)).toEqual({ ok: false, reason: 'could not sign the call with AWS IAM: no credentials' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('asymmetric signatures (v1a, Ed25519)', () => {
  const KEYS_URL = 'https://app.example.com/.well-known/webhook-keys.json';
  const pair = () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    return { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), alg: 'Ed25519', use: 'sig', kid: randomUUID() } };
  };
  const signer =
    (privateKey: KeyObject): WebhookKeySigner =>
    async (content) => ({ signature: new Uint8Array(sign(null, content, privateKey)) });
  /** A madAuth that serves `published()` at KEYS_URL, counting the fetches. */
  const served = (published: () => object[]) => {
    const fetches = { count: 0 };
    const fetchImpl = (async (url: string) => {
      fetches.count++;
      return url === KEYS_URL ? Response.json({ keys: published() }) : new Response(null, { status: 404 });
    }) as typeof fetch;
    return { fetches, fetchImpl };
  };
  /** Sends one call with `auth` and returns its headers and body as the receiver gets them. */
  async function sent(auth: Parameters<typeof createWebhookClient>[0]) {
    let received: { headers: Headers; body: string } | undefined;
    const result = await createWebhookClient(auth, (async (_url: string, init: RequestInit) => {
      received = { headers: new Headers(init.headers), body: String(init.body) };
      return new Response(null, { status: 204 });
    }) as typeof fetch).call('user.signed_in', { user: { id: 'usr_1' } }, 1000);
    return { result, ...received! };
  }
  const base = { url: 'https://hooks.example.com/x', events: new Set<string>(WEBHOOK_TYPES) };

  it('V1: signs with the webhook key alone, and a receiver with the published key accepts it; no shared secret', async () => {
    const key = pair();
    const { fetchImpl } = served(() => [key.jwk]);
    const { headers, body } = await sent({ ...base, ed25519: signer(key.privateKey) });

    expect(headers.get('webhook-signature')).toMatch(/^v1a,[A-Za-z0-9+/]{86}==$/);
    const keys = webhookKeys(KEYS_URL, { fetch: fetchImpl });
    expect(await verifyWebhook({ keys }, headers, body)).toBe(true);
    expect(await verifyWebhook({ keys }, headers, body.replace('usr_1', 'usr_2'))).toBe(false);
    // A key of someone else's: rejected.
    expect(await verifyWebhook({ keys: webhookKeys(KEYS_URL, { fetch: served(() => [pair().jwk]).fetchImpl }) }, headers, body)).toBe(false);
    // Old calls are rejected as with v1.
    expect(await verifyWebhook({ keys }, headers, body, { now: Date.now() + 301_000 })).toBe(false);
    // The string form checks v1 only: no secret matches a v1a signature.
    expect(verifyWebhook(generateWebhookSecret(), headers, body)).toBe(false);
    // An unset secret (process.env.WEBHOOK_SECRET!) is false at once, not a promise that a sync check would take as true.
    expect(verifyWebhook(undefined as unknown as string, headers, body)).toBe(false);
  });

  it('V2: with WEBHOOK_SECRET too, both signatures in one header, v1a first; a receiver of either kind accepts it', async () => {
    const key = pair();
    const secret = generateWebhookSecret();
    const { headers, body } = await sent({ ...base, ed25519: signer(key.privateKey), secret });

    expect(headers.get('webhook-signature')).toMatch(/^v1a,\S+ v1,\S+$/);
    expect(verifyWebhook(secret, headers, body)).toBe(true);
    const keys = webhookKeys(KEYS_URL, { fetch: served(() => [key.jwk]).fetchImpl });
    expect(await verifyWebhook({ keys }, headers, body)).toBe(true);
    expect(await verifyWebhook({ keys, secret }, headers, body)).toBe(true);
    // A receiver moving to v1a accepts a call signed with the secret alone too.
    const v1Only = await sent({ ...base, secret });
    expect(await verifyWebhook({ keys, secret }, v1Only.headers, v1Only.body)).toBe(true);
    expect(await verifyWebhook({ keys }, v1Only.headers, v1Only.body)).toBe(false);
  });

  it('V3: without its v1a signature (e.g. too long for KMS) a call goes with v1 alone; with no signature at all it is not sent', async () => {
    const failing: WebhookKeySigner = async () => ({ problem: 'too long' });
    const secret = generateWebhookSecret();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const withSecret = await sent({ ...base, ed25519: failing, secret });
    expect(withSecret.headers.get('webhook-signature')).toMatch(/^v1,\S+$/);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('without its v1a signature'));
    warn.mockRestore();

    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    expect(await createWebhookClient({ ...base, ed25519: failing }, fetchImpl).call('user.signed_in', {}, 1000)).toEqual({
      ok: false,
      reason: 'could not sign the call with the webhook key (v1a): too long',
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('V4: the receiver caches the keys, and fetches them again for a key it does not know, at most every 30 seconds', async () => {
    const first = pair();
    const second = pair();
    let published = [first.jwk];
    const { fetches, fetchImpl } = served(() => published);
    const keys = webhookKeys(KEYS_URL, { fetch: fetchImpl });
    const start = Date.now();
    const byFirst = await sent({ ...base, ed25519: signer(first.privateKey) });
    const bySecond = await sent({ ...base, ed25519: signer(second.privateKey) });
    // The calls stay within their five minutes while the clock moves on.
    const at = (ms: number) => ({ now: start + ms });

    vi.useFakeTimers({ toFake: ['Date'], now: start });
    try {
      expect(await verifyWebhook({ keys }, byFirst.headers, byFirst.body, at(0))).toBe(true);
      expect(await verifyWebhook({ keys }, byFirst.headers, byFirst.body, at(0))).toBe(true);
      expect(fetches.count).toBe(1);
      // madAuth signs with a new key: an unknown signature fetches the list again, once within the cooldown.
      published = [second.jwk, first.jwk];
      vi.setSystemTime(start + 31_000);
      expect(await verifyWebhook({ keys }, bySecond.headers, bySecond.body, at(31_000))).toBe(true);
      expect(fetches.count).toBe(2);
      const forged = new Headers(bySecond.headers);
      forged.set('webhook-signature', `v1a,${Buffer.alloc(64).toString('base64')}`);
      expect(await verifyWebhook({ keys }, forged, bySecond.body, at(31_000))).toBe(false);
      expect(await verifyWebhook({ keys }, forged, bySecond.body, at(31_000))).toBe(false);
      expect(fetches.count).toBe(2);
      // A call without any v1a signature fetches nothing.
      forged.set('webhook-signature', 'v1,AAAA');
      vi.setSystemTime(start + 62_000);
      expect(await verifyWebhook({ keys }, forged, bySecond.body, at(62_000))).toBe(false);
      expect(fetches.count).toBe(2);
      // After ten minutes, the list is fetched again anyway.
      vi.setSystemTime(start + 31_000 + 600_000);
      await keys.keys();
      expect(fetches.count).toBe(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it('V5: a failed fetch keeps the keys fetched before and says so; the URL must be https or on this machine', async () => {
    const key = pair();
    let up = true;
    const errors: string[] = [];
    const fetchImpl = (async () =>
      up ? Response.json({ keys: [key.jwk, { kty: 'EC' }, { kty: 'OKP', crv: 'Ed25519', x: 'short' }] }) : new Response(null, { status: 503 })) as typeof fetch;
    const keys = webhookKeys(KEYS_URL, { fetch: fetchImpl, cooldownSeconds: 0, onError: (message) => errors.push(message) });
    // What isn't an Ed25519 key is left out.
    expect(await keys.keys()).toHaveLength(1);
    up = false;
    expect(await keys.refresh()).toHaveLength(1);
    expect(errors).toEqual([`[madauth] Could not fetch the webhook keys from ${KEYS_URL}: HTTP 503. The keys fetched before stay.`]);

    // Whatever goes wrong while fetching, verifyWebhook resolves false and never rejects.
    const broken = webhookKeys(KEYS_URL, {
      fetch: (() => {
        throw new Error('boom');
      }) as typeof fetch,
      onError: (message) => errors.push(message),
    });
    const signed = await sent({ ...base, ed25519: signer(key.privateKey) });
    await expect(verifyWebhook({ keys: broken }, signed.headers, signed.body)).resolves.toBe(false);
    expect(errors.at(-1)).toContain('boom');

    expect(() => webhookKeys('http://auth.example.com/.well-known/webhook-keys.json')).toThrow(/must be https/);
    expect(() => webhookKeys('not a url')).toThrow(/must be https/);
    expect(() => webhookKeys('http://localhost:8787/.well-known/webhook-keys.json')).not.toThrow();
  });
});
