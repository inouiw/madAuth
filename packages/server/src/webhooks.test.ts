import { describe, expect, it } from 'vitest';
import { createWebhookClient, generateWebhookSecret, signWebhook, verifyWebhook } from './webhooks.js';

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
  const settings = { url: 'https://hooks.example.com/x', secret: generateWebhookSecret(), events: null };

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

    const result = await client.call('signup.before', { email: 'a@example.com' }, 1000);

    expect(result).toEqual({ ok: true, body: { allow: false } });
    expect(JSON.parse(received!.body)).toEqual({ type: 'signup.before', data: { email: 'a@example.com' } });
    expect(verifyWebhook(settings.secret, received!.headers, received!.body)).toBe(true);
  });

  it('reports error statuses, network errors and timeouts', async () => {
    const answer = (status: number) => (async () => new Response('', { status })) as typeof fetch;
    expect(await createWebhookClient(settings, answer(500)).call('email.verify', {}, 1000)).toEqual({ ok: false, reason: 'HTTP 500' });

    const offline = (async () => {
      throw new TypeError('fetch failed');
    }) as typeof fetch;
    expect(await createWebhookClient(settings, offline).call('email.verify', {}, 1000)).toEqual({ ok: false, reason: 'fetch failed' });

    const slow = ((_url: string, init: RequestInit) =>
      new Promise((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason)))) as typeof fetch;
    expect(await createWebhookClient(settings, slow).call('email.verify', {}, 20)).toEqual({ ok: false, reason: 'no answer within 20 ms' });
  });

  it('K6: sends only the selected events, but always the e-mails', async () => {
    const sent: string[] = [];
    const client = createWebhookClient({ ...settings, events: new Set(['email.verified']) }, (async (_url: string, init: RequestInit) => {
      sent.push(JSON.parse(String(init.body)).type);
      return new Response(null, { status: 204 });
    }) as typeof fetch);

    for (const type of ['email.verify', 'email.reset', 'email.already_registered', 'email.verified', 'user.created', 'signup.before'] as const) {
      await client.call(type, {}, 1000);
    }

    expect(sent).toEqual(['email.verify', 'email.reset', 'email.already_registered', 'email.verified']);
  });
});
