// Every webhook call fits what AWS KMS signs with Ed25519 (MAX_RAW_MESSAGE, 4096 bytes of `<id>.<timestamp>.<body>`),
// so the v1a signature is never missing. Each type's largest possible call, from the limits on what goes in it. When a
// call gets a new field, or a limit changes, change its payload here. See "Webhook signing key" in docs/server.md.
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { MAX_API_KEY_NAME, MAX_API_KEY_SCOPES } from './api-keys.js';
import { MAX_IP_LENGTH, normalizeIp, parseUserAgent } from './device.js';
import { MAX_RAW_MESSAGE } from './aws-kms.js';
import { MAX_CLAIMS_BYTES, parseClaims } from './claims.js';
import { isValidEmail } from './password.js';
import { loadConfig } from './config.js';
import { MAX_PROVIDERS, Providers, parseProviderFields } from './providers.js';
import { MAX_REDIRECT_BYTES } from './routes/helpers.js';
import { METHODS, Settings } from './settings.js';
import { createSqliteAdapter } from './store/sqlite.js';
import { APP_ORIGIN, getNonce, googleIdToken, keyService, passwordApp, post, signingKey, verify } from './test/helpers.js';
import { MAX_NAME_LENGTH, cutName } from './user.js';
import { WEBHOOK_TYPES, type WebhookType } from './webhooks.js';

/** What the signature is made of: `msg_<uuid>.<seconds>.<body>`, the time with room for more digits. */
const signedLength = (type: WebhookType, data: Record<string, unknown>) =>
  Buffer.byteLength(`msg_${randomUUID()}.${'9'.repeat(12)}.${JSON.stringify({ type, data })}`, 'utf8');

// The largest value of each field, as its limit allows it, in the characters that take the most bytes in JSON.
/** An id of madAuth's (`usr_…`, `acc_…`, `key_…`: 26 characters), with room for a store of one's own. */
const ID = 'x'.repeat(64);
/** 254 bytes in UTF-8; quotes, backslashes and control characters (more bytes in JSON) are no part of an address. */
const EMAIL = `${'é'.repeat(121)}@example.com`;
/** 100 characters of 3 bytes each; control characters are removed. */
const NAME = '€'.repeat(MAX_NAME_LENGTH);
/** Claims of exactly 1024 bytes as JSON. */
const CLAIMS = { big: '€'.repeat(338) };
/** A locale as a request sends it: up to 35 characters, which may take 6 bytes each in JSON. */
const LOCALE = '\u0001'.repeat(35);
/** A `redirectTo` of 1024 bytes as a URL, plus the hash with the token. */
const LINK = `https://${'a'.repeat(MAX_REDIRECT_BYTES - 'https://'.length)}#madauth_verify=${'t'.repeat(43)}`;
/** The host of an app in ALLOWED_ORIGINS: at most 253 characters, and a port. */
const SITE = `${'a'.repeat(253)}:65535`;
/** A method: madAuth's own, or a provider's id (32 characters). */
const METHOD = 'm'.repeat(32);
/** Every method a user can have: madAuth's own, and every provider's. */
const ALL_METHODS = [...METHODS, ...Array.from({ length: MAX_PROVIDERS }, (_, i) => `p${i}`.padEnd(32, 'x'))];
const TIME = 9_999_999_999_999;
/** The user in an event: never the session's `amr`, never the provider's `picture`. */
const USER = { id: ID, email: EMAIL, name: NAME, claims: CLAIMS };
/** A name of an API key or a provider: up to 64 characters, only trimmed, so control characters take 6 bytes each. */
const ADMIN_NAME = '\u0001'.repeat(MAX_API_KEY_NAME);
const BY_API_KEY = { id: ID, name: ADMIN_NAME };
const MAIL = { to: EMAIL, link: LINK, code: '123456', expiresAt: TIME, site: SITE, locale: LOCALE, user: { id: ID, name: NAME } };
const ACCOUNT_MAIL = { to: EMAIL, link: LINK.split('#')[0], site: SITE, locale: LOCALE, user: { id: ID, name: NAME }, methods: ALL_METHODS };
/** An OpenID Connect provider (the largest kind): client ID of 255 printable characters, issuer of 256, scopes of 512 in all. */
const PROVIDER = {
  id: METHOD,
  kind: 'oidc',
  name: ADMIN_NAME,
  clientId: '"'.repeat(255),
  hasClientSecret: true,
  callbackUrl: `https://${SITE}/auth/providers/${METHOD}/callback`,
  createdAt: TIME,
  updatedAt: TIME,
  issuer: `https://${'"'.repeat(248)}`,
  scopes: Array.from({ length: 20 }, (_, i) => `s${i}`.padEnd(24, 's')),
  trustEmail: true,
  preset: 'linkedin',
};
const BY_ADMIN = { by: EMAIL, byApiKey: BY_API_KEY };
/** A session as `user.signed_in` names it: browser and system from madAuth's short lists, an IPv6 address of 45 characters. */
const SESSION = { id: ID, browser: 'Samsung Internet', os: 'ChromeOS', ip: `ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255` };

const LARGEST: Record<WebhookType, Record<string, unknown>> = {
  'email.send_verification': MAIL,
  'email.send_password_reset': MAIL,
  'email.send_signin_link': MAIL,
  'email.send_already_registered': ACCOUNT_MAIL,
  'email.send_password_reset_no_password': ACCOUNT_MAIL,
  'sms.send_code': { to: `+${'9'.repeat(15)}`, code: '123456', purpose: 'approve', expiresAt: TIME, site: SITE, locale: LOCALE, user: { id: ID, name: NAME } },
  'user.signing_up': { email: EMAIL, name: NAME, locale: LOCALE, method: METHOD },
  'user.signed_up': { user: USER, method: METHOD },
  'user.email_verified': { user: USER, method: METHOD, via: 'link' },
  'user.password_reset': { user: USER },
  'user.password_changed': { user: USER },
  'user.signed_in': { user: USER, method: METHOD, secondFactor: 'recovery_code', session: SESSION },
  'user.session_ended': { user: USER, session: { id: ID }, reason: 'signed_out', ...BY_ADMIN },
  'user.deleted': { user: USER, ...BY_ADMIN },
  // The claims twice: the largest call of all.
  'user.claims_changed': { user: USER, claims: CLAIMS, ...BY_ADMIN },
  'user.second_factor_enabled': { user: USER, method: 'authenticator', phone: `+${'9'.repeat(15)}` },
  'user.second_factor_disabled': { user: USER, method: 'authenticator' },
  'user.recovery_code_used': { user: USER, remaining: 10 },
  'user.method_added': { user: USER, method: METHOD, email: EMAIL, passkey: { id: ID, name: '€'.repeat(64) } },
  'user.method_removed': { user: USER, method: METHOD, passkey: { id: ID, name: '€'.repeat(64) } },
  'user.sign_in_reset': { user: USER, ...BY_ADMIN },
  'user.api_key_created': {
    user: USER,
    apiKey: { id: ID, name: ADMIN_NAME, scopes: Array.from({ length: MAX_API_KEY_SCOPES }, (_, i) => `s${i}`.padEnd(64, 'x')), createdAt: TIME, expiresAt: TIME, lastUsedAt: TIME },
  },
  'user.api_key_revoked': { user: USER, apiKey: { id: ID, name: ADMIN_NAME }, by: EMAIL },
  'provider.added': { provider: PROVIDER, by: EMAIL, bySetupToken: true },
  'provider.changed': { provider: PROVIDER, by: EMAIL, bySetupToken: true },
  'provider.removed': { provider: PROVIDER, by: EMAIL, bySetupToken: true },
};

describe('the size of the webhook calls', () => {
  it('W1: the largest values are what the limits allow', () => {
    expect(Buffer.byteLength(EMAIL, 'utf8')).toBe(254);
    expect(isValidEmail(EMAIL)).toBe(true);
    expect(isValidEmail(`${'é'.repeat(122)}@example.com`)).toBe(false);
    expect(isValidEmail('"quoted"@example.com')).toBe(false);
    expect(Buffer.byteLength(JSON.stringify(parseClaims(CLAIMS)), 'utf8')).toBe(MAX_CLAIMS_BYTES);
    expect(cutName('€'.repeat(500))).toBe(NAME);
    expect(cutName(`\u0001${'a'.repeat(3)}\u001f`)).toBe('aaa');
    expect(LINK.split('#')[0]).toHaveLength(MAX_REDIRECT_BYTES);
    expect(PROVIDER.issuer).toHaveLength(256);
    expect(PROVIDER.scopes.join(' ').length).toBeLessThanOrEqual(512);
    expect(SESSION.ip).toHaveLength(MAX_IP_LENGTH);
    expect(normalizeIp(SESSION.ip)).toBe(SESSION.ip);
    expect(normalizeIp(`fe80::1%${'e'.repeat(60)}`)).toBeNull();
    // The longest names on madAuth's lists of browsers and systems.
    expect(parseUserAgent('Mozilla/5.0 (X11; CrOS x86_64) SamsungBrowser/1.0')).toEqual({ browser: 'Samsung Internet', os: 'ChromeOS' });
  });

  it.each(WEBHOOK_TYPES)('W2: the largest %s call fits what AWS KMS signs with Ed25519, with room to spare', (type) => {
    const length = signedLength(type, LARGEST[type]);
    // A margin of 5%, for a field added later without a look at this test.
    expect(length).toBeLessThan(MAX_RAW_MESSAGE * 0.95);
  });
});

describe('the limits that keep the webhook calls small', () => {
  it('W3: a redirectTo longer than 1024 bytes as a URL is refused', async () => {
    const { app } = passwordApp();
    const signUp = (redirectTo: string) => post(app, '/auth/password/signup', { email: 'grace@example.com', password: 'correct horse battery', redirectTo });
    const long = await signUp(`${APP_ORIGIN}/${'a'.repeat(MAX_REDIRECT_BYTES)}`);
    expect(long.status).toBe(400);
    expect(await long.json()).toEqual({ error: 'invalid_options', message: 'redirectTo must be at most 1024 bytes long as a URL: the e-mail links are made of it.' });
    // Measured as madAuth writes the URL: "é" is "%C3%A9".
    expect((await signUp(`${APP_ORIGIN}/${'é'.repeat(200)}`)).status).toBe(400);
    expect((await signUp(`${APP_ORIGIN}/${'a'.repeat(MAX_REDIRECT_BYTES - APP_ORIGIN.length - 1)}`)).status).toBe(202);
  });

  it("W4: a provider's name is cut to 100 characters, its picture never goes to the webhook, and an address over 254 bytes doesn't sign in", async () => {
    const { app, hook, store } = passwordApp();
    const first = await getNonce(app);
    await verify(app, await googleIdToken({ nonce: first.nonce, name: `  ${'N'.repeat(150)}\u0007 ` }), first.cookie);
    const stored = (await store.findMany('user', {}))[0]!;
    expect(stored.name).toBe('N'.repeat(100));
    const signedIn = hook.calls.find((call) => call.type === 'user.signed_in')!;
    expect(signedIn.data.user).toEqual({ id: stored.id, email: 'ada@example.com', name: 'N'.repeat(100) });

    const second = await getNonce(app);
    const tooLong = await verify(app, await googleIdToken({ nonce: second.nonce, sub: '2002', email: `${'a'.repeat(243)}@example.com` }), second.cookie);
    expect(tooLong.status).toBe(403);
    expect(await tooLong.json()).toMatchObject({ error: 'email_unverified' });
  });

  it('W5: a key has at most 20 scopes; providers at most 20, with an issuer of 256 and scopes and bundle ids of 512 characters', async () => {
    expect(MAX_API_KEY_SCOPES).toBe(20);
    expect(parseProviderFields('oidc', { name: 'X', clientId: 'c', clientSecret: 's', issuer: `https://${'a'.repeat(241)}.example`, scopes: 'a' }, true)).toMatchObject({ error: 'invalid_provider' });
    expect(parseProviderFields('oidc', { name: 'X', clientId: 'c', clientSecret: 's', issuer: 'https://gitlab.com', scopes: Array.from({ length: 20 }, (_, i) => `b${i}`.padEnd(30, 'b')).join(' ') }, true)).toMatchObject({
      error: 'invalid_provider',
      message: expect.stringContaining('512 characters in all'),
    });
    expect(parseProviderFields('oidc', { name: 'X', clientId: 'c', clientSecret: 's', issuer: 'https://gitlab.com', scopes: Array.from({ length: 20 }, (_, i) => `b${i}`.padEnd(24, 'b')).join(' ') }, true)).not.toHaveProperty('error');

    const settings = new Settings(createSqliteAdapter(':memory:'));
    const providers = new Providers(settings, keyService);
    for (let i = 0; i < MAX_PROVIDERS; i++) {
      expect(await providers.add('oidc', `p${i}`, { name: `P${i}`, clientId: 'c', issuer: `https://p${i}.example.com` }, null)).toHaveProperty('provider');
    }
    expect(await providers.add('oidc', 'one-more', { name: 'One more', clientId: 'c', issuer: 'https://one-more.example.com' }, null)).toEqual({ error: 'too_many_providers' });
  });

  it('W6: the hosts of MADAUTH_ISSUER and ALLOWED_ORIGINS have at most 253 characters, as a domain name does', async () => {
    const host = `${'a'.repeat(250)}.com`;
    await expect(
      loadConfig({ MADAUTH_ISSUER: `https://${host}`, MADAUTH_KEY_SERVICE: 'local', MADAUTH_SIGNING_KEY: JSON.stringify(signingKey), ALLOWED_ORIGINS: APP_ORIGIN, DATABASE_URL: 'sqlite::memory:' }),
    ).rejects.toThrow(/longer than 253 characters/);
  });
});
