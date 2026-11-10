// The users' sessions: a record per session, which the user and the admins list and end. An ended session stops at
// its next renewal. See "Sessions" in docs/server.md.
import { createLocalJWKSet, decodeJwt } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { normalizeIp, parseUserAgent } from './device.js';
import { CLEANUP_INTERVAL_MS, Sessions } from './sessions.js';
import { createSqliteAdapter } from './store/sqlite.js';
import { APP_ORIGIN, ISSUER, cookieHeader, cookies, getNonce, googleIdToken, keyService, passwordApp, post, setClaims, signUpVerified, type RecordingWebhook } from './test/helpers.js';
import { signRenewal } from './tokens.js';
import { createSessionVerifier } from './verify.js';

afterEach(() => {
  vi.useRealTimers();
});

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const FIREFOX_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:133.0) Gecko/20100101 Firefox/133.0';
const SAFARI_IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
type App = ReturnType<typeof passwordApp>['app'];

/** Moves the clock forward without touching timers, so scrypt's callbacks still run. */
function advance(ms: number) {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
}

/** A Google sign-in from a browser with this user agent and address (CLIENT_IP_HEADER is x-forwarded-for); its cookies. */
async function signInFrom(app: App, userAgent: string, ip: string, claims: Record<string, unknown> = {}): Promise<string> {
  const { nonce, cookie } = await getNonce(app);
  const res = await app.request('/auth/providers/google/verify', {
    method: 'POST',
    headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json', Cookie: cookie, 'User-Agent': userAgent, 'X-Forwarded-For': `198.51.100.1, ${ip}` },
    body: JSON.stringify({ credential: await googleIdToken({ nonce, ...claims }) }),
  });
  expect(res.status).toBe(200);
  return cookieHeader(res);
}

const list = async (app: App, cookie: string) => app.request('/auth/sessions', { headers: { Cookie: cookie } });
const sessionsOf = async (app: App, cookie: string) => ((await (await list(app, cookie)).json()) as { sessions: { id: string; current: boolean; [key: string]: unknown }[] }).sessions;
const check = (app: App, cookie: string) => app.request('/auth/session', { headers: { Cookie: cookie } });
const renewalOnly = (cookie: string) => cookie.split('; ').find((c) => c.startsWith('madauth_renewal='))!;
const sidOf = (cookie: string, name = 'madauth_session') => decodeJwt(cookie.split('; ').find((c) => c.startsWith(`${name}=`))!.split('=')[1]).sid as string;
const sidOwner = (cookie: string) => decodeJwt(cookie.split('; ').find((c) => c.startsWith('madauth_session='))!.split('=')[1]).sub!;
const ended = (hook: RecordingWebhook) => hook.calls.filter((call) => call.type === 'user.session_ended').map((call) => call.data);

function sessionsApp() {
  return passwordApp({ clientIpHeader: 'x-forwarded-for' });
}

describe('the session record', () => {
  it('SE1: a sign-in records its session with the device; the tokens, the verifier and user.signed_in name it', async () => {
    const { app, hook } = sessionsApp();
    const cookie = await signInFrom(app, FIREFOX_MAC, '203.0.113.7');
    const sid = sidOf(cookie);

    expect(sid).toMatch(/^ses_[A-Za-z0-9_-]{22}$/);
    expect(sidOf(cookie, 'madauth_renewal')).toBe(sid);
    const [session] = await sessionsOf(app, cookie);
    expect(session).toEqual({
      id: sid,
      current: true,
      browser: 'Firefox',
      os: 'macOS',
      ip: '203.0.113.7',
      signedInAt: expect.any(Number),
      amr: ['google'],
      createdAt: expect.any(Number),
      lastActiveAt: expect.any(Number),
      expiresAt: (session.createdAt as number) + 30 * 24 * HOUR,
    });
    const verifySession = createSessionVerifier({ issuer: ISSUER, jwks: createLocalJWKSet({ keys: await keyService.verificationKeys() }) });
    expect(await verifySession(cookie.split('; ').find((c) => c.startsWith('madauth_session='))!.split('=')[1])).toMatchObject({ sessionId: sid });
    expect(hook.calls.find((call) => call.type === 'user.signed_in')!.data).toEqual({
      user: { id: expect.stringMatching(/^usr_/), email: 'ada@example.com', name: 'Ada Lovelace', picture: 'https://example.com/ada.png' },
      method: 'google',
      session: { id: sid, ip: '203.0.113.7', browser: 'Firefox', os: 'macOS' },
    });
  });

  it('SE2: a renewal keeps the id, moves the expiry on and records the device anew', async () => {
    const { app } = sessionsApp();
    const cookie = await signInFrom(app, FIREFOX_MAC, '203.0.113.7');
    const [before] = await sessionsOf(app, cookie);
    advance(2 * HOUR);

    const res = await app.request('/auth/session', { headers: { Cookie: renewalOnly(cookie), 'User-Agent': SAFARI_IPHONE, 'X-Forwarded-For': '203.0.113.9' } });
    expect(res.status).toBe(200);
    const renewed = cookieHeader(res);
    expect(sidOf(renewed)).toBe(before.id);
    expect((await res.json()).user.sessionId).toBe(before.id);
    const [after] = await sessionsOf(app, renewed);
    expect(after).toMatchObject({ id: before.id, ip: '203.0.113.9', browser: 'Safari', os: 'iOS', createdAt: before.createdAt, signedInAt: before.signedInAt });
    expect(after.lastActiveAt).toBeGreaterThanOrEqual((before.lastActiveAt as number) + 2 * HOUR);
    expect(after.expiresAt).toBeGreaterThanOrEqual((before.expiresAt as number) + 2 * HOUR);
  });

  it('SE3: a session issued before sessions had records gets one at its first renewal, and nobody is signed out', async () => {
    const { app, store } = sessionsApp();
    await signInFrom(app, FIREFOX_MAC, '203.0.113.7');
    const user = (await store.findMany('user', {}))[0];
    await store.delete('session', { userId: user.id as string });
    const authTime = Math.floor(Date.now() / 1000) - 600;
    // A renewal token as madAuth 0.7 signed it: no `sid`.
    const legacy = await signRenewal(keyService, ISSUER, 30 * 24 * 3600, { id: user.id as string, email: 'ada@example.com' }, ['google'], { sv: 0, auth_time: authTime });

    const first = await app.request('/auth/session', { headers: { Cookie: `madauth_renewal=${legacy}`, 'User-Agent': SAFARI_IPHONE } });
    const again = await app.request('/auth/session', { headers: { Cookie: `madauth_renewal=${legacy}`, 'User-Agent': SAFARI_IPHONE } });

    expect(first.status).toBe(200);
    expect(again.status).toBe(200);
    const sid = sidOf(cookieHeader(first));
    expect(sid).toMatch(/^ses_/);
    // The same token makes one record, however often it renews.
    expect(sidOf(cookieHeader(again))).toBe(sid);
    expect(await sessionsOf(app, cookieHeader(first))).toEqual([expect.objectContaining({ id: sid, current: true, browser: 'Safari', signedInAt: authTime * 1000, amr: ['google'] })]);
  });

  it('SE4: signing out deletes the record and sends user.session_ended (signed_out); a new sign-in at the browser replaces its session', async () => {
    const { app, hook } = sessionsApp();
    const first = await signInFrom(app, FIREFOX_MAC, '203.0.113.7');
    const other = await signInFrom(app, SAFARI_IPHONE, '203.0.113.8');
    expect(await sessionsOf(app, other)).toHaveLength(2);

    expect((await post(app, '/auth/logout', {}, { Cookie: first })).status).toBe(204);
    expect(ended(hook)).toEqual([{ user: expect.objectContaining({ email: 'ada@example.com' }), session: { id: sidOf(first) }, reason: 'signed_out' }]);
    expect((await sessionsOf(app, other)).map((s) => s.id)).toEqual([sidOf(other)]);

    hook.calls.length = 0;
    // A new sign-in at the second browser (as after "sign in again"): its old session goes.
    const { nonce, cookie } = await getNonce(app);
    const res = await app.request('/auth/providers/google/verify', {
      method: 'POST',
      headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json', Cookie: `${cookie}; ${other}` },
      body: JSON.stringify({ credential: await googleIdToken({ nonce }) }),
    });
    const replaced = cookieHeader(res);
    expect(ended(hook)).toEqual([expect.objectContaining({ session: { id: sidOf(other) }, reason: 'replaced' })]);
    expect((await sessionsOf(app, replaced)).map((s) => s.id)).toEqual([sidOf(replaced)]);
  });
});

describe("the user's sessions", () => {
  it('SE5: lists the current session first; ending another takes a recent sign-in and stops it at its next renewal', async () => {
    const { app, hook } = sessionsApp();
    const laptop = await signInFrom(app, FIREFOX_MAC, '203.0.113.7');
    const phone = await signInFrom(app, SAFARI_IPHONE, '203.0.113.8');
    expect((await sessionsOf(app, laptop)).map((s) => [s.id, s.current])).toEqual([
      [sidOf(laptop), true],
      [sidOf(phone), false],
    ]);
    expect((await list(app, '')).status).toBe(401);

    advance(3 * MINUTE);
    const late = await post(app, '/auth/sessions/end', { id: sidOf(phone) }, { Cookie: laptop });
    expect(late.status).toBe(401);
    expect(await late.json()).toMatchObject({ error: 'reauth_required' });

    const fresh = await signInFrom(app, FIREFOX_MAC, '203.0.113.7');
    expect((await post(app, '/auth/sessions/end', { id: 'ses_unknown' }, { Cookie: fresh })).status).toBe(404);
    expect((await post(app, '/auth/sessions/end', { id: sidOf(phone) }, { Cookie: fresh })).status).toBe(204);
    expect(ended(hook)).toContainEqual({ user: expect.objectContaining({ email: 'ada@example.com' }), session: { id: sidOf(phone) }, reason: 'ended' });
    expect((await post(app, '/auth/sessions/end', { id: sidOf(phone) }, { Cookie: fresh })).status).toBe(404);

    // The phone's session token is still valid until its renewal (backends check it without madAuth)...
    expect((await check(app, phone)).status).toBe(200);
    // ...which fails: the session is over, and its cookies go.
    advance(40 * MINUTE);
    const renewal = await check(app, phone);
    expect(renewal.status).toBe(401);
    expect(cookies(renewal).madauth_renewal).toMatchObject({ value: '' });
    expect((await check(app, renewalOnly(phone))).status).toBe(401);
  });

  it('SE6: ending all others keeps this one; ending the current one signs this browser out', async () => {
    const { app, hook } = sessionsApp();
    await signInFrom(app, FIREFOX_MAC, '203.0.113.7');
    await signInFrom(app, SAFARI_IPHONE, '203.0.113.8');
    const current = await signInFrom(app, FIREFOX_MAC, '203.0.113.9');
    hook.calls.length = 0;

    const res = await post(app, '/auth/sessions/end-others', {}, { Cookie: current });
    expect(await res.json()).toEqual({ ended: 2 });
    expect(ended(hook)).toHaveLength(2);
    expect((await sessionsOf(app, current)).map((s) => s.id)).toEqual([sidOf(current)]);

    const self = await post(app, '/auth/sessions/end', { id: sidOf(current) }, { Cookie: current });
    expect(self.status).toBe(204);
    expect(cookies(self).madauth_session).toMatchObject({ value: '' });
  });

  it("SE7: a password change keeps this session and removes the others' records", async () => {
    const { app, hook, store } = sessionsApp();
    await signUpVerified(app, hook);
    const user = (await store.findMany('user', {}))[0];
    const signInWithPassword = async (agent: string) => cookieHeader(await post(app, '/auth/password/signin', { email: 'grace@example.com', password: 'correct horse battery' }, { 'User-Agent': agent }));
    await signInWithPassword(SAFARI_IPHONE);
    const here = await signInWithPassword(FIREFOX_MAC);
    // With the session of the sign-up.
    expect(await sessionsOf(app, here)).toHaveLength(3);

    const res = await post(app, '/auth/password/change', { current: 'correct horse battery', password: 'another horse battery' }, { Cookie: here });
    expect(res.status).toBe(200);
    const after = cookieHeader(res);
    expect(sidOf(after)).toBe(sidOf(here));
    expect((await sessionsOf(app, after)).map((s) => s.id)).toEqual([sidOf(here)]);
    expect(await store.findMany('session', { userId: user.id as string })).toHaveLength(1);
  });
});

describe('an ended session before its renewal', () => {
  it('SE13: makes no sensitive change, although its sign-in is recent and its token valid', async () => {
    const { app } = sessionsApp();
    const taken = await signInFrom(app, FIREFOX_MAC, '198.51.100.9');
    const owner = await signInFrom(app, SAFARI_IPHONE, '203.0.113.8');
    expect((await post(app, '/auth/sessions/end', { id: sidOf(taken) }, { Cookie: owner })).status).toBe(204);

    expect((await check(app, taken)).status).toBe(200);
    expect(await (await post(app, '/auth/sessions/end-others', {}, { Cookie: taken })).json()).toMatchObject({ error: 'reauth_required' });
    expect((await sessionsOf(app, owner)).map((s) => s.id)).toEqual([sidOf(owner)]);
  });

  it("SE14: a password change doesn't bring it back", async () => {
    const { app, hook, store } = sessionsApp();
    await signUpVerified(app, hook);
    const signInWithPassword = async (agent: string) => cookieHeader(await post(app, '/auth/password/signin', { email: 'grace@example.com', password: 'correct horse battery' }, { 'User-Agent': agent }));
    const taken = await signInWithPassword(FIREFOX_MAC);
    await store.delete('session', { id: sidOf(taken) });

    const res = await post(app, '/auth/password/change', { current: 'correct horse battery', password: 'another horse battery' }, { Cookie: taken });
    expect(cookies(res).madauth_session).toMatchObject({ value: '' });
    expect(await store.findOne('session', { id: sidOf(taken) })).toBeNull();
  });
});

describe("an admin and a user's sessions", () => {
  it('SE8: an admin lists a user\'s sessions by id and ends one or all of them, told with `by`', async () => {
    const { app, hook, store } = sessionsApp();
    const grace = await signInFrom(app, FIREFOX_MAC, '203.0.113.7', { sub: '2002', email: 'grace@example.com', name: 'Grace Hopper' });
    await signInFrom(app, SAFARI_IPHONE, '203.0.113.8', { sub: '2002', email: 'grace@example.com', name: 'Grace Hopper' });
    const graceId = decodeJwt(grace.split('; ').find((c) => c.startsWith('madauth_session='))!.split('=')[1]).sub!;
    await signInFrom(app, FIREFOX_MAC, '203.0.113.1');
    await setClaims(store, 'ada@example.com', { roles: ['admin'] });
    const ada = await signInFrom(app, FIREFOX_MAC, '203.0.113.1');

    expect((await post(app, '/auth/admin/sessions/list', { userId: graceId }, { Cookie: grace })).status).toBe(403);
    expect((await post(app, '/auth/admin/sessions/list', { userId: 'usr_nobody' }, { Cookie: ada })).status).toBe(404);
    const listed = await (await post(app, '/auth/admin/sessions/list', { userId: graceId }, { Cookie: ada })).json();
    expect(listed).toMatchObject({ userId: graceId, email: 'grace@example.com' });
    expect(listed.sessions).toHaveLength(2);
    expect(listed.sessions.every((s: { current: boolean }) => !s.current)).toBe(true);

    hook.calls.length = 0;
    const one = await post(app, '/auth/admin/sessions/end', { userId: graceId, id: sidOf(grace) }, { Cookie: ada });
    expect(await one.json()).toEqual({ userId: graceId, email: 'grace@example.com', ended: 1 });
    expect(ended(hook)).toEqual([{ user: expect.objectContaining({ email: 'grace@example.com' }), session: { id: sidOf(grace) }, reason: 'ended', by: 'ada@example.com' }]);
    expect((await post(app, '/auth/admin/sessions/end', { userId: graceId, id: sidOf(grace) }, { Cookie: ada })).status).toBe(404);
    expect((await post(app, '/auth/admin/sessions/end', { userId: graceId }, { Cookie: ada })).status).toBe(400);

    const all = await post(app, '/auth/admin/sessions/end', { userId: graceId, id: 'all' }, { Cookie: ada });
    expect(await all.json()).toMatchObject({ ended: 1 });
    expect(await store.findMany('session', { userId: graceId })).toEqual([]);

    // An admin who ends their own session is signed out at once.
    const own = await post(app, '/auth/admin/sessions/end', { userId: sidOwner(ada), id: sidOf(ada) }, { Cookie: ada });
    expect(await own.json()).toMatchObject({ ended: 1 });
    expect(cookies(own).madauth_session).toMatchObject({ value: '' });

    // Ending takes a recent sign-in, like every change of the admin API.
    advance(3 * MINUTE);
    expect(await (await post(app, '/auth/admin/sessions/end', { userId: graceId, id: 'all' }, { Cookie: ada })).json()).toMatchObject({ error: 'reauth_required' });
  });
});

describe('the records of ended sessions', () => {
  it('SE9: a session that expired or is of an older session version is not listed and goes at the next sign-in', async () => {
    const store = createSqliteAdapter(':memory:');
    const sessions = new Sessions(store, HOUR);
    const device = { ip: null, browser: null, os: null };
    await sessions.start({ id: 'ses_a', userId: 'usr_1', sessionVersion: 0, authTime: 1, amr: ['pwd'], device });
    advance(2 * HOUR);
    await sessions.start({ id: 'ses_b', userId: 'usr_1', sessionVersion: 1, authTime: 2, amr: ['pwd'], device });
    expect((await sessions.list('usr_1', 1)).map((s) => s.id)).toEqual(['ses_b']);
    expect((await store.findMany('session', { userId: 'usr_1' })).map((s) => s.id)).toEqual(['ses_b']);
    expect(await sessions.renew('ses_a', 'usr_1', device)).toBe(false);
    expect(await sessions.renew('ses_b', 'usr_2', device)).toBe(false);
  });

  it("SE10: now and then, the expired sessions of every user go, with a store that can delete them", async () => {
    const store = createSqliteAdapter(':memory:');
    const deleteExpired = vi.spyOn(store, 'deleteExpired');
    const sessions = new Sessions(store, HOUR);
    const device = { ip: null, browser: null, os: null };
    await sessions.start({ id: 'ses_old', userId: 'usr_gone', sessionVersion: 0, authTime: 1, amr: ['pwd'], device });
    advance(2 * HOUR);
    await sessions.start({ id: 'ses_1', userId: 'usr_1', sessionVersion: 0, authTime: 1, amr: ['pwd'], device });
    expect(await store.findOne('session', { id: 'ses_old' })).toBeNull();
    await sessions.start({ id: 'ses_2', userId: 'usr_2', sessionVersion: 0, authTime: 1, amr: ['pwd'], device });
    expect(deleteExpired).toHaveBeenCalledTimes(2);
    advance(CLEANUP_INTERVAL_MS);
    await sessions.start({ id: 'ses_3', userId: 'usr_3', sessionVersion: 0, authTime: 1, amr: ['pwd'], device });
    expect(deleteExpired).toHaveBeenCalledTimes(3);
  });
});

describe('the device', () => {
  it('SE11: names the browser and the operating system of common user agents, and nothing else', () => {
    expect(parseUserAgent(FIREFOX_MAC)).toEqual({ browser: 'Firefox', os: 'macOS' });
    expect(parseUserAgent(SAFARI_IPHONE)).toEqual({ browser: 'Safari', os: 'iOS' });
    expect(parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0')).toEqual({ browser: 'Edge', os: 'Windows' });
    expect(parseUserAgent('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36')).toEqual({ browser: 'Chrome', os: 'Android' });
    expect(parseUserAgent('Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0 Mobile/15E148 Safari/604.1')).toEqual({ browser: 'Chrome', os: 'iPadOS' });
    expect(parseUserAgent('Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')).toEqual({ browser: 'Chrome', os: 'ChromeOS' });
    expect(parseUserAgent('curl/8.7.1')).toEqual({ browser: null, os: null });
    expect(parseUserAgent(undefined)).toEqual({ browser: null, os: null });
  });

  it('SE12: reads an IP address without its port, and an IPv4 address mapped into IPv6 as IPv4', () => {
    expect(normalizeIp('203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeIp(' 203.0.113.7:5123 ')).toBe('203.0.113.7');
    expect(normalizeIp('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeIp('2001:db8::1')).toBe('2001:db8::1');
    expect(normalizeIp('[2001:db8::1]:443')).toBe('2001:db8::1');
    expect(normalizeIp('unknown')).toBeNull();
    expect(normalizeIp(undefined)).toBeNull();
  });
});
