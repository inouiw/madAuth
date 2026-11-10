import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { Password } from '../providers/password.js';
import { SERVER, ada, fakeServer, grace, resetAll } from '../test-helpers.js';
import type { SessionInfo } from './sessions.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

const init = () => Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
const session = (email: string, id: string, current = false): SessionInfo & { email: string } => ({
  email,
  id,
  current,
  browser: 'Firefox',
  os: 'macOS',
  ip: '203.0.113.7',
  signedInAt: 1,
  amr: ['pwd'],
  createdAt: 1,
  lastActiveAt: 2,
  expiresAt: 3,
});

describe('Madauth.sessions', () => {
  it("SW1: lists the user's sessions, ends one and all others", async () => {
    const server = fakeServer();
    server.user = grace;
    server.sessions = [session(grace.email!, 'ses_1', true), session(grace.email!, 'ses_2'), session(grace.email!, 'ses_3'), session(ada.email!, 'ses_ada')];
    await init();

    const listed = await Madauth.sessions.list();
    expect(listed).toMatchObject({ isSuccess: true, sessions: [{ id: 'ses_1', current: true, browser: 'Firefox' }, { id: 'ses_2' }, { id: 'ses_3' }] });
    expect(await Madauth.sessions.end('ses_2')).toEqual({ isSuccess: true });
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/sessions/end`, body: { id: 'ses_2' } });
    expect(await Madauth.sessions.end('ses_2')).toMatchObject({ isSuccess: false, error: { code: 'session_not_found' } });
    expect(await Madauth.sessions.endOthers()).toEqual({ isSuccess: true, ended: 1 });
    expect(server.sessions.map((s) => s.id)).toEqual(['ses_1', 'ses_ada']);
  });

  it('SW2: ending takes a recent sign-in, and everything a session', async () => {
    const server = fakeServer();
    server.user = grace;
    server.sessions = [session(grace.email!, 'ses_1', true), session(grace.email!, 'ses_2')];
    await init();

    server.staleSignIn = true;
    expect(await Madauth.sessions.end('ses_2')).toMatchObject({ isSuccess: false, error: { code: 'reauth_required' } });
    expect(await Madauth.sessions.endOthers()).toMatchObject({ isSuccess: false, error: { code: 'reauth_required' } });
    server.user = null;
    expect(await Madauth.sessions.list()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
  });
});

describe('Madauth.admin.sessions', () => {
  it("SW3: an admin lists a user's sessions by id and ends one or all; others are forbidden", async () => {
    const server = fakeServer();
    server.user = grace;
    server.accounts.set(ada.email!, { password: 'adas password!', verified: true, name: 'Ada' });
    server.sessions = [session(ada.email!, 'ses_a1'), session(ada.email!, 'ses_a2'), session(ada.email!, 'ses_a3')];
    await init();

    expect(await Madauth.admin.sessions.list(ada.id)).toMatchObject({ isSuccess: false, error: { code: 'forbidden' } });
    server.claims.set(grace.email!, { roles: ['admin'] });
    server.user = { ...grace, claims: { roles: ['admin'] } };

    expect(await Madauth.admin.sessions.list(ada.id)).toMatchObject({ isSuccess: true, email: ada.email, sessions: [{ id: 'ses_a1' }, { id: 'ses_a2' }, { id: 'ses_a3' }] });
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/admin/sessions/list`, body: { userId: ada.id } });
    expect(await Madauth.admin.sessions.list('usr_nobody')).toMatchObject({ isSuccess: false, error: { code: 'user_not_found' } });
    expect(await Madauth.admin.sessions.end(ada.id, 'ses_a1')).toEqual({ isSuccess: true, ended: 1 });
    expect(await Madauth.admin.sessions.end(ada.id, 'ses_a1')).toMatchObject({ isSuccess: false, error: { code: 'session_not_found' } });
    expect(await Madauth.admin.sessions.end(ada.id, 'all')).toEqual({ isSuccess: true, ended: 2 });
    expect(server.sessions).toEqual([]);
  });
});
