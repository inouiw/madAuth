// Searching users, for admins: see "Searching users" in docs/server.md.
import { describe, expect, it } from 'vitest';
import { REDIRECT_TO, passwordApp, post, setClaims, signUpVerified } from './test/helpers.js';
import type { StoreAdapter } from './store/schema.js';
import type { FoundUser } from './user-search.js';

type Made = ReturnType<typeof passwordApp>;
type Answer = { users: FoundUser[]; cursor?: string };

/** A server with Ada, an admin signed in now. */
async function withAdmin(): Promise<Made & { cookie: string }> {
  const made = passwordApp();
  const cookie = `madauth_session=${await signUpVerified(made.app, made.hook, 'ada@example.com', 'the admins own password')}`;
  await setClaims(made.store, 'ada@example.com', { roles: ['admin'] });
  return { ...made, cookie };
}

const search = (made: Made & { cookie: string }, body: Record<string, unknown>) => post(made.app, '/auth/admin/users/search', body, { Cookie: made.cookie });
const found = async (made: Made & { cookie: string }, body: Record<string, unknown>): Promise<Answer> => {
  const res = await search(made, body);
  expect(res.status).toBe(200);
  return (await res.json()) as Answer;
};
const emails = (answer: Answer) => answer.users.map((user) => user.email).sort();

let counter = 0;
/** A user written straight into the store, e.g. many of them or with a given sign-up time. */
async function storeUser(store: StoreAdapter, fields: { email?: string; signedUpAt?: number | null; claims?: Record<string, unknown> } = {}): Promise<string> {
  const id = `usr_search_${(counter++).toString().padStart(5, '0')}`;
  const email = fields.email ?? `${id}@example.com`;
  await store.create('user', {
    id,
    email,
    emailNormalized: email,
    emailVerified: true,
    name: null,
    sessionVersion: 0,
    lastMailAt: 0,
    lastSmsAt: null,
    wrongCodes: 0,
    claims: fields.claims ? JSON.stringify(fields.claims) : null,
    signedUpAt: fields.signedUpAt === undefined ? 1_700_000_000_000 : fields.signedUpAt,
    signUpMethod: null,
    createdAt: 1_600_000_000_000,
  });
  return email;
}

describe('searching users', () => {
  it('US1: is for admins only, and answers each user with their claims, methods and sign-up', async () => {
    const made = await withAdmin();
    expect((await post(made.app, '/auth/admin/users/search', {})).status).toBe(401);
    const grace = `madauth_session=${await signUpVerified(made.app, made.hook, 'grace@example.com', 'correct horse battery')}`;
    expect((await post(made.app, '/auth/admin/users/search', {}, { Cookie: grace })).status).toBe(403);

    const { users, cursor } = await found(made, {});
    expect(cursor).toBeUndefined();
    expect(users.find((user) => user.email === 'ada@example.com')).toEqual({
      id: expect.stringMatching(/^usr_/),
      email: 'ada@example.com',
      name: 'Grace Hopper',
      emailVerified: true,
      claims: { roles: ['admin'] },
      methods: ['password'],
      signedUpAt: expect.any(Number),
      pending: false,
    });
    expect(emails({ users, cursor })).toEqual(['ada@example.com', 'grace@example.com']);
  });

  it('US2: finds users by role, by their exact address, by when they signed up and by a pending sign-up', async () => {
    const made = await withAdmin();
    await storeUser(made.store, { email: 'early@example.com', signedUpAt: 1_000, claims: { roles: ['editor'] } });
    await storeUser(made.store, { email: 'later@example.com', signedUpAt: 3_000, claims: { roles: ['editor', 'support'] } });
    // From before schema version 7: no sign-up time, so its creation counts.
    await storeUser(made.store, { email: 'old@example.com', signedUpAt: null });
    await post(made.app, '/auth/password/signup', { email: 'pending@example.com', password: 'correct horse battery', redirectTo: REDIRECT_TO });

    expect(emails(await found(made, { role: 'editor' }))).toEqual(['early@example.com', 'later@example.com']);
    expect(emails(await found(made, { role: 'admin' }))).toEqual(['ada@example.com']);
    expect(emails(await found(made, { role: 'support', signedUpAfter: 2_000 }))).toEqual(['later@example.com']);
    expect(emails(await found(made, { signedUpBefore: 2_000 }))).toEqual(['early@example.com']);
    expect(emails(await found(made, { signedUpAfter: 2_000, signedUpBefore: 1_650_000_000_000 }))).toEqual(['later@example.com', 'old@example.com']);

    const pending = await found(made, { pending: true });
    expect(pending.users).toEqual([expect.objectContaining({ email: 'pending@example.com', pending: true, signedUpAt: null, emailVerified: false })]);
    expect(emails(await found(made, { pending: false }))).not.toContain('pending@example.com');
    // A pending sign-up has no time to be in a range.
    expect(emails(await found(made, { signedUpAfter: 0 }))).not.toContain('pending@example.com');

    expect(emails(await found(made, { email: 'Later@Example.com' }))).toEqual(['later@example.com']);
    expect(emails(await found(made, { email: 'later@example.com', role: 'admin' }))).toEqual([]);
    expect(emails(await found(made, { email: 'nobody@example.com' }))).toEqual([]);
  });

  it('US3: goes through every user page by page, each once', async () => {
    const made = await withAdmin();
    const stored = await Promise.all(Array.from({ length: 7 }, () => storeUser(made.store)));

    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await found(made, { limit: 3, ...(cursor ? { cursor } : {}) });
      expect(page.users.length).toBeLessThanOrEqual(3);
      seen.push(...page.users.map((user) => user.email));
      cursor = page.cursor;
    } while (cursor);
    expect(seen.sort()).toEqual(['ada@example.com', ...stored].sort());
  });

  it('US4: reads at most a thousand users per request, and goes on from its cursor', async () => {
    const made = await withAdmin();
    for (let i = 0; i < 1100; i++) await storeUser(made.store);
    const rare = await storeUser(made.store, { claims: { roles: ['rare'] } });

    const first = await found(made, { role: 'rare' });
    const second = first.cursor ? await found(made, { role: 'rare', cursor: first.cursor }) : first;
    expect(first.cursor).toBeDefined();
    expect(second.cursor).toBeUndefined();
    expect([...emails(first), ...emails(second)]).toEqual([rare]);
  });

  it('US5: refuses filters it does not have and values that are none', async () => {
    const made = await withAdmin();
    for (const [body, error] of [
      [{ method: 'passkey' }, 'invalid_search'],
      [{ role: 'Admin' }, 'invalid_search'],
      [{ role: 7 }, 'invalid_search'],
      [{ signedUpAfter: '2026-01-01' }, 'invalid_search'],
      [{ pending: 'yes' }, 'invalid_search'],
      [{ limit: 0 }, 'invalid_search'],
      [{ limit: 101 }, 'invalid_search'],
      [{ limit: 2.5 }, 'invalid_search'],
      [{ cursor: '' }, 'invalid_search'],
      [{ email: 'not an address' }, 'invalid_email'],
    ] as const) {
      const res = await search(made, body);
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error, message: expect.any(String) });
    }
  });

  it('US6: takes an API key with the scope madauth:users:read, and no other', async () => {
    const made = await withAdmin();
    const key = async (scopes: string[]) => {
      const res = await post(made.app, '/auth/api-keys/create', { name: 'k', scopes }, { Cookie: made.cookie });
      return ((await res.json()) as { key: string }).key;
    };
    const withKey = (key: string) =>
      made.app.request('/auth/admin/users/search', { method: 'POST', headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' }, body: '{"role":"admin"}' });

    const allowed = await withKey(await key(['madauth:users:read']));
    expect(allowed.status).toBe(200);
    expect(emails((await allowed.json()) as Answer)).toEqual(['ada@example.com']);
    const other = await withKey(await key(['madauth:claims:read']));
    expect(other.status).toBe(403);
    expect(await other.json()).toMatchObject({ error: 'insufficient_scope' });
  });
});
