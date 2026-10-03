import type { Row, StoreAdapter } from './store/schema.js';

/** The parts of a test runner the contract needs; Vitest, Jest and node:test with `expect` all fit. */
export interface ContractRunner {
  describe(name: string, fn: () => void): void;
  it(name: string, fn: () => Promise<void>): void;
  expect(actual: unknown): { toEqual(expected: unknown): void; toBe(expected: unknown): void };
}

let counter = 0;
/** A value no other test run uses, so the suite also works against a shared, non-empty database. */
function unique(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${(counter++).toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function testUser(overrides: Row = {}): Row {
  const id = unique('usr_contract');
  return {
    id,
    email: `${id}@Example.com`,
    emailNormalized: `${id}@example.com`,
    emailVerified: false,
    name: null,
    sessionVersion: 0,
    lastMailAt: 0,
    wrongCodes: 0,
    createdAt: 1_700_000_000_000,
    ...overrides,
  };
}

function testAccount(overrides: Row = {}): Row {
  const id = unique('acc_contract');
  return {
    id,
    userId: unique('usr_contract'),
    key: `password:${id}`,
    secret: 'hash',
    failedAttempts: 0,
    lockedUntil: 0,
    createdAt: 1_700_000_000_000,
    ...overrides,
  };
}

function testVerification(userId: string, purpose = 'reset'): Row {
  return { id: unique('ver'), userId, purpose, codeHash: 'h', attempts: 0, expiresAt: 1_700_000_000_000 };
}

/**
 * Checks that a {@link StoreAdapter} behaves the way madAuth relies on. Run it from your own tests:
 *
 * ```ts
 * import { describe, it, expect } from 'vitest';
 * import { storeAdapterContract } from '@madauth/server/testing';
 * storeAdapterContract({ describe, it, expect }, () => createMyAdapter(process.env.TEST_DB_URL!));
 * ```
 *
 * `createAdapter` is called once per test. The tests only add records with fresh ids, so a shared test
 * database works as well as an empty one.
 */
export function storeAdapterContract(t: ContractRunner, createAdapter: () => StoreAdapter | Promise<StoreAdapter>): void {
  const { describe, it, expect } = t;

  describe('madAuth store adapter contract', () => {
    it('creates a record and finds it with the same types', async () => {
      const store = await createAdapter();
      const user = testUser({ emailVerified: true, name: 'Ada', sessionVersion: 3 });

      expect(await store.create('user', user)).toBe(true);

      expect(await store.findOne('user', { id: user.id })).toEqual(user);
      expect(await store.findOne('user', { id: unique('missing') })).toBe(null);
    });

    it('keeps false, 0 and null distinct', async () => {
      const store = await createAdapter();
      const user = testUser({ emailVerified: false, name: null, sessionVersion: 0 });
      await store.create('user', user);

      const found = await store.findOne('user', { id: user.id });

      expect(found?.emailVerified).toBe(false);
      expect(found?.name).toBe(null);
      expect(found?.sessionVersion).toBe(0);
    });

    it('refuses a duplicate unique value or primary key and writes nothing', async () => {
      const store = await createAdapter();
      const user = testUser({ name: 'Original' });
      await store.create('user', user);

      const sameEmail = testUser({ emailNormalized: user.emailNormalized, name: 'Duplicate' });
      expect(await store.create('user', sameEmail)).toBe(false);
      expect(await store.findOne('user', { id: sameEmail.id })).toBe(null);

      expect(await store.create('user', { ...testUser(), id: user.id, name: 'Duplicate' })).toBe(false);
      expect((await store.findOne('user', { id: user.id }))?.name).toBe('Original');
    });

    it('matches every field of the filter, including null', async () => {
      const store = await createAdapter();
      const user = testUser({ emailVerified: true, name: null });
      await store.create('user', user);

      expect((await store.findOne('user', { emailNormalized: user.emailNormalized, emailVerified: true }))?.id).toBe(user.id);
      expect(await store.findOne('user', { emailNormalized: user.emailNormalized, emailVerified: false })).toBe(null);
      expect((await store.findOne('user', { id: user.id, name: null }))?.id).toBe(user.id);
    });

    it('finds many records and honours the limit', async () => {
      const store = await createAdapter();
      const userId = unique('usr_contract');
      for (let i = 0; i < 3; i++) await store.create('verification', testVerification(userId));

      expect((await store.findMany('verification', { userId })).length).toBe(3);
      expect((await store.findMany('verification', { userId }, { limit: 2 })).length).toBe(2);
      expect(await store.findMany('verification', { userId: unique('nobody') })).toEqual([]);
    });

    it('updates only the given fields of the matching records and counts them', async () => {
      const store = await createAdapter();
      const user = testUser({ name: 'Ada' });
      const other = testUser({ name: 'Grace' });
      await store.create('user', user);
      await store.create('user', other);

      expect(await store.update('user', { id: user.id }, { emailVerified: true, sessionVersion: 1 })).toBe(1);
      expect(await store.update('user', { id: unique('missing') }, { sessionVersion: 1 })).toBe(0);

      expect(await store.findOne('user', { id: user.id })).toEqual({ ...user, emailVerified: true, sessionVersion: 1 });
      expect(await store.findOne('user', { id: other.id })).toEqual(other);
    });

    it('deletes the matching records and counts them', async () => {
      const store = await createAdapter();
      const userId = unique('usr_contract');
      const records = [testVerification(userId), testVerification(userId)];
      for (const record of records) await store.create('verification', record);

      expect(await store.delete('verification', { id: records[0].id })).toBe(1);
      expect(await store.delete('verification', { id: records[0].id })).toBe(0);
      expect(await store.findOne('verification', { id: records[1].id })).toEqual(records[1]);
    });

    it('reports a deleted record to only one of several concurrent deletes', async () => {
      const store = await createAdapter();
      const record = testVerification(unique('usr_contract'));
      await store.create('verification', record);

      const counts = await Promise.all(Array.from({ length: 10 }, () => store.delete('verification', { id: record.id })));

      expect(counts.reduce((sum, n) => sum + n, 0)).toBe(1);
    });

    it('finds a record by a unique field other than its id', async () => {
      const store = await createAdapter();
      const account = testAccount();
      await store.create('account', account);

      expect(await store.findOne('account', { key: account.key })).toEqual(account);
      expect(await store.findOne('account', { key: unique('password:missing') })).toBe(null);
    });

    it('sets a field to a value and to null', async () => {
      const store = await createAdapter();
      const user = testUser({ name: 'Ada' });
      await store.create('user', user);

      expect(await store.update('user', { id: user.id }, { name: 'Grace' })).toBe(1);
      expect((await store.findOne('user', { id: user.id }))?.name).toBe('Grace');

      expect(await store.update('user', { id: user.id }, { name: null })).toBe(1);
      expect(await store.findOne('user', { id: user.id })).toEqual({ ...user, name: null });

      // `null` in a filter matches the emptied field.
      expect(await store.update('user', { id: user.id, name: null }, { name: 'Ada' })).toBe(1);
      expect(await store.update('user', { id: user.id, name: null }, { name: 'Grace' })).toBe(0);
      expect((await store.findOne('user', { id: user.id }))?.name).toBe('Ada');
    });

    it('updates a record only while it still matches every field of the filter', async () => {
      const store = await createAdapter();
      const account = testAccount();
      await store.create('account', account);
      const unchanged = { id: account.id, failedAttempts: 0 };

      expect(await store.update('account', unchanged, { failedAttempts: 1, lockedUntil: 5 })).toBe(1);
      expect(await store.update('account', unchanged, { failedAttempts: 1, lockedUntil: 9 })).toBe(0);

      expect(await store.findOne('account', { id: account.id })).toEqual({ ...account, failedAttempts: 1, lockedUntil: 5 });
    });

    it('applies only one of several concurrent updates with the same filter', async () => {
      const store = await createAdapter();
      const account = testAccount();
      await store.create('account', account);

      const counts = await Promise.all(
        Array.from({ length: 10 }, () => store.update('account', { id: account.id, failedAttempts: 0 }, { failedAttempts: 1 })),
      );

      expect(counts.reduce((sum, n) => sum + n, 0)).toBe(1);
    });

    it('deletes every record that matches an indexed field', async () => {
      const store = await createAdapter();
      const userId = unique('usr_contract');
      const other = testVerification(unique('usr_contract'));
      for (const purpose of ['verify', 'reset', 'reset']) await store.create('verification', testVerification(userId, purpose));
      await store.create('verification', other);

      expect(await store.delete('verification', { userId, purpose: 'verify' })).toBe(1);
      expect((await store.findMany('verification', { userId })).length).toBe(2);

      expect(await store.delete('verification', { userId })).toBe(2);
      expect(await store.findMany('verification', { userId })).toEqual([]);
      expect(await store.findOne('verification', { id: other.id })).toEqual(other);
    });
  });
}
