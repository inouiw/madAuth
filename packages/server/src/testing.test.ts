import { describe, expect, it } from 'vitest';
import type { StoreAdapter } from './store/schema.js';
import { createSqliteAdapter } from './store/sqlite.js';
import { storeAdapterContract, type ContractRunner } from './testing.js';

/** Runs the contract with a runner that records which tests fail instead of reporting them. */
async function runContract(createAdapter: () => StoreAdapter): Promise<string[]> {
  const tests: { name: string; fn: () => Promise<void> }[] = [];
  const runner: ContractRunner = {
    describe: (_name, fn) => fn(),
    it: (name, fn) => tests.push({ name, fn }),
    expect,
  };
  storeAdapterContract(runner, createAdapter);
  const failed: string[] = [];
  for (const test of tests) {
    try {
      await test.fn();
    } catch {
      failed.push(test.name);
    }
  }
  return failed;
}

describe('storeAdapterContract', () => {
  it('passes for the SQLite adapter', async () => {
    expect(await runContract(() => createSqliteAdapter(':memory:'))).toEqual([]);
  });

  it('P7: catches an adapter that overwrites duplicates and over-reports deletes', async () => {
    const broken = (): StoreAdapter => {
      const real = createSqliteAdapter(':memory:');
      return {
        ...real,
        // Overwrites instead of refusing duplicates.
        async create(model, data) {
          await real.delete(model, { id: data.id });
          return real.create(model, data);
        },
        // Says every delete worked, so a link could be used twice.
        async delete(model, where) {
          await real.delete(model, where);
          return 1;
        },
      };
    };

    expect(await runContract(broken)).toEqual(
      expect.arrayContaining([
        'refuses a duplicate unique value or primary key and writes nothing',
        'deletes the matching records and counts them',
        'reports a deleted record to only one of several concurrent deletes',
      ]),
    );
  });
});
