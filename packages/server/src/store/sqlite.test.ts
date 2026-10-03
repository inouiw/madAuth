import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import { storeAdapterContract } from '../testing.js';
import { madauthSchema } from './schema.js';
import { columnName, createTablesSql } from './sql.js';
import { createSqliteAdapter } from './sqlite.js';

// P4: the built-in adapter is checked with the same contract as a custom one.
storeAdapterContract({ describe, it, expect }, () => createSqliteAdapter(':memory:'));

let dir: string | undefined;
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

const user = {
  id: 'usr_1',
  email: 'Ada@example.com',
  emailNormalized: 'ada@example.com',
  emailVerified: true,
  name: 'Ada',
  sessionVersion: 0,
  lastMailAt: 0,
  createdAt: 1,
};

describe('SQLite adapter', () => {
  it('P5: keeps the data when the database is opened again', async () => {
    dir = mkdtempSync(join(tmpdir(), 'madauth-'));
    const path = join(dir, 'madauth.db');
    await createSqliteAdapter(path).create('user', user);

    const reopened = createSqliteAdapter(path);

    expect(await reopened.findOne('user', { id: 'usr_1' })).toEqual(user);
  });

  it('P5: refuses a database written by a newer madAuth', () => {
    dir = mkdtempSync(join(tmpdir(), 'madauth-'));
    const path = join(dir, 'madauth.db');
    const db = new DatabaseSync(path);
    db.exec(`PRAGMA user_version = ${madauthSchema.version + 1}`);
    db.close();

    expect(() => createSqliteAdapter(path)).toThrow(/newer|Update madAuth/);
  });

  it('rejects models and fields that are not in the schema', async () => {
    const store = createSqliteAdapter(':memory:');

    await expect(store.findOne('user; DROP TABLE madauth_user', {})).rejects.toThrow(/Unknown model/);
    await expect(store.findOne('user', { 'id = id OR 1': 1 })).rejects.toThrow(/Unknown field/);
  });

  it('P6: is built only on the public API, like a custom adapter', () => {
    const source = readFileSync(new URL('./sqlite.ts', import.meta.url), 'utf8');
    const imports = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]);

    expect(imports.sort()).toEqual(['./schema.js', './sql.js', 'node:sqlite']);
    // Only type imports from node:sqlite: the module is loaded lazily.
    expect(source).toMatch(/import type \{[^}]*\} from 'node:sqlite'/);
  });
});

describe('schema', () => {
  it('is independent of how the records are stored', () => {
    const source = readFileSync(new URL('./schema.ts', import.meta.url), 'utf8');

    expect(source).not.toMatch(/^import /m);
    expect(source).not.toMatch(/sql/i);
  });
});

describe('createTablesSql', () => {
  it('P8: creates every model and field, with unique constraints and indexes, in every dialect', () => {
    for (const dialect of ['sqlite', 'postgres', 'mysql'] as const) {
      const sql = createTablesSql(dialect);
      for (const [model, { fields }] of Object.entries(madauthSchema.models)) {
        expect(sql).toContain(`CREATE TABLE madauth_${model} (`);
        for (const field of Object.keys(fields)) expect(sql).toContain(`  ${columnName(field)} `);
      }
      expect(sql).toMatch(/email_normalized \S+ NOT NULL UNIQUE/);
      expect(sql).toContain('CREATE INDEX madauth_account_user_id ON madauth_account (user_id);');
    }
    expect(createTablesSql('mysql')).toContain('email_normalized VARCHAR(255) NOT NULL UNIQUE');
    expect(createTablesSql('postgres')).toContain('email_verified BOOLEAN NOT NULL');
  });

  it('P8: the SQLite output runs', () => {
    const db = new DatabaseSync(':memory:');
    db.exec(createTablesSql('sqlite'));

    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((r) => r.name);
    expect(tables).toEqual(['madauth_account', 'madauth_user', 'madauth_verification']);
  });
});
