import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import { storeAdapterContract } from '../testing.js';
import { madauthSchema } from './schema.js';
import { columnName, createTablesSql, upgradeTablesSql } from './sql.js';
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
  wrongCodes: 0,
  claims: null,
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

  it('upgrades a database written by an older madAuth and keeps its records', async () => {
    dir = mkdtempSync(join(tmpdir(), 'madauth-'));
    const path = join(dir, 'madauth.db');
    // Schema version 1: users had no count of wrong codes and no claims, accounts no e-mail, and there were no settings.
    const { wrongCodes: _, claims: __, ...v1Fields } = madauthSchema.models.user.fields;
    const { email: ___, ...v1AccountFields } = madauthSchema.models.account.fields;
    const { setting: ____, ...v1Models } = madauthSchema.models;
    const v1 = { version: 1, models: { ...v1Models, user: { fields: v1Fields }, account: { fields: v1AccountFields } } };
    const db = new DatabaseSync(path);
    db.exec(createTablesSql('sqlite', v1));
    db.exec("INSERT INTO madauth_user VALUES ('usr_1', 'Ada@example.com', 'ada@example.com', 1, 'Ada', 0, 0, 1)");
    db.exec('PRAGMA user_version = 1');
    db.close();

    const store = createSqliteAdapter(path);

    expect(await store.findOne('user', { id: 'usr_1' })).toEqual(user);
    expect(await store.update('user', { id: 'usr_1', wrongCodes: 0 }, { wrongCodes: 1 })).toBe(1);
    expect(await store.create('setting', { id: 'methods', value: '{}', updatedAt: 1, updatedBy: null })).toBe(true);
    // Opening it again changes nothing more.
    const reopened = createSqliteAdapter(path);
    expect((await reopened.findOne('user', { id: 'usr_1' }))?.wrongCodes).toBe(1);
    expect((await reopened.findOne('setting', { id: 'methods' }))?.value).toBe('{}');
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

  it('upgradeTablesSql lists what newer schema versions added, per dialect', () => {
    expect(upgradeTablesSql('postgres', 1).split('\n')[0]).toBe('ALTER TABLE madauth_user ADD COLUMN wrong_codes DOUBLE PRECISION NOT NULL DEFAULT 0;');
    expect(upgradeTablesSql('mysql', 1).split('\n')[0]).toBe('ALTER TABLE madauth_user ADD COLUMN wrong_codes DOUBLE NOT NULL DEFAULT 0;');
    expect(upgradeTablesSql('mysql', 2).split('\n')[0]).toBe('CREATE TABLE madauth_role (');
    // Version 4 replaced the role table with claims on the user and added settings.
    expect(upgradeTablesSql('postgres', 3)).toBe(
      'ALTER TABLE madauth_user ADD COLUMN claims TEXT;\n' +
        'ALTER TABLE madauth_account ADD COLUMN email TEXT;\n' +
        'DROP TABLE madauth_role;\n' +
        'CREATE TABLE madauth_setting (\n  id TEXT PRIMARY KEY,\n  value TEXT NOT NULL,\n  updated_at DOUBLE PRECISION NOT NULL,\n  updated_by TEXT\n);',
    );
    expect(upgradeTablesSql('sqlite', madauthSchema.version)).toBe('');
  });

  it('P8: the SQLite output runs', () => {
    const db = new DatabaseSync(':memory:');
    db.exec(createTablesSql('sqlite'));

    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((r) => r.name);
    expect(tables).toEqual(['madauth_account', 'madauth_setting', 'madauth_user', 'madauth_verification']);
  });
});
