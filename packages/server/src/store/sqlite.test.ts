import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import { schemaV1 } from '../test/schema-v1.js';
import { storeAdapterContract } from '../testing.js';
import { madauthSchema } from './schema.js';
import { columnName, createTablesSql, tableName, upgradeTablesSql } from './sql.js';
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
  lastSmsAt: null,
  wrongCodes: 0,
  claims: null,
  signedUpAt: null,
  signUpMethod: null,
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
    const db = new DatabaseSync(path);
    db.exec(createTablesSql('sqlite', schemaV1));
    db.exec("INSERT INTO madauth_user VALUES ('usr_1', 'Ada@example.com', 'ada@example.com', 1, 'Ada', 0, 0, 1)");
    db.exec("INSERT INTO madauth_account VALUES ('acc_1', 'usr_1', 'password:usr_1', 'hash', 0, 0, 1)");
    db.exec('PRAGMA user_version = 1');
    db.close();

    const store = createSqliteAdapter(path);

    expect(await store.findOne('user', { id: 'usr_1' })).toEqual(user);
    expect(await store.update('user', { id: 'usr_1', wrongCodes: 0 }, { wrongCodes: 1 })).toBe(1);
    expect(await store.create('setting', { id: 'methods', value: '{}', updatedAt: 1, updatedBy: null })).toBe(true);
    expect(await store.create('apiKey', { id: 'key_1', userId: 'usr_1', hash: 'h', name: 'k', scopes: 'orders:read', createdAt: 1, expiresAt: null, lastUsedAt: 0 })).toBe(true);
    // An account from before version 5 reads as if no authenticator code was ever used, before 6 has no phone,
    // and before 7 doesn't say whether it is the user's sign-in method.
    expect(await store.findOne('account', { id: 'acc_1' })).toMatchObject({ email: null, lastUsedStep: 0, setupId: null, phone: null, primaryUserId: null, secondFactor: null, name: null, credentialId: null });
    expect(await store.update('account', { id: 'acc_1', lastUsedStep: 0 }, { lastUsedStep: 7 })).toBe(1);
    expect(await store.update('account', { id: 'acc_1' }, { phone: '+41791234567' })).toBe(1);
    expect(await store.findOne('account', { id: 'acc_1' })).toMatchObject({ phone: '+41791234567' });
    expect(await store.create('recoveryCode', { id: 'hash', userId: 'usr_1', setupId: 'tsu_1', createdAt: 1 })).toBe(true);
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
        expect(sql).toContain(`CREATE TABLE ${tableName(model)} (`);
        for (const field of Object.keys(fields)) expect(sql).toContain(`  ${columnName(field)} `);
      }
      expect(sql).toMatch(/email_normalized \S+ NOT NULL UNIQUE/);
      expect(sql).toContain('CREATE INDEX madauth_account_user_id ON madauth_account (user_id);');
    }
    expect(createTablesSql('mysql')).toContain('email_normalized VARCHAR(255) NOT NULL UNIQUE');
    expect(createTablesSql('postgres')).toContain('email_verified BOOLEAN NOT NULL');
  });

  it('upgradeTablesSql lists what newer schema versions added, per dialect', () => {
    const V10 = 'CREATE TABLE madauth_api_key (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  hash TEXT NOT NULL UNIQUE,\n  name TEXT NOT NULL,\n  scopes TEXT NOT NULL,\n  created_at DOUBLE PRECISION NOT NULL,\n  expires_at DOUBLE PRECISION,\n  last_used_at DOUBLE PRECISION NOT NULL\n);\nCREATE INDEX madauth_api_key_user_id ON madauth_api_key (user_id);';
    const V9 = 'ALTER TABLE madauth_user ADD COLUMN sign_up_method TEXT;\n' + V10;
    const V8 =
      'ALTER TABLE madauth_account ADD COLUMN name TEXT;\n' +
      'ALTER TABLE madauth_account ADD COLUMN credential_id TEXT;\n' +
      'ALTER TABLE madauth_account ADD COLUMN sign_count DOUBLE PRECISION;\n' +
      'ALTER TABLE madauth_account ADD COLUMN transports TEXT;\n' +
      'ALTER TABLE madauth_account ADD COLUMN last_used_at DOUBLE PRECISION;\n' +
      'ALTER TABLE madauth_account ADD COLUMN rp_id TEXT;\n' +
      V9;
    const V7 =
      'ALTER TABLE madauth_user ADD COLUMN signed_up_at DOUBLE PRECISION;\n' +
      'ALTER TABLE madauth_account ADD COLUMN primary_user_id TEXT;\n' +
      'CREATE UNIQUE INDEX madauth_account_primary_user_id ON madauth_account (primary_user_id);\n' +
      'ALTER TABLE madauth_account ADD COLUMN second_factor BOOLEAN;\n' +
      V8;
    expect(upgradeTablesSql('postgres', 1).split('\n')[0]).toBe('ALTER TABLE madauth_user ADD COLUMN wrong_codes DOUBLE PRECISION NOT NULL DEFAULT 0;');
    expect(upgradeTablesSql('mysql', 1).split('\n')[0]).toBe('ALTER TABLE madauth_user ADD COLUMN wrong_codes DOUBLE NOT NULL DEFAULT 0;');
    expect(upgradeTablesSql('mysql', 2).split('\n')[0]).toBe('CREATE TABLE madauth_role (');
    // Version 4 replaced the role table with claims on the user and added settings.
    expect(upgradeTablesSql('postgres', 3).split('\n').slice(0, 4).join('\n')).toBe(
      'ALTER TABLE madauth_user ADD COLUMN claims TEXT;\n' +
        'ALTER TABLE madauth_account ADD COLUMN email TEXT;\n' +
        'DROP TABLE madauth_role;\n' +
        'CREATE TABLE madauth_setting (',
    );
    // Version 5 added the authenticator app: the last used code on the account, and recovery codes.
    expect(upgradeTablesSql('postgres', 4)).toBe(
      'ALTER TABLE madauth_account ADD COLUMN last_used_step DOUBLE PRECISION NOT NULL DEFAULT 0;\n' +
        'ALTER TABLE madauth_account ADD COLUMN setup_id TEXT;\n' +
        'CREATE TABLE madauth_recovery_code (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  setup_id TEXT NOT NULL,\n  created_at DOUBLE PRECISION NOT NULL\n);\n' +
        'CREATE INDEX madauth_recovery_code_user_id ON madauth_recovery_code (user_id);\n' +
        'ALTER TABLE madauth_account ADD COLUMN phone TEXT;\n' +
        'ALTER TABLE madauth_user ADD COLUMN last_sms_at DOUBLE PRECISION;\n' +
        V7,
    );
    expect(upgradeTablesSql('mysql', 4).split('\n')[0]).toBe('ALTER TABLE madauth_account ADD COLUMN last_used_step DOUBLE NOT NULL DEFAULT 0;');
    // Version 6 added SMS codes: the phone number on the account, and when the last SMS went to a user.
    expect(upgradeTablesSql('postgres', 5)).toBe('ALTER TABLE madauth_account ADD COLUMN phone TEXT;\nALTER TABLE madauth_user ADD COLUMN last_sms_at DOUBLE PRECISION;\n' + V7);
    // Version 7 added when a sign-up was complete, and which account is the user's one sign-in method: a
    // unique index, since SQLite can't add a UNIQUE column, and on a fixed-length string for MySQL.
    expect(upgradeTablesSql('postgres', 6)).toBe(V7);
    expect(upgradeTablesSql('mysql', 6).split('\n')[1]).toBe('ALTER TABLE madauth_account ADD COLUMN primary_user_id VARCHAR(255);');
    // Version 8 added passkeys: their name, credential id, counter, transports and last use.
    expect(upgradeTablesSql('postgres', 7)).toBe(V8);
    // Version 9 added the method a pending sign-up confirms its address for.
    expect(upgradeTablesSql('postgres', 8)).toBe(V9);
    expect(upgradeTablesSql('mysql', 8).split('\n')[0]).toBe('ALTER TABLE madauth_user ADD COLUMN sign_up_method TEXT;');
    // Version 10 added API keys.
    expect(upgradeTablesSql('postgres', 9)).toBe(V10);
    expect(upgradeTablesSql('mysql', 9).split('\n')[1]).toBe('  id VARCHAR(255) PRIMARY KEY,');
    expect(upgradeTablesSql('sqlite', madauthSchema.version)).toBe('');
  });

  it('P8: the SQLite output runs', () => {
    const db = new DatabaseSync(':memory:');
    db.exec(createTablesSql('sqlite'));

    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((r) => r.name);
    expect(tables).toEqual(['madauth_account', 'madauth_api_key', 'madauth_recovery_code', 'madauth_setting', 'madauth_user', 'madauth_verification']);
  });
});
