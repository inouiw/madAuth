import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { schemaV1 } from '../test/schema-v1.js';
import { storeAdapterContract } from '../testing.js';
import { openPostgresAdapter, type PostgresAdapter, type PostgresAdapterOptions } from './postgres.js';
import { madauthSchema } from './schema.js';
import { createTablesSql } from './sql.js';

// These tests need a database. Start Postgres and point the tests to it:
//   docker run --rm -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17
//   POSTGRES_TEST_URL=postgres://postgres:postgres@localhost:5432/postgres npm test
// Each test works in a schema of its own, which is dropped at the end.
const url = process.env.POSTGRES_TEST_URL;

describe.skipIf(!url)('Postgres adapter with a database', () => {
  const admin = new pg.Client({ connectionString: url });
  const schemas: string[] = [];
  const adapters: PostgresAdapter[] = [];

  beforeAll(async () => {
    await admin.connect();
  });

  afterAll(async () => {
    await Promise.all(adapters.map((adapter) => adapter.close()));
    for (const schema of schemas) await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  /** A new, empty schema. */
  const freshSchema = async (): Promise<string> => {
    const schema = `madauth_test_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    await admin.query(`CREATE SCHEMA ${schema}`);
    schemas.push(schema);
    return schema;
  };

  /** Runs SQL (without parameters) in a schema. */
  const sqlIn = async (schema: string, sql: string): Promise<Record<string, unknown>[]> => {
    const results = await admin.query(`SET search_path TO ${schema}; ${sql}`);
    return (Array.isArray(results) ? results.at(-1)! : results).rows;
  };

  /** Opens the adapter on a schema, and closes it at the end. */
  const open = async (schema: string, options: PostgresAdapterOptions = {}): Promise<PostgresAdapter> => {
    const adapter = await openPostgresAdapter(url!, { ...options, pool: { options: `-c search_path=${schema}`, ...options.pool } });
    adapters.push(adapter);
    return adapter;
  };

  const tableExists = async (schema: string, table: string): Promise<boolean> =>
    (await sqlIn(schema, `SELECT to_regclass('${table}') IS NOT NULL AS found`))[0].found as boolean;

  let shared: Promise<PostgresAdapter> | undefined;
  // P4: the built-in adapter is checked with the same contract as a custom one, on one adapter for all its tests.
  storeAdapterContract({ describe, it, expect }, () => (shared ??= freshSchema().then((schema) => open(schema))));

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

  it('creates the tables in an empty database and records their version; opening it again changes nothing', async () => {
    const schema = await freshSchema();

    const store = await open(schema);
    await store.create('user', user);
    const reopened = await open(schema);

    expect(await sqlIn(schema, 'SELECT version FROM madauth_schema')).toEqual([{ version: madauthSchema.version }]);
    expect(await reopened.findOne('user', { id: 'usr_1' })).toEqual(user);
  });

  it('lets several instances start at once: one creates the tables, the others wait and find them', async () => {
    const schema = await freshSchema();

    const stores = await Promise.all([open(schema), open(schema), open(schema)]);

    expect(await sqlIn(schema, 'SELECT version FROM madauth_schema')).toEqual([{ version: madauthSchema.version }]);
    expect(await stores[0].create('user', user)).toBe(true);
    expect(await stores[2].findOne('user', { id: 'usr_1' })).toEqual(user);
  });

  it('upgrades a database written by an older madAuth and keeps its records', async () => {
    const schema = await freshSchema();
    await sqlIn(
      schema,
      [
        createTablesSql('postgres', schemaV1),
        "INSERT INTO madauth_user VALUES ('usr_1', 'Ada@example.com', 'ada@example.com', TRUE, 'Ada', 0, 0, 1);",
        "INSERT INTO madauth_account VALUES ('acc_1', 'usr_1', 'password:usr_1', 'hash', 0, 0, 1);",
        'CREATE TABLE madauth_schema (version INTEGER NOT NULL);',
        'INSERT INTO madauth_schema VALUES (1);',
      ].join('\n'),
    );

    const store = await open(schema);

    expect(await sqlIn(schema, 'SELECT version FROM madauth_schema')).toEqual([{ version: madauthSchema.version }]);
    expect(await store.findOne('user', { id: 'usr_1' })).toEqual(user);
    expect(await store.update('user', { id: 'usr_1', wrongCodes: 0 }, { wrongCodes: 1 })).toBe(1);
    expect(await store.findOne('account', { id: 'acc_1' })).toMatchObject({ email: null, lastUsedStep: 0, primaryUserId: null, secondFactor: null });
    expect(await store.create('apiKey', { id: 'key_1', userId: 'usr_1', hash: 'h', name: 'k', scopes: 'orders:read', createdAt: 1, expiresAt: null, lastUsedAt: 0 })).toBe(true);
  });

  it('P5: refuses a database written by a newer madAuth', async () => {
    const schema = await freshSchema();
    await sqlIn(schema, `CREATE TABLE madauth_schema (version INTEGER NOT NULL); INSERT INTO madauth_schema VALUES (${madauthSchema.version + 1});`);

    await expect(open(schema)).rejects.toThrow(/Update madAuth/);
  });

  it('refuses madAuth tables without a recorded version, and says how to record it', async () => {
    const schema = await freshSchema();
    await sqlIn(schema, createTablesSql('postgres'));

    await expect(open(schema)).rejects.toThrow(/no madauth_schema table.*INSERT INTO madauth_schema/s);
  });

  it('refuses a recorded version whose tables are missing', async () => {
    const schema = await freshSchema();
    await sqlIn(schema, `CREATE TABLE madauth_schema (version INTEGER NOT NULL); INSERT INTO madauth_schema VALUES (${madauthSchema.version});`);

    await expect(open(schema)).rejects.toThrow(/tables are missing/);
    await expect(open(schema, { migrate: false })).rejects.toThrow(/tables are missing/);
  });

  it('with migrate false, changes no tables: refuses an empty or older database, opens an up-to-date one', async () => {
    const empty = await freshSchema();
    await expect(open(empty, { migrate: false })).rejects.toThrow(/no madAuth tables.*schema --dialect postgres/s);
    expect(await tableExists(empty, 'madauth_user')).toBe(false);
    expect(await tableExists(empty, 'madauth_schema')).toBe(false);

    const older = await freshSchema();
    await sqlIn(older, `${createTablesSql('postgres', schemaV1)} CREATE TABLE madauth_schema (version INTEGER NOT NULL); INSERT INTO madauth_schema VALUES (1);`);
    await expect(open(older, { migrate: false })).rejects.toThrow(/--from 1/);
    expect(await sqlIn(older, 'SELECT version FROM madauth_schema')).toEqual([{ version: 1 }]);

    const current = await freshSchema();
    await open(current);
    const store = await open(current, { migrate: false });
    expect(await store.create('user', user)).toBe(true);
  });

  it('survives a failover: a connection that dies while idle is replaced, without ending the process', async () => {
    const schema = await freshSchema();
    const applicationName = `madauth_failover_${schema}`;
    const store = await open(schema, { pool: { application_name: applicationName } });
    await store.create('user', user);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

    const killed = await admin.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1', [applicationName]);
    expect(killed.rowCount).toBeGreaterThan(0);
    await vi.waitFor(() => expect(logged).toHaveBeenCalledWith(expect.stringContaining('the next query opens a new one')));
    logged.mockRestore();

    expect(await store.findOne('user', { id: 'usr_1' })).toEqual(user);
  });

  it('rejects models and fields that are not in the schema', async () => {
    const store = await (shared ??= freshSchema().then((schema) => open(schema)));

    await expect(store.findOne('user; DROP TABLE madauth_user', {})).rejects.toThrow(/Unknown model/);
    await expect(store.findOne('user', { 'id = id OR 1': 1 })).rejects.toThrow(/Unknown field/);
  });
});

describe('Postgres adapter', () => {
  it('rejects an unreachable database when it is opened', async () => {
    await expect(openPostgresAdapter('postgres://madauth:secret@127.0.0.1:1/madauth')).rejects.toThrow(/ECONNREFUSED/);
  });
  it('P6: is built only on the public API, like a custom adapter', () => {
    const source = readFileSync(new URL('./postgres.ts', import.meta.url), 'utf8');
    const imports = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]);

    expect(imports.sort()).toEqual(['./schema.js', './sql.js', 'pg']);
    // Only type imports from pg: the package is loaded when the adapter is opened.
    expect(source).toMatch(/import type \{[^}]*\} from 'pg'/);
  });
});
