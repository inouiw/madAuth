// A store adapter for PostgreSQL, built only on madAuth's public API, exactly as a custom adapter would be.
// Published as `@madauth/server/postgres`. It needs the `pg` package (node-postgres).
//
// The tables are the ones `createTablesSql('postgres')` creates. The schema version they have is kept in the
// table `madauth_schema`; opening the adapter creates or upgrades the tables under an advisory lock, so several
// instances can start at the same time.
import type { Pool, PoolClient, PoolConfig } from 'pg';
import { madauthSchema, type FieldDef, type Row, type StoreAdapter, type Value, type Where } from './schema.js';
import { columnName, createTablesSql, tableName, upgradeTablesSql } from './sql.js';

export interface PostgresAdapterOptions {
  /**
   * Default true: create the tables in an empty database and upgrade older ones. False: only check that the
   * tables are up to date, for a database user that may not change tables (see "Postgres" in docs/server.md).
   */
  migrate?: boolean;
  /** Further settings of the connection pool, e.g. `max` (default 10) or `ssl`. */
  pool?: PoolConfig;
}

/** A Postgres store adapter; `close` ends its connections. */
export type PostgresAdapter = StoreAdapter & { close(): Promise<void> };

/** The table that holds the schema version of madAuth's tables, in one row. */
const VERSION_TABLE = 'madauth_schema';
/** The key of the advisory lock held while the tables are created or upgraded ("mada" in ASCII). */
const MIGRATION_LOCK = 0x6d616461;

/**
 * Connects to the Postgres database at `url` (`postgres://user:password@host:5432/database`), creates or
 * upgrades madAuth's tables, and resolves to the adapter. Rejects if the database can't be reached, was
 * written by a newer madAuth, or, with `migrate: false`, is not up to date.
 */
export async function openPostgresAdapter(url: string, options: PostgresAdapterOptions = {}): Promise<PostgresAdapter> {
  // Loaded here, so importing madAuth works without the pg package.
  const { Pool } = await import('pg');
  const pool: Pool = new Pool({ connectionString: url, keepAlive: true, connectionTimeoutMillis: 10_000, ...options.pool });
  // A connection that fails while idle, e.g. when the primary fails over, is dropped by the pool, which opens a
  // new one for the next query. Without a listener its error would end the process.
  pool.on('error', (e) => console.error(`[madauth] Postgres: an idle connection failed, the next query opens a new one: ${e.message}`));
  await migrate(pool, options.migrate ?? true).catch(async (e: unknown) => {
    await pool.end();
    throw e;
  });

  const fieldsOf = (model: string): Record<string, FieldDef> => {
    const fields = (madauthSchema.models as Record<string, { fields: Record<string, FieldDef> }>)[model]?.fields;
    if (!fields) throw new Error(`Unknown model "${model}"`);
    return fields;
  };

  // Only field names from the schema reach the SQL text; values are always bound parameters.
  const column = (fields: Record<string, FieldDef>, field: string): string => {
    if (!fields[field]) throw new Error(`Unknown field "${field}"`);
    return columnName(field);
  };

  /** The WHERE clause; its parameters are numbered from `first`. */
  const whereSql = (fields: Record<string, FieldDef>, where: Where, first = 1): { sql: string; params: Value[] } => {
    const parts: string[] = [];
    const params: Value[] = [];
    for (const [field, value] of Object.entries(where)) {
      if (value === null) {
        parts.push(`${column(fields, field)} IS NULL`);
      } else {
        params.push(value);
        parts.push(`${column(fields, field)} = $${first + params.length - 1}`);
      }
    }
    return { sql: parts.length ? ` WHERE ${parts.join(' AND ')}` : '', params };
  };

  const fromSql = (fields: Record<string, FieldDef>, raw: Record<string, unknown>): Row =>
    Object.fromEntries(Object.keys(fields).map((field) => [field, raw[columnName(field)] as Value]));

  const limitSql = (limit: number): string => ` LIMIT ${Math.max(0, Math.floor(limit))}`;

  // Every statement goes through pool.query, which drops a connection whose query failed. Nothing is retried:
  // a write sent again could count twice, e.g. a single-use code.
  const query = async (sql: string, params: Value[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number }> => {
    const result = await pool.query(sql, params);
    return { rows: result.rows, rowCount: result.rowCount ?? 0 };
  };

  return {
    async create(model, data) {
      const fields = fieldsOf(model);
      const names = Object.keys(data);
      const sql =
        `INSERT INTO ${tableName(model)} (${names.map((f) => column(fields, f)).join(', ')}) ` +
        `VALUES (${names.map((_, i) => `$${i + 1}`).join(', ')}) ON CONFLICT DO NOTHING`;
      return (await query(sql, names.map((f) => data[f]))).rowCount === 1;
    },

    async findOne(model, where) {
      const fields = fieldsOf(model);
      const w = whereSql(fields, where);
      const [raw] = (await query(`SELECT * FROM ${tableName(model)}${w.sql}${limitSql(1)}`, w.params)).rows;
      return raw ? fromSql(fields, raw) : null;
    },

    async findMany(model, where, opts = {}) {
      const fields = fieldsOf(model);
      const w = whereSql(fields, where);
      const limit = opts.limit === undefined ? '' : limitSql(opts.limit);
      return (await query(`SELECT * FROM ${tableName(model)}${w.sql}${limit}`, w.params)).rows.map((raw) => fromSql(fields, raw));
    },

    // A concurrent update of the same record waits for this one and then checks its WHERE again, so a filter
    // on the old value lets only one of them through.
    async update(model, where, patch) {
      const fields = fieldsOf(model);
      const names = Object.keys(patch);
      if (!names.length) return 0;
      const w = whereSql(fields, where, names.length + 1);
      const sql = `UPDATE ${tableName(model)} SET ${names.map((f, i) => `${column(fields, f)} = $${i + 1}`).join(', ')}${w.sql}`;
      return (await query(sql, [...names.map((f) => patch[f]), ...w.params])).rowCount;
    },

    async delete(model, where) {
      const fields = fieldsOf(model);
      const w = whereSql(fields, where);
      return (await query(`DELETE FROM ${tableName(model)}${w.sql}`, w.params)).rowCount;
    },

    // In the order of the primary key, so a page goes on after `after` whether or not that record still exists.
    async scan(model, { after, limit }) {
      const fields = fieldsOf(model);
      const id = column(fields, Object.keys(fields).find((field) => fields[field].primaryKey)!);
      const from = after === undefined ? '' : ` WHERE ${id} > $1`;
      return (await query(`SELECT * FROM ${tableName(model)}${from} ORDER BY ${id}${limitSql(limit)}`, after === undefined ? [] : [after])).rows.map(
        (raw) => fromSql(fields, raw),
      );
    },

    async close() {
      await pool.end();
    },
  };
}

/** The schema version of the tables: 0 without tables, null for madAuth tables without a recorded version. */
async function schemaVersion(db: Pick<PoolClient, 'query'>): Promise<number | null> {
  const { rows } = await db.query(
    `SELECT to_regclass('${VERSION_TABLE}') IS NOT NULL AS versioned, to_regclass('${tableName('user')}') IS NOT NULL AS tables`,
  );
  const { versioned, tables } = rows[0] as { versioned: boolean; tables: boolean };
  if (!versioned) return tables ? null : 0;
  const recorded = (await db.query(`SELECT version FROM ${VERSION_TABLE}`)).rows[0] as { version: number } | undefined;
  return recorded ? recorded.version : tables ? null : 0;
}

/**
 * Creates the tables in an empty database and upgrades older ones, in one transaction under an advisory lock:
 * an instance that starts at the same time waits, then finds the tables up to date. Refuses a database written
 * by a newer madAuth. With `allowed` false, only checks the version.
 */
async function migrate(pool: Pool, allowed: boolean): Promise<void> {
  if (!allowed) {
    checkVersion(await schemaVersion(pool), false);
    return;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT pg_advisory_xact_lock(${MIGRATION_LOCK})`);
    const version = checkVersion(await schemaVersion(client), true);
    if (version === 0) {
      await client.query(createTablesSql('postgres'));
      await client.query(`CREATE TABLE IF NOT EXISTS ${VERSION_TABLE} (version INTEGER NOT NULL)`);
      await client.query(`INSERT INTO ${VERSION_TABLE} (version) VALUES (${madauthSchema.version})`);
    } else if (version < madauthSchema.version) {
      await client.query(upgradeTablesSql('postgres', version));
      await client.query(`UPDATE ${VERSION_TABLE} SET version = ${madauthSchema.version}`);
    }
    await client.query('COMMIT');
    client.release();
  } catch (e) {
    // Closing the connection rolls the transaction back and releases the lock.
    client.release(true);
    throw e;
  }
}

/** The version, if madAuth can use the tables (after upgrading them, if `upgrade`); throws an explanation if not. */
function checkVersion(version: number | null, upgrade: boolean): number {
  const current = madauthSchema.version;
  if (version === null) {
    throw new Error(
      `The database has madAuth tables but no ${VERSION_TABLE} table with their schema version. Record the version ` +
        `they were created for (see "Postgres" in docs/server.md): CREATE TABLE ${VERSION_TABLE} (version INTEGER NOT NULL); ` +
        `INSERT INTO ${VERSION_TABLE} VALUES (<version>);`,
    );
  }
  if (version > current) {
    throw new Error(`The database uses madAuth schema version ${version}, but this madAuth only knows version ${current}. Update madAuth.`);
  }
  if (version < current && !upgrade) {
    throw new Error(
      version === 0
        ? `The database has no madAuth tables, and creating them is turned off. Create them with the SQL from ` +
            `"npx @madauth/server schema --dialect postgres", then CREATE TABLE ${VERSION_TABLE} (version INTEGER NOT NULL); ` +
            `INSERT INTO ${VERSION_TABLE} VALUES (${current});`
        : `The database uses madAuth schema version ${version}, this madAuth needs version ${current}, and upgrading ` +
            `is turned off. Run the SQL from "npx @madauth/server schema --dialect postgres --from ${version}", then ` +
            `UPDATE ${VERSION_TABLE} SET version = ${current};`,
    );
  }
  return version;
}
