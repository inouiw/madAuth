// A store adapter built only on madAuth's public API, exactly as a custom adapter would be.
// Published as `@madauth/server/sqlite`; read it as the reference when writing your own.
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';
import { madauthSchema, type FieldDef, type Row, type StoreAdapter, type Value, type Where } from './schema.js';
import { columnName, createTablesSql, tableName, upgradeTablesSql } from './sql.js';

/**
 * Stores madAuth's records in a SQLite file using Node's built-in `node:sqlite` (Node 22.13 or newer).
 * Creates the tables on first use. Pass `':memory:'` for a database that lives only in memory.
 */
export function createSqliteAdapter(path: string): StoreAdapter {
  // Loaded on first use, so importing madAuth works on runtimes without node:sqlite.
  const { DatabaseSync } = process.getBuiltinModule('node:sqlite') as typeof import('node:sqlite');
  const db: DatabaseSync = new DatabaseSync(path);
  db.exec('PRAGMA busy_timeout = 5000');
  if (path !== ':memory:') db.exec('PRAGMA journal_mode = WAL');
  migrate(db);

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

  const toSql = (value: Value): SQLInputValue => (typeof value === 'boolean' ? (value ? 1 : 0) : value);

  const whereSql = (fields: Record<string, FieldDef>, where: Where): { sql: string; params: SQLInputValue[] } => {
    const parts: string[] = [];
    const params: SQLInputValue[] = [];
    for (const [field, value] of Object.entries(where)) {
      if (value === null) {
        parts.push(`${column(fields, field)} IS NULL`);
      } else {
        parts.push(`${column(fields, field)} = ?`);
        params.push(toSql(value));
      }
    }
    return { sql: parts.length ? ` WHERE ${parts.join(' AND ')}` : '', params };
  };

  const fromSql = (fields: Record<string, FieldDef>, raw: Record<string, unknown>): Row => {
    const row: Row = {};
    for (const [field, def] of Object.entries(fields)) {
      const value = raw[columnName(field)] as Value;
      row[field] = def.type === 'boolean' && value !== null ? value === 1 : value;
    }
    return row;
  };

  return {
    async create(model, data) {
      const fields = fieldsOf(model);
      const names = Object.keys(data);
      const sql =
        `INSERT INTO ${tableName(model)} (${names.map((f) => column(fields, f)).join(', ')}) ` +
        `VALUES (${names.map(() => '?').join(', ')}) ON CONFLICT DO NOTHING`;
      return Number(db.prepare(sql).run(...names.map((f) => toSql(data[f]))).changes) === 1;
    },

    async findOne(model, where) {
      const fields = fieldsOf(model);
      const w = whereSql(fields, where);
      const raw = db.prepare(`SELECT * FROM ${tableName(model)}${w.sql} LIMIT 1`).get(...w.params);
      return raw ? fromSql(fields, raw) : null;
    },

    async findMany(model, where, opts = {}) {
      const fields = fieldsOf(model);
      const w = whereSql(fields, where);
      const limit = opts.limit === undefined ? '' : ` LIMIT ${Math.max(0, Math.floor(opts.limit))}`;
      return db
        .prepare(`SELECT * FROM ${tableName(model)}${w.sql}${limit}`)
        .all(...w.params)
        .map((raw) => fromSql(fields, raw));
    },

    async update(model, where, patch) {
      const fields = fieldsOf(model);
      const names = Object.keys(patch);
      if (!names.length) return 0;
      const w = whereSql(fields, where);
      const sql = `UPDATE ${tableName(model)} SET ${names.map((f) => `${column(fields, f)} = ?`).join(', ')}${w.sql}`;
      return Number(db.prepare(sql).run(...names.map((f) => toSql(patch[f])), ...w.params).changes);
    },

    async delete(model, where) {
      const fields = fieldsOf(model);
      const w = whereSql(fields, where);
      return Number(db.prepare(`DELETE FROM ${tableName(model)}${w.sql}`).run(...w.params).changes);
    },
  };
}

/** Creates the tables in a new database and upgrades an older one; refuses a database written by a newer madAuth. */
function migrate(db: DatabaseSync): void {
  const { user_version: version } = db.prepare('PRAGMA user_version').get() as { user_version: number };
  if (version > madauthSchema.version) {
    throw new Error(
      `The database uses madAuth schema version ${version}, but this madAuth only knows version ` +
        `${madauthSchema.version}. Update madAuth.`,
    );
  }
  if (version === madauthSchema.version) return;
  db.exec('BEGIN');
  try {
    // Version 0 is an empty database.
    db.exec(version === 0 ? createTablesSql('sqlite') : upgradeTablesSql('sqlite', version));
    db.exec(`PRAGMA user_version = ${madauthSchema.version}`);
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}
