/** A value of a record field. */
export type Value = string | number | boolean | null;

/** A record: field name → value. Field names are the camelCase names from {@link madauthSchema}. */
export type Row = Record<string, Value>;

/** Filter: every field must equal the given value (`null` matches empty fields). */
export type Where = Record<string, Value>;

/**
 * Stores madAuth's records in a database. madAuth does all the security work (hashing, throttling,
 * single-use links); an adapter only stores the models of {@link madauthSchema}.
 *
 * Check an implementation with `storeAdapterContract` from `@madauth/server/testing`.
 */
export interface StoreAdapter {
  /** Inserts a record. Resolves to false and writes nothing if a `unique` or primary-key value already exists. */
  create(model: string, data: Row): Promise<boolean>;
  findOne(model: string, where: Where): Promise<Row | null>;
  findMany(model: string, where: Where, opts?: { limit?: number }): Promise<Row[]>;
  /** Changes the given fields of the matching records. Resolves to the number of records changed. */
  update(model: string, where: Where, patch: Row): Promise<number>;
  /**
   * Deletes the matching records. Resolves to the number of records deleted; madAuth relies on this count
   * to use a link or code only once, so it must be exact when two requests delete the same record.
   */
  delete(model: string, where: Where): Promise<number>;
}

export type FieldType = 'string' | 'number' | 'boolean';

export interface FieldDef {
  type: FieldType;
  primaryKey?: boolean;
  unique?: boolean;
  /** Looked up often, so it should have an index. */
  index?: boolean;
  nullable?: boolean;
}

export interface Schema {
  /** Increases with every change to the models. */
  version: number;
  models: Record<string, { fields: Record<string, FieldDef> }>;
}

/** The records madAuth stores. Timestamps are milliseconds since 1970. */
export const madauthSchema = {
  version: 1,
  models: {
    user: {
      fields: {
        id: { type: 'string', primaryKey: true },
        email: { type: 'string' },
        emailNormalized: { type: 'string', unique: true },
        emailVerified: { type: 'boolean' },
        name: { type: 'string', nullable: true },
        sessionVersion: { type: 'number' },
        lastMailAt: { type: 'number' },
        createdAt: { type: 'number' },
      },
    },
    /** How a user signs in. `key` is e.g. `password:<userId>`; later `google:<sub>` or `totp:<userId>`. */
    account: {
      fields: {
        id: { type: 'string', primaryKey: true },
        userId: { type: 'string', index: true },
        key: { type: 'string', unique: true },
        secret: { type: 'string', nullable: true },
        failedAttempts: { type: 'number' },
        lockedUntil: { type: 'number' },
        createdAt: { type: 'number' },
      },
    },
    /** A pending e-mail verification or password reset. `id` is the SHA-256 of the link token. */
    verification: {
      fields: {
        id: { type: 'string', primaryKey: true },
        userId: { type: 'string', index: true },
        purpose: { type: 'string' },
        codeHash: { type: 'string' },
        attempts: { type: 'number' },
        expiresAt: { type: 'number' },
      },
    },
  },
} as const satisfies Schema;

/** The SQL table that holds a model, e.g. `madauth_user`. */
export function tableName(model: string): string {
  return `madauth_${model}`;
}

/** The SQL column that holds a field, e.g. `email_normalized` for `emailNormalized`. */
export function columnName(field: string): string {
  return field.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}

export type SqlDialect = 'sqlite' | 'postgres' | 'mysql';

const columnTypes: Record<SqlDialect, Record<FieldType, string>> = {
  sqlite: { string: 'TEXT', number: 'INTEGER', boolean: 'INTEGER' },
  // DOUBLE PRECISION keeps numbers as JavaScript numbers in most Postgres drivers (BIGINT often becomes a string).
  postgres: { string: 'TEXT', number: 'DOUBLE PRECISION', boolean: 'BOOLEAN' },
  mysql: { string: 'TEXT', number: 'DOUBLE', boolean: 'BOOLEAN' },
};

/** The SQL that creates madAuth's tables and indexes in an empty database. */
export function createTablesSql(dialect: SqlDialect, schema: Schema = madauthSchema): string {
  const statements: string[] = [];
  for (const [model, { fields }] of Object.entries(schema.models)) {
    const table = tableName(model);
    const columns = Object.entries(fields).map(([field, def]) => {
      // MySQL can only index or constrain strings of a fixed maximum length.
      const keyed = def.primaryKey || def.unique || def.index;
      const type = dialect === 'mysql' && def.type === 'string' && keyed ? 'VARCHAR(255)' : columnTypes[dialect][def.type];
      const constraints = def.primaryKey ? ' PRIMARY KEY' : `${def.nullable ? '' : ' NOT NULL'}${def.unique ? ' UNIQUE' : ''}`;
      return `  ${columnName(field)} ${type}${constraints}`;
    });
    statements.push(`CREATE TABLE ${table} (\n${columns.join(',\n')}\n);`);
    for (const [field, def] of Object.entries(fields)) {
      if (def.index) statements.push(`CREATE INDEX ${table}_${columnName(field)} ON ${table} (${columnName(field)});`);
    }
  }
  return statements.join('\n');
}
