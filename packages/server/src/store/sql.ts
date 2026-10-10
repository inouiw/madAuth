// Helpers for adapters that store madAuth's records in an SQL database. The schema itself (schema.ts) is
// independent of how the records are stored.
import { madauthSchema, type FieldType, type Schema } from './schema.js';

/** The SQL table that holds a model, e.g. `madauth_user`, or `madauth_recovery_code` for `recoveryCode`. */
export function tableName(model: string): string {
  return `madauth_${columnName(model)}`;
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

/** What each schema version after the first one added, as SQL for tables created by an older version. */
const upgrades: { version: number; sql: (dialect: SqlDialect) => string }[] = [
  {
    version: 2,
    sql: (dialect) =>
      `ALTER TABLE ${tableName('user')} ADD COLUMN ${columnName('wrongCodes')} ${columnTypes[dialect].number} NOT NULL DEFAULT 0;`,
  },
  {
    // Roles were per e-mail address in their own table; since version 4 they are one of the user's claims.
    version: 3,
    sql: (dialect) =>
      createTablesSql(dialect, {
        version: 3,
        models: {
          role: {
            fields: {
              id: { type: 'string', primaryKey: true },
              roles: { type: 'string' },
              updatedAt: { type: 'number' },
              updatedBy: { type: 'string', nullable: true },
            },
          },
        },
      }),
  },
  {
    version: 4,
    sql: (dialect) =>
      [
        `ALTER TABLE ${tableName('user')} ADD COLUMN ${columnName('claims')} ${columnTypes[dialect].string};`,
        `ALTER TABLE ${tableName('account')} ADD COLUMN ${columnName('email')} ${columnTypes[dialect].string};`,
        `DROP TABLE ${tableName('role')};`,
        createTablesSql(dialect, { version: 4, models: { setting: madauthSchema.models.setting } }),
      ].join('\n'),
  },
  {
    // The authenticator app: which code was used last, and the recovery codes.
    version: 5,
    sql: (dialect) =>
      [
        `ALTER TABLE ${tableName('account')} ADD COLUMN ${columnName('lastUsedStep')} ${columnTypes[dialect].number} NOT NULL DEFAULT 0;`,
        createTablesSql(dialect, { version: 5, models: { recoveryCode: madauthSchema.models.recoveryCode } }),
      ].join('\n'),
  },
];

/**
 * The SQL that brings tables created for schema version `fromVersion` up to date. Empty if they are.
 * Run it before you start the madAuth version that needs it; older madAuth versions ignore the additions.
 */
export function upgradeTablesSql(dialect: SqlDialect, fromVersion: number): string {
  return upgrades
    .filter((step) => step.version > fromVersion)
    .map((step) => step.sql(dialect))
    .join('\n');
}

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
