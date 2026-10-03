// Helpers for adapters that store madAuth's records in an SQL database. The schema itself (schema.ts) is
// independent of how the records are stored.
import { madauthSchema, type FieldType, type Schema } from './schema.js';

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
