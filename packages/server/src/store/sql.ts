// Helpers for adapters that store madAuth's records in an SQL database. The schema itself (schema.ts) is
// independent of how the records are stored.
import { madauthSchema, type FieldDef, type FieldType, type Schema } from './schema.js';

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

/** The SQL type of a field. MySQL can only index or constrain strings of a fixed maximum length. */
function columnType(dialect: SqlDialect, def: FieldDef): string {
  const keyed = def.primaryKey || def.unique || def.index;
  return dialect === 'mysql' && def.type === 'string' && keyed ? 'VARCHAR(255)' : columnTypes[dialect][def.type];
}

/** The client model as version 12 created it: without `deviceFlow` (version 13) and `tokenExchange` (version 14). */
const { deviceFlow: _deviceFlow, tokenExchange: _tokenExchange, idTokenAlg: _idTokenAlg, ...oidcClientFieldsV12 } = madauthSchema.models.oidcClient.fields;

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
        `ALTER TABLE ${tableName('account')} ADD COLUMN ${columnName('setupId')} ${columnTypes[dialect].string};`,
        createTablesSql(dialect, { version: 5, models: { recoveryCode: madauthSchema.models.recoveryCode } }),
      ].join('\n'),
  },
  {
    // SMS codes as a second factor: the phone number of an sms account, and when the last SMS went to a user.
    version: 6,
    sql: (dialect) =>
      [
        `ALTER TABLE ${tableName('account')} ADD COLUMN ${columnName('phone')} ${columnTypes[dialect].string};`,
        `ALTER TABLE ${tableName('user')} ADD COLUMN ${columnName('lastSmsAt')} ${columnTypes[dialect].number};`,
      ].join('\n'),
  },
  {
    // One primary sign-in method per user, which accounts are second factors, and when a user's sign-up was
    // complete. Older records stay empty: madAuth tells them apart by the account's key, and counts their
    // sign-up as complete.
    version: 7,
    sql: (dialect) =>
      [
        `ALTER TABLE ${tableName('user')} ADD COLUMN ${columnName('signedUpAt')} ${columnTypes[dialect].number};`,
        // SQLite can't add a UNIQUE column, so the constraint is an index.
        `ALTER TABLE ${tableName('account')} ADD COLUMN ${columnName('primaryUserId')} ${columnType(dialect, madauthSchema.models.account.fields.primaryUserId)};`,
        `CREATE UNIQUE INDEX ${tableName('account')}_${columnName('primaryUserId')} ON ${tableName('account')} (${columnName('primaryUserId')});`,
        `ALTER TABLE ${tableName('account')} ADD COLUMN ${columnName('secondFactor')} ${columnType(dialect, madauthSchema.models.account.fields.secondFactor)};`,
      ].join('\n'),
  },
  {
    // Passkeys: their name, credential id, signature counter, transports and last use.
    version: 8,
    sql: (dialect) =>
      (['name', 'credentialId', 'signCount', 'transports', 'lastUsedAt', 'rpId'] as const)
        .map((field) => `ALTER TABLE ${tableName('account')} ADD COLUMN ${columnName(field)} ${columnType(dialect, madauthSchema.models.account.fields[field])};`)
        .join('\n'),
  },
  {
    // The method a pending sign-up confirms its address for.
    version: 9,
    sql: (dialect) => `ALTER TABLE ${tableName('user')} ADD COLUMN ${columnName('signUpMethod')} ${columnType(dialect, madauthSchema.models.user.fields.signUpMethod)};`,
  },
  {
    // API keys.
    version: 10,
    sql: (dialect) => createTablesSql(dialect, { version: 10, models: { apiKey: madauthSchema.models.apiKey } }),
  },
  {
    // The second factor a user wants to be asked for first.
    version: 11,
    sql: (dialect) => `ALTER TABLE ${tableName('user')} ADD COLUMN ${columnName('preferredSecondFactor')} ${columnType(dialect, madauthSchema.models.user.fields.preferredSecondFactor)};`,
  },
  {
    // madAuth as an OpenID Connect provider: its clients, authorization codes and refresh tokens.
    version: 12,
    sql: (dialect) =>
      createTablesSql(dialect, {
        version: 12,
        models: { oidcClient: { fields: oidcClientFieldsV12 }, oidcCode: madauthSchema.models.oidcCode, oidcRefreshToken: madauthSchema.models.oidcRefreshToken },
      }),
  },
  {
    // The device authorization grant: which clients may use it, a device's pending sign-ins, and the wrong codes a user typed.
    version: 13,
    sql: (dialect) =>
      [
        `ALTER TABLE ${tableName('oidcClient')} ADD COLUMN ${columnName('deviceFlow')} ${columnType(dialect, madauthSchema.models.oidcClient.fields.deviceFlow)};`,
        `ALTER TABLE ${tableName('user')} ADD COLUMN ${columnName('wrongDeviceCodes')} ${columnType(dialect, madauthSchema.models.user.fields.wrongDeviceCodes)};`,
        `ALTER TABLE ${tableName('user')} ADD COLUMN ${columnName('wrongDeviceCodeAt')} ${columnType(dialect, madauthSchema.models.user.fields.wrongDeviceCodeAt)};`,
        createTablesSql(dialect, { version: 13, models: { oidcDeviceCode: madauthSchema.models.oidcDeviceCode } }),
      ].join('\n'),
  },
  {
    // The token exchange: which clients may use it, and its nonces.
    version: 14,
    sql: (dialect) =>
      [
        `ALTER TABLE ${tableName('oidcClient')} ADD COLUMN ${columnName('tokenExchange')} ${columnType(dialect, madauthSchema.models.oidcClient.fields.tokenExchange)};`,
        createTablesSql(dialect, { version: 14, models: { oidcNonce: madauthSchema.models.oidcNonce } }),
      ].join('\n'),
  },
  {
    // RS256 ID tokens: the algorithm each client gets its ID tokens in.
    version: 15,
    sql: (dialect) => `ALTER TABLE ${tableName('oidcClient')} ADD COLUMN ${columnName('idTokenAlg')} ${columnType(dialect, madauthSchema.models.oidcClient.fields.idTokenAlg)};`,
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
      const type = columnType(dialect, def);
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
