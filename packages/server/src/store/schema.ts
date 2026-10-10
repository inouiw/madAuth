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
  version: 5,
  models: {
    /** Someone who signed in, whichever way: the e-mail address is the identity shared by the sign-in methods. */
    user: {
      fields: {
        id: { type: 'string', primaryKey: true },
        email: { type: 'string' },
        emailNormalized: { type: 'string', unique: true },
        emailVerified: { type: 'boolean' },
        name: { type: 'string', nullable: true },
        sessionVersion: { type: 'number' },
        lastMailAt: { type: 'number' },
        /** Wrong e-mail codes in a row, counted across e-mails (since version 2). */
        wrongCodes: { type: 'number' },
        /** What admins attached to the user, as JSON, e.g. `{"roles":["admin"]}` (since version 4). */
        claims: { type: 'string', nullable: true },
        createdAt: { type: 'number' },
      },
    },
    /**
     * How a user signs in. `key` is `password:<userId>`, `google:<sub>` or `totp:<userId>` (the authenticator
     * app, whose `secret` is encrypted).
     */
    account: {
      fields: {
        id: { type: 'string', primaryKey: true },
        userId: { type: 'string', index: true },
        key: { type: 'string', unique: true },
        secret: { type: 'string', nullable: true },
        failedAttempts: { type: 'number' },
        lockedUntil: { type: 'number' },
        /** The address the provider reported at the last sign-in, e.g. Google's current primary address (since version 4). */
        email: { type: 'string', nullable: true },
        /** The time step of the last authenticator code that was accepted, so a code works once; 0 before (since version 5). */
        lastUsedStep: { type: 'number' },
        createdAt: { type: 'number' },
      },
    },
    /** A recovery code of a user's authenticator app (since version 5). `id` is the code's keyed hash; the record goes when the code is used. */
    recoveryCode: {
      fields: {
        id: { type: 'string', primaryKey: true },
        userId: { type: 'string', index: true },
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
    /** A setting admins change at runtime, as JSON (since version 4), e.g. `methods`: which sign-in methods are on. */
    setting: {
      fields: {
        id: { type: 'string', primaryKey: true },
        value: { type: 'string' },
        updatedAt: { type: 'number' },
        /** The address of the admin who set it; empty when set from the command line. */
        updatedBy: { type: 'string', nullable: true },
      },
    },
  },
} as const satisfies Schema;
