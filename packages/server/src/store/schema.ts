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
  /**
   * The records of a model, a page at a time: at most `limit`, in an order the adapter chooses that stays the
   * same, starting after the record whose id is `after` (which may be gone by now), or at the first one.
   * Fewer than `limit` means there are no more. A record that exists for the whole scan is returned once;
   * one added or deleted meanwhile may be or not. madAuth scans only for admins, e.g. to search users.
   */
  scan(model: string, opts: { after?: string; limit: number }): Promise<Row[]>;
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
  version: 11,
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
        /** When the last e-mail was sent to the user: at most one per minute. */
        lastMailAt: { type: 'number' },
        /** When the last SMS was sent to the user: at most one per minute, counted apart from the e-mails (since version 6). */
        lastSmsAt: { type: 'number', nullable: true },
        /** Wrong e-mail codes in a row, counted across e-mails (since version 2). */
        wrongCodes: { type: 'number' },
        /** What admins attached to the user, as JSON, e.g. `{"roles":["admin"]}` (since version 4). */
        claims: { type: 'string', nullable: true },
        /**
         * When the user's first session started: the sign-up was complete, with every second factor the
         * policy asked for. 0 until then. Empty in records from before version 7, whose sign-up counts as
         * complete (since version 7).
         */
        signedUpAt: { type: 'number', nullable: true },
        /**
         * The method the user's pending sign-up confirms the address for: `password`, `authenticator` (the
         * authenticator app; `totp`, its id before 0.6, is read as `authenticator`) or `passkey`. Set by each
         * sign-up that sends a confirmation e-mail; the latest one wins. Empty in records from before version
         * 9 (since version 9).
         */
        signUpMethod: { type: 'string', nullable: true },
        /**
         * The second factor the user wants to be asked for first: `passkey`, `authenticator` or `sms`. Empty for
         * the usual order, and in records from before version 11 (since version 11).
         */
        preferredSecondFactor: { type: 'string', nullable: true },
        createdAt: { type: 'number' },
      },
    },
    /**
     * How a user signs in. `key` is `password:<userId>`, `google:<sub>`, `totp:<userId>` (the authenticator
     * app, whose `secret` is encrypted), `email-link:<userId>`, `sms:<userId>` (the phone that gets the
     * codes of the second factor) or `passkey:<hash of the credential id>` (one per passkey; `secret` is its
     * public key).
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
        /**
         * The setup an authenticator secret came from; its recovery codes carry the same id, so the app and
         * its codes always belong together. Empty for other accounts (since version 5).
         */
        setupId: { type: 'string', nullable: true },
        /** The phone number of an `sms:` account, in E.164 form (`+41791234567`). Empty for other accounts (since version 6). */
        phone: { type: 'string', nullable: true },
        /**
         * The user's id when the account is how they sign in (their one primary method), empty for a second
         * factor. Unique, so a user has one primary method at most (since version 7; empty in older records).
         */
        primaryUserId: { type: 'string', nullable: true, unique: true },
        /**
         * Whether the account is a second factor (an authenticator app that is a step of the user's sign-in
         * method, or a phone for SMS codes) rather than a sign-in method. Empty in records from before version 7,
         * which madAuth tells apart by their key (since version 7).
         */
        secondFactor: { type: 'boolean', nullable: true },
        /** A passkey's name, which the user can change. Empty for other accounts (since version 8). */
        name: { type: 'string', nullable: true },
        /** A passkey's credential id (base64url), which the browser asks the authenticator for. Empty for other accounts (since version 8). */
        credentialId: { type: 'string', nullable: true },
        /** A passkey's signature counter at its last use; 0 for passkeys that keep none (since version 8). */
        signCount: { type: 'number', nullable: true },
        /** How the browser reaches a passkey's authenticator (`internal,hybrid`), as it reported them (since version 8). */
        transports: { type: 'string', nullable: true },
        /** When a passkey last signed in, or 0 (since version 8). */
        lastUsedAt: { type: 'number', nullable: true },
        /** The domain a passkey belongs to (the WebAuthn relying party id); it answers only there (since version 8). */
        rpId: { type: 'string', nullable: true },
        createdAt: { type: 'number' },
      },
    },
    /**
     * A recovery code of a user's authenticator app (since version 5). `id` is the code's keyed hash; the
     * record goes when the code is used. It works only while the account's `setupId` is its own.
     */
    recoveryCode: {
      fields: {
        id: { type: 'string', primaryKey: true },
        userId: { type: 'string', index: true },
        setupId: { type: 'string' },
        createdAt: { type: 'number' },
      },
    },
    /** A pending e-mail verification, password reset, sign-in link or SMS code. `id` is the SHA-256 of the link token. */
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
    /**
     * An API key of a user (since version 10): what programs that call an API on the user's behalf send. The
     * key itself is never stored: `hash` is its SHA-256, by which madAuth finds it.
     */
    apiKey: {
      fields: {
        id: { type: 'string', primaryKey: true },
        userId: { type: 'string', index: true },
        hash: { type: 'string', unique: true },
        name: { type: 'string' },
        /** Its scopes, separated by spaces, e.g. `madauth:claims:read orders:read`. */
        scopes: { type: 'string' },
        createdAt: { type: 'number' },
        /** When it stops working; empty: never. */
        expiresAt: { type: 'number', nullable: true },
        /** When it was last used, to the hour; 0: never. */
        lastUsedAt: { type: 'number' },
      },
    },
    /**
     * A setting, as JSON (since version 4): e.g. `methods`, which sign-in methods are on, which admins change at
     * runtime, or `initialAdmin`, the values of INITIAL_ADMIN_EMAIL that madAuth applied (see admins.ts).
     */
    setting: {
      fields: {
        id: { type: 'string', primaryKey: true },
        value: { type: 'string' },
        updatedAt: { type: 'number' },
        /** The address of the admin who set it; empty when madAuth set it by itself, or a command line before 0.6 did. */
        updatedBy: { type: 'string', nullable: true },
      },
    },
  },
} as const satisfies Schema;
