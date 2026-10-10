// Settings that admins change while the server runs, kept in the store: which sign-in methods are on.
import type { Row, StoreAdapter } from './store/schema.js';

/** The sign-in methods madAuth has. */
export const SIGN_IN_METHODS = ['google', 'password'] as const;
export type SignInMethod = (typeof SIGN_IN_METHODS)[number];

/** Which sign-in methods are on. A method that is not mentioned is on. */
export type MethodSettings = Partial<Record<SignInMethod, boolean>>;

/** The id of the setting that holds {@link MethodSettings}. */
export const METHODS_SETTING = 'methods';

/**
 * Checks a methods setting and returns it with only the known methods, or null if `input` is not one:
 * an object whose values are booleans, keyed by sign-in method.
 */
export function parseMethodSettings(input: unknown): MethodSettings | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const settings: MethodSettings = {};
  for (const [key, value] of Object.entries(input)) {
    if (!(SIGN_IN_METHODS as readonly string[]).includes(key) || typeof value !== 'boolean') return null;
    settings[key as SignInMethod] = value;
  }
  return settings;
}

/** Settings on top of the StoreAdapter, each one a JSON value under its id. */
export class Settings {
  constructor(private readonly store: StoreAdapter) {}

  /** The setting's value, or undefined if it was never set. */
  async get<T>(id: string): Promise<T | undefined> {
    const record = await this.store.findOne('setting', { id });
    if (typeof record?.value !== 'string') return undefined;
    try {
      return JSON.parse(record.value) as T;
    } catch {
      return undefined;
    }
  }

  /** Replaces the setting. `updatedBy` is the address of the admin, or null for the command line. */
  async set(id: string, value: unknown, updatedBy: string | null): Promise<void> {
    const patch: Row = { value: JSON.stringify(value), updatedAt: Date.now(), updatedBy };
    if (await this.store.update('setting', { id }, patch)) return;
    if (await this.store.create('setting', { id, ...patch })) return;
    // Another request created it meanwhile.
    await this.store.update('setting', { id }, patch);
  }

  /** Which sign-in methods are on; a method that was never switched off is on. */
  async methods(): Promise<MethodSettings> {
    return parseMethodSettings(await this.get(METHODS_SETTING)) ?? {};
  }

  async setMethods(methods: MethodSettings, updatedBy: string | null): Promise<void> {
    await this.set(METHODS_SETTING, methods, updatedBy);
  }
}
