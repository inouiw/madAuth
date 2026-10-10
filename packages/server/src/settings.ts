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

/** How often a change is tried again when another request changed the setting in between. */
const MAX_TRIES = 3;

/** Settings on top of the StoreAdapter, each one a JSON value under its id. */
export class Settings {
  constructor(private readonly store: StoreAdapter) {}

  /** The setting's value, or undefined if it was never set. */
  async get<T>(id: string): Promise<T | undefined> {
    return (await this.read<T>(id)).value;
  }

  /** The stored JSON and what it holds; both undefined if the setting was never set. */
  private async read<T>(id: string): Promise<{ json?: string; value?: T }> {
    const record = await this.store.findOne('setting', { id });
    if (typeof record?.value !== 'string') return {};
    try {
      return { json: record.value, value: JSON.parse(record.value) as T };
    } catch {
      return { json: record.value };
    }
  }

  /**
   * Changes the setting: `apply` gets the current value and returns the new one, or null to refuse the
   * change. The write only lands if nobody changed the setting since `apply` read it; otherwise `apply` runs
   * again with the newer value. Resolves to the new value, or null if `apply` refused.
   * `updatedBy` is the address of the admin, or null for the command line.
   */
  async change<T>(id: string, apply: (current: T | undefined) => T | null, updatedBy: string | null): Promise<T | null> {
    for (let attempt = 0; attempt < MAX_TRIES; attempt++) {
      const { json, value } = await this.read<T>(id);
      const next = apply(value);
      if (next === null) return null;
      const patch: Row = { value: JSON.stringify(next), updatedAt: Date.now(), updatedBy };
      const written =
        json === undefined
          ? await this.store.create('setting', { id, ...patch })
          : (await this.store.update('setting', { id, value: json }, patch)) === 1;
      if (written) return next;
    }
    throw new Error(`Setting "${id}" kept changing; try again.`);
  }

  /** Replaces the setting. */
  async set(id: string, value: unknown, updatedBy: string | null): Promise<void> {
    await this.change(id, () => value, updatedBy);
  }

  /** Which sign-in methods are on; a method that was never switched off is on. */
  async methods(): Promise<MethodSettings> {
    return parseMethodSettings(await this.get(METHODS_SETTING)) ?? {};
  }

  /** Changes which methods are on, see {@link change}; `apply` gets the methods as they are now. */
  async changeMethods(
    apply: (current: MethodSettings) => MethodSettings | null,
    updatedBy: string | null,
  ): Promise<MethodSettings | null> {
    return this.change<MethodSettings>(METHODS_SETTING, (current) => apply(parseMethodSettings(current) ?? {}), updatedBy);
  }
}

/** Whether a method is on: configured on the server, and not switched off in the settings. */
export function isOn(method: SignInMethod, available: (method: SignInMethod) => boolean, methods: MethodSettings): boolean {
  return available(method) && methods[method] !== false;
}

/** Whether the settings leave at least one configured method on. */
export function anyOn(available: (method: SignInMethod) => boolean, methods: MethodSettings): boolean {
  return SIGN_IN_METHODS.some((method) => isOn(method, available, methods));
}
