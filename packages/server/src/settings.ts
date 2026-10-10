// Settings that admins change while the server runs, kept in the store: which sign-in methods are on, and
// which of them ask for a second factor. See "Sign-in methods" in docs/server.md.
import type { Row, StoreAdapter } from './store/schema.js';

/**
 * The primary sign-in methods madAuth has: Google, e-mail & password, and the authenticator app on its own
 * (the e-mail address and a code from the app).
 */
export const SIGN_IN_METHODS = ['google', 'password', 'totp'] as const;
export type SignInMethod = (typeof SIGN_IN_METHODS)[number];

/** The methods that can ask for a code from the authenticator app after they succeeded. */
export const METHODS_WITH_SECOND_FACTOR = ['google', 'password'] as const;
export type MethodWithSecondFactor = (typeof METHODS_WITH_SECOND_FACTOR)[number];

/**
 * Whether a method asks for the authenticator app as a second factor: never, when the user has set one up
 * (`optional`), or always, so that a user without one sets it up at the next sign-in (`required`).
 */
export const SECOND_FACTOR_POLICIES = ['none', 'optional', 'required'] as const;
export type SecondFactorPolicy = (typeof SECOND_FACTOR_POLICIES)[number];

/** The settings of a method that is on. `secondFactor` is for Google and password; it defaults to `none`. */
export interface MethodSetting {
  secondFactor?: SecondFactorPolicy;
}

/** The sign-in methods that are on, each with its settings. A method that is not listed is off. */
export type MethodSettings = Partial<Record<SignInMethod, MethodSetting>>;

/** The id of the setting that holds {@link MethodSettings}. */
export const METHODS_SETTING = 'methods';

/** What decides whether the server has what a method needs. `MadauthConfig` has these fields. */
export interface MethodConfig {
  google?: object;
  password?: object;
  /** The webhook sends the e-mails that confirm an address, so people can sign up. */
  emailVerification?: boolean;
}

const isSignInMethod = (value: string): value is SignInMethod => (SIGN_IN_METHODS as readonly string[]).includes(value);
const isPolicy = (value: unknown): value is SecondFactorPolicy => (SECOND_FACTOR_POLICIES as readonly unknown[]).includes(value);

/**
 * Checks a methods setting and returns it as {@link MethodSettings}, or null if `input` is not one: an
 * object keyed by sign-in method, each `{}` (on) or `{ secondFactor }` (Google and password). With
 * `booleans`, as the admin API takes it, `true` means `{}` and `false` means left out; what is stored
 * never has them, so a value stored by madAuth 0.3 (booleans with another meaning) is not mistaken for one.
 */
export function parseMethodSettings(input: unknown, options: { booleans?: boolean } = {}): MethodSettings | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const settings: MethodSettings = {};
  for (const [method, value] of Object.entries(input)) {
    if (!isSignInMethod(method)) return null;
    if (typeof value === 'boolean') {
      if (!options.booleans) return null;
      if (value) settings[method] = {};
      continue;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const setting: MethodSetting = {};
    for (const [field, fieldValue] of Object.entries(value as Record<string, unknown>)) {
      if (field !== 'secondFactor' || method === 'totp' || !isPolicy(fieldValue)) return null;
      setting.secondFactor = fieldValue;
    }
    settings[method] = setting;
  }
  return settings;
}

/** Whether the server has what a method needs; only a configured method can be on. */
export function isConfigured(config: MethodConfig, method: SignInMethod): boolean {
  if (method === 'google') return !!config.google;
  if (method === 'password') return !!config.password;
  // The authenticator app needs nothing but the store, which every server has.
  return true;
}

/**
 * The methods a server runs until an admin sets them: the configured ones, without a second factor. The
 * authenticator app on its own only when nothing else can create users, i.e. on an authenticator-only server.
 */
export function initialMethods(config: MethodConfig): MethodSettings {
  const methods: MethodSettings = {};
  if (config.google) methods.google = { secondFactor: 'none' };
  if (config.password) methods.password = { secondFactor: 'none' };
  if (!config.google && !config.password && config.emailVerification) methods.totp = {};
  return methods;
}

/** How often a change is tried again when another request changed the setting in between. */
const MAX_TRIES = 3;

/** Settings on top of the StoreAdapter, each one a JSON value under its id. */
export class Settings {
  private warned = false;

  /** `initial` is what counts until the methods are set, see {@link initialMethods}. */
  constructor(
    private readonly store: StoreAdapter,
    private readonly initial: MethodSettings = {},
  ) {}

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

  /** Which sign-in methods are on, with their settings; the initial ones until an admin set them. */
  async methods(): Promise<MethodSettings> {
    return this.current(await this.get(METHODS_SETTING));
  }

  /** Changes which methods are on, see {@link change}; `apply` gets the methods as they are now. */
  async changeMethods(
    apply: (current: MethodSettings) => MethodSettings | null,
    updatedBy: string | null,
  ): Promise<MethodSettings | null> {
    return this.change<MethodSettings>(METHODS_SETTING, (current) => apply(this.current(current)), updatedBy);
  }

  /** The stored methods, or the initial ones if nothing (usable) is stored. */
  private current(stored: unknown): MethodSettings {
    if (stored === undefined) return this.initial;
    const parsed = parseMethodSettings(stored);
    if (parsed) return parsed;
    if (!this.warned) {
      this.warned = true;
      console.warn('[madauth] The stored sign-in methods are not in the form this version expects (they were set by an older one?). Set them again with set-methods; until then the initial methods count.');
    }
    return this.initial;
  }
}

/** Whether a method is on: configured on the server, and listed in the settings. */
export function isOn(method: SignInMethod, configured: (method: SignInMethod) => boolean, methods: MethodSettings): boolean {
  return configured(method) && methods[method] !== undefined;
}

/** The second-factor policy of a method, `none` unless set. */
export function policyOf(method: SignInMethod, methods: MethodSettings): SecondFactorPolicy {
  return methods[method]?.secondFactor ?? 'none';
}

/** Whether the settings leave at least one configured method on. */
export function anyOn(configured: (method: SignInMethod) => boolean, methods: MethodSettings): boolean {
  return SIGN_IN_METHODS.some((method) => isOn(method, configured, methods));
}

/**
 * Whether the authenticator app is in use at all, so it can be set up: on its own, or as the second factor
 * of a method that is on.
 */
export function authenticatorOn(configured: (method: SignInMethod) => boolean, methods: MethodSettings): boolean {
  if (isOn('totp', configured, methods)) return true;
  return METHODS_WITH_SECOND_FACTOR.some((method) => isOn(method, configured, methods) && policyOf(method, methods) !== 'none');
}
