// Settings that admins change while the server runs, kept in the store: which sign-in methods are on, which
// of them sign in on their own, which ask for a second factor, and the rules for new passwords. See "Sign-in
// methods" and "Password rules" in docs/server.md.
import { isProviderId } from './providers.js';
import type { Row, StoreAdapter } from './store/schema.js';

/**
 * The sign-in methods madAuth has: Google, GitHub, e-mail & password, the authenticator app on its own
 * (`authenticator`: the e-mail address and a code from the app), the passwordless e-mail link (`email-link`: the
 * address, then the link or the code from an e-mail) and passkeys (`passkey`: WebAuthn).
 */
export const SIGN_IN_METHODS = ['google', 'github', 'password', 'authenticator', 'email-link', 'passkey'] as const;
export type SignInMethod = (typeof SIGN_IN_METHODS)[number];

/**
 * Every key of the methods setting: the sign-in methods, and `sms`, which signs nobody in by itself: SMS
 * codes as a second factor of the methods whose policy asks for one.
 */
export const METHODS = [...SIGN_IN_METHODS, 'sms'] as const;
export type MethodId = (typeof METHODS)[number];

/**
 * The second factors, in the order a sign-in offers them: a passkey, a code from the authenticator app, a
 * code by SMS. Each is on when its method is listed, whether or not it also signs in on its own.
 */
export const SECOND_FACTORS = ['passkey', 'authenticator', 'sms'] as const;
export type SecondFactor = (typeof SECOND_FACTORS)[number];

/**
 * The methods that always sign in when they are on: they are nothing else, and a sign-up makes their account. So
 * do the OpenID Connect providers, whose ids are methods too (see `isProviderId`).
 */
export const ALWAYS_SIGN_IN = ['google', 'github', 'password', 'email-link'] as const;
const isAlwaysSignIn = (method: string) => (ALWAYS_SIGN_IN as readonly string[]).includes(method) || isProviderId(method);

/**
 * The methods that can ask for a second factor after they succeeded: those that always sign in, and passkeys.
 * They are also the methods a user removes without a code (the app and the phone take one).
 */
export const METHODS_WITH_SECOND_FACTOR = [...ALWAYS_SIGN_IN, 'passkey'] as const;
export type MethodWithSecondFactor = (typeof METHODS_WITH_SECOND_FACTOR)[number];

/**
 * Whether a method asks for a second factor: never, when the user has set one up (`optional`), or always,
 * so that a user without one sets it up at the next sign-in (`required`).
 */
export const SECOND_FACTOR_POLICIES = ['none', 'optional', 'required'] as const;
export type SecondFactorPolicy = (typeof SECOND_FACTOR_POLICIES)[number];

/**
 * The settings of a method that is on, both always given. `allowAsSignInMethod`: whether it signs a user in
 * on its own, as one of their sign-in methods (Google, GitHub, password and the e-mail link always do, SMS
 * never; the authenticator app and passkeys either do, or are only a second factor). `secondFactor`: whether
 * a sign-in with it asks for a second factor; `none` for a method that does not sign in.
 */
export interface MethodSetting {
  allowAsSignInMethod: boolean;
  secondFactor: SecondFactorPolicy;
}

/**
 * The sign-in methods that are on, each with its settings: madAuth's own ({@link MethodId}) and the OpenID Connect
 * providers', by their ids. A method that is not listed is off.
 */
export type MethodSettings = Partial<Record<string, MethodSetting>>;

/** The id of the setting that holds {@link MethodSettings}. */
export const METHODS_SETTING = 'methods';

/** The id of the setting that holds {@link PasswordRules}. */
export const PASSWORD_SETTING = 'password';

/** The id of the setting that holds the app's login page, see {@link parseLoginUrl}. */
export const LOGIN_URL_SETTING = 'loginUrl';

/**
 * The app's login page as an admin sets it, or null if `value` is none: a path on the issuer's origin (`/login`),
 * or an absolute URL on one of `allowedOrigins`. madAuth sends people there when an application that signs in with
 * madAuth as its OpenID Connect provider needs them to sign in (see "OpenID Connect provider" in docs/server.md).
 */
export function parseLoginUrl(value: unknown, allowedOrigins: readonly string[]): string | null {
  if (typeof value !== 'string' || value.length > 2048) return null;
  // A browser reads `\` as `/`, so `/\host` would lead to another host.
  if (value.startsWith('/')) return value.startsWith('//') || value.includes('\\') || value.includes('#') ? null : value;
  if (!URL.canParse(value) || value.includes('#')) return null;
  return allowedOrigins.includes(new URL(value).origin) ? value : null;
}

/** The rules for new passwords: at sign-up, at a reset, and when a user adds a password. */
export interface PasswordRules {
  /** The fewest characters a password may have, from 1 to {@link MAX_MIN_LENGTH}. */
  minLength: number;
  /**
   * How hard to guess it must be, as zxcvbn rates it (see `passwordScore`): 0 (anything) to 4. 2 refuses
   * common passwords and simple patterns; 3 asks for noticeably stronger ones.
   */
  minScore: PasswordScore;
}

export type PasswordScore = 0 | 1 | 2 | 3 | 4;

/** The rules until an admin sets them. */
export const DEFAULT_PASSWORD_RULES: PasswordRules = { minLength: 8, minScore: 2 };

/** The highest minimum length an admin can set; a password has at most 256 characters. */
export const MAX_MIN_LENGTH = 128;

export const isPasswordScore = (value: unknown): value is PasswordScore => Number.isInteger(value) && (value as number) >= 0 && (value as number) <= 4;

/**
 * Checks password rules and returns them as {@link PasswordRules}, or null if `input` is not: an object with
 * `minLength` and `minScore`, each optional (then its default), nothing else.
 */
export function parsePasswordRules(input: unknown): PasswordRules | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const { minLength = DEFAULT_PASSWORD_RULES.minLength, minScore = DEFAULT_PASSWORD_RULES.minScore, ...rest } = input as Record<string, unknown>;
  if (Object.keys(rest).length) return null;
  if (!Number.isInteger(minLength) || (minLength as number) < 1 || (minLength as number) > MAX_MIN_LENGTH) return null;
  if (!isPasswordScore(minScore)) return null;
  return { minLength: minLength as number, minScore };
}

export const isMethodId = (value: string): value is MethodId => (METHODS as readonly string[]).includes(value);
/** Whether a method takes a `secondFactor` policy other than `none`: those that always sign in, passkeys, and the providers'. */
const hasSecondFactor = (method: string): boolean => (METHODS_WITH_SECOND_FACTOR as readonly string[]).includes(method) || isProviderId(method);
/** Whether `method` signs people in: one of madAuth's own, or an OpenID Connect provider's id. */
const isSignInMethodId = (method: string): boolean => (SIGN_IN_METHODS as readonly string[]).includes(method) || isProviderId(method);
const isPolicy = (value: unknown): value is SecondFactorPolicy => (SECOND_FACTOR_POLICIES as readonly unknown[]).includes(value);
const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

/**
 * Checks the form of a methods setting and returns it as {@link MethodSettings}, or null if `input` is not
 * one: an object keyed by method id, each `{ allowAsSignInMethod, secondFactor }` with both given and nothing else. What
 * the values mean together is {@link checkMethodSettings}.
 */
export function parseMethodSettings(input: unknown): MethodSettings | null {
  if (!isObject(input)) return null;
  const settings: MethodSettings = {};
  for (const [method, value] of Object.entries(input)) {
    if ((!isMethodId(method) && !isProviderId(method)) || !isObject(value)) return null;
    const { allowAsSignInMethod, secondFactor, ...rest } = value;
    if (Object.keys(rest).length || typeof allowAsSignInMethod !== 'boolean' || !isPolicy(secondFactor)) return null;
    settings[method] = { allowAsSignInMethod, secondFactor };
  }
  return settings;
}

/** Whether a list from before 0.6 (its `totp` read as `authenticator`) has nothing that signs in but the app: SMS codes sign nobody in. */
const signsInOnlyWithApp = (stored: Record<string, unknown>) => !Object.keys(stored).some((method) => method !== 'authenticator' && method !== 'sms');

/**
 * The authenticator app's id before madAuth 0.6. Stored data keeps it, and it is read as `authenticator`:
 * the start of the app's account keys (`totp:<userId>`, see `authenticatorAccountKey`), a saved methods list
 * ({@link renameStoredMethods}) and the method of a pending sign-up (`signUpMethodOf`). It is no method id.
 */
export const FORMER_AUTHENTICATOR_ID = 'totp';

/**
 * A stored methods setting with {@link FORMER_AUTHENTICATOR_ID} read as `authenticator`, in its place among the
 * others; anything else as it is. A list with both (madAuth never writes one) keeps the setting of
 * `authenticator`. Only for what is stored: the settings an admin sets name the app `authenticator`.
 */
export function renameStoredMethods(stored: unknown): unknown {
  if (!isObject(stored) || !(FORMER_AUTHENTICATOR_ID in stored)) return stored;
  const both = 'authenticator' in stored;
  return Object.fromEntries(
    Object.entries(stored).flatMap(([method, value]) => (method !== FORMER_AUTHENTICATOR_ID ? [[method, value]] : both ? [] : [['authenticator', value]])),
  );
}

/**
 * A methods setting as madAuth before 0.6 stored it: `{}` for a method that is on, `{ secondFactor }` for
 * Google, GitHub, password and the e-mail link. Then the authenticator app was a second factor whenever a
 * policy asked for one, listed or not; SMS was only ever a second factor. Listing the app let it sign in on
 * its own, but only for the users who signed up with it, which 0.6 can't say: the app signs in everyone who
 * has one, or nobody. A listed app is read as a second factor only, which weakens no account, until an admin
 * chooses (see {@link legacyAppProblem}); where nothing else signs in, it keeps signing in, or nobody could.
 * Returns the same as {@link MethodSettings}, or null if `input` is not in that form.
 */
export function parseLegacyMethodSettings(input: unknown): MethodSettings | null {
  if (!isObject(input)) return null;
  const legacy = ['google', 'github', 'password', 'authenticator', 'email-link', 'sms'];
  const appOnly = signsInOnlyWithApp(input);
  const settings: MethodSettings = {};
  for (const [method, value] of Object.entries(input)) {
    if (!legacy.includes(method) || !isObject(value)) return null;
    const { secondFactor = 'none', ...rest } = value;
    if (Object.keys(rest).length || !isPolicy(secondFactor) || (secondFactor !== 'none' && !hasSecondFactor(method))) return null;
    settings[method as MethodId] = { allowAsSignInMethod: method !== 'sms' && (method !== 'authenticator' || appOnly), secondFactor };
  }
  const asks = Object.values(settings).some((setting) => !!setting && setting.secondFactor !== 'none');
  if (asks && !settings.authenticator) settings.authenticator = { allowAsSignInMethod: false, secondFactor: 'none' };
  return settings;
}

/**
 * Why a stored methods setting needs an admin's choice, as a message for the operator; null if it doesn't. A
 * list that madAuth before 0.6 stored with the authenticator app on its own (`totp`) next to other methods has
 * no meaning in 0.6 (see {@link parseLegacyMethodSettings}): until an admin saves the methods again, the app is
 * a second factor only, and the message says what to choose from.
 */
export function legacyAppProblem(value: unknown): string | null {
  const stored = renameStoredMethods(value);
  if (stored === undefined || parseMethodSettings(stored) || !isObject(stored) || !('authenticator' in stored)) return null;
  if (!parseLegacyMethodSettings(stored) || signsInOnlyWithApp(stored)) return null;
  return (
    'The sign-in methods were saved by madAuth before 0.6 and let the authenticator app sign in on its own (totp). ' +
    'Then it did so only for the users who signed up with it; now it does for everyone who has one, also for those who set it up ' +
    "as a second factor, or for nobody. Until an admin chooses, it is a second factor only: users who signed up with it alone can't sign in. " +
    'An admin chooses by saving the methods with Madauth.admin.setSettings: authenticator with allowAsSignInMethod false keeps the app a second factor, ' +
    'with true everyone who has the app signs in with it alone. See docs/upgrading.md.'
  );
}

/**
 * What decides whether the server has what a method needs: the providers in the store (Google, GitHub), and what
 * the server's configuration has (the webhook's e-mails and SMS).
 */
export interface MethodConfig {
  google?: object;
  github?: object;
  /** The ids of the OpenID Connect providers in the store. */
  oidc?: ReadonlySet<string>;
  password?: object;
  /** The webhook sends the e-mails that confirm an address, so people can sign up. */
  emailVerification?: boolean;
  /** The webhook sends the sign-in e-mails of the e-mail link (`email.send_signin_link`). */
  emailLink?: boolean;
  /** The webhook sends the SMS (`sms.send_code`). */
  sms?: boolean;
}

/** Whether the server has what a method needs; only a configured method can be on. */
export function isConfigured(config: MethodConfig, method: string): boolean {
  if (!isMethodId(method)) return !!config.oidc?.has(method);
  if (method === 'google') return !!config.google;
  if (method === 'github') return !!config.github;
  if (method === 'password') return !!config.password;
  if (method === 'email-link') return !!config.emailLink;
  if (method === 'sms') return !!config.sms;
  // The authenticator app and passkeys need nothing but the store, which every server has.
  return true;
}

/**
 * Whether a method creates users on this server: Google, GitHub, password and the e-mail link when configured,
 * the authenticator app and passkeys only when the webhook sends the confirmation e-mails (sign-up with them).
 * Without it, an app or a passkey that existing users set up is no way in for anyone new.
 */
export function canSignUp(config: MethodConfig, method: string): boolean {
  return method === 'authenticator' || method === 'passkey' ? !!config.emailVerification : isConfigured(config, method);
}

/**
 * The methods a server runs until an admin sets them: the configured ones, without a second factor, and SMS
 * codes when the webhook sends them. The authenticator app on its own only when nothing else can create
 * users, i.e. on an authenticator-only server. Passkeys only once an admin lists them.
 */
export function initialMethods(config: MethodConfig): MethodSettings {
  const methods: MethodSettings = {};
  const signIn: MethodSetting = { allowAsSignInMethod: true, secondFactor: 'none' };
  if (config.google) methods.google = signIn;
  if (config.github) methods.github = signIn;
  if (config.password) methods.password = signIn;
  if (config.emailLink) methods['email-link'] = signIn;
  if (!config.google && !config.github && !config.password && !config.emailLink && config.emailVerification) methods.authenticator = signIn;
  if (config.sms) methods.sms = { allowAsSignInMethod: false, secondFactor: 'none' };
  return methods;
}

/** How often a change is tried again when another request changed the setting in between. */
const MAX_TRIES = 3;

/** Settings on top of the StoreAdapter, each one a JSON value under its id. */
export class Settings {
  private warned = false;
  private warnedRules = false;
  private warnedLegacy = false;

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
   * `updatedBy` is the address of the admin, or null when madAuth changes it by itself.
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

  /**
   * Which sign-in methods are on, with their settings; `initial` until an admin set them (see
   * {@link initialMethods}: it depends on the providers in the store, so the caller passes it).
   */
  async methods(initial: MethodSettings = {}): Promise<MethodSettings> {
    return this.methodsFrom(await this.get(METHODS_SETTING), initial);
  }

  /** {@link methods} from the setting's value as read, for a caller that read it together with something else. */
  methodsFrom(value: unknown, initial: MethodSettings = {}): MethodSettings {
    return this.current(value, initial);
  }

  /** Changes which methods are on, see {@link change}; `apply` gets the methods as they are now. */
  async changeMethods(
    apply: (current: MethodSettings) => MethodSettings | null,
    updatedBy: string | null,
    initial: MethodSettings = {},
  ): Promise<MethodSettings | null> {
    return this.change<MethodSettings>(METHODS_SETTING, (current) => apply(this.current(current, initial)), updatedBy);
  }

  /** The app's login page as an admin set it (see {@link parseLoginUrl}); null: the issuer's `/`. */
  async loginUrl(): Promise<string | null> {
    const stored = await this.get<unknown>(LOGIN_URL_SETTING);
    return typeof stored === 'string' ? stored : null;
  }

  /** The rules for new passwords; the defaults until an admin set them. */
  async passwordRules(): Promise<PasswordRules> {
    const stored = await this.get(PASSWORD_SETTING);
    if (stored === undefined) return DEFAULT_PASSWORD_RULES;
    const parsed = parsePasswordRules(stored);
    if (parsed) return parsed;
    if (!this.warnedRules) {
      this.warnedRules = true;
      console.warn('[madauth] The stored password rules are not in the form this version expects. An admin sets them again with Madauth.admin.setSettings; until then the defaults count.');
    }
    return DEFAULT_PASSWORD_RULES;
  }

  /** Replaces the rules for new passwords. */
  async setPasswordRules(rules: PasswordRules, updatedBy: string | null): Promise<PasswordRules> {
    await this.set(PASSWORD_SETTING, rules, updatedBy);
    return rules;
  }

  /**
   * The stored methods (`totp` read as `authenticator`, see {@link renameStoredMethods}), or the initial ones
   * if nothing (usable) is stored. A value stored by madAuth before 0.6 keeps its meaning (see
   * {@link parseLegacyMethodSettings}), but for the app on its own next to other methods, which counts as a
   * second factor only until an admin chooses: the operator is told once.
   */
  private current(value: unknown, initial: MethodSettings): MethodSettings {
    if (value === undefined) return initial;
    const stored = renameStoredMethods(value);
    const parsed = parseMethodSettings(stored) ?? parseLegacyMethodSettings(stored);
    const problem = parsed && !this.warnedLegacy ? legacyAppProblem(stored) : null;
    if (problem) {
      this.warnedLegacy = true;
      console.warn(`[madauth] ${problem}`);
    }
    if (parsed) return parsed;
    if (!this.warned) {
      this.warned = true;
      console.warn('[madauth] The stored sign-in methods are not in the form this version expects. An admin sets them again with Madauth.admin.setSettings; until then the initial methods count.');
    }
    return initial;
  }
}

/** Whether a method is on: configured on the server, and listed in the settings. */
export function isOn(method: string, configured: (method: string) => boolean, methods: MethodSettings): boolean {
  return configured(method) && methods[method] !== undefined;
}

/** Whether a method signs in on its own: it is on, and not only a second factor. */
export function signsIn(method: string, configured: (method: string) => boolean, methods: MethodSettings): boolean {
  return isOn(method, configured, methods) && methods[method]!.allowAsSignInMethod;
}

/** {@link signsIn} for any method id, as the account checks take it: an id that is no method never signs in. */
export const signInPredicate =
  (configured: (method: string) => boolean, methods: MethodSettings) =>
  (method: string): boolean =>
    (isMethodId(method) || isProviderId(method)) && signsIn(method, configured, methods);

/** The second-factor policy of a method, `none` unless set. */
export function policyOf(method: string, methods: MethodSettings): SecondFactorPolicy {
  return methods[method]?.secondFactor ?? 'none';
}

/** The second factors that are on, in the order a sign-in offers them; `except` is the method whose sign-in it is. */
export function factorsOn(configured: (method: string) => boolean, methods: MethodSettings, except?: string): SecondFactor[] {
  return SECOND_FACTORS.filter((factor) => factor !== except && isOn(factor, configured, methods));
}

/** The methods that sign in and require a second factor, so a user's last one can't go; providers' by their ids. */
export function requiringSecondFactor(configured: (method: string) => boolean, methods: MethodSettings): string[] {
  const candidates = [...METHODS_WITH_SECOND_FACTOR, ...Object.keys(methods).filter(isProviderId)];
  return candidates.filter((method) => signsIn(method, configured, methods) && policyOf(method, methods) === 'required');
}

/**
 * Whether the settings leave on at least one method that creates users, so that nobody is locked out:
 * `signsUp` is {@link canSignUp} for the server. The app or passkeys alone, on a server where nobody can sign
 * up with them, would let in only the users who already have one.
 */
export function anyOn(signsUp: (method: string) => boolean, methods: MethodSettings): boolean {
  return Object.keys(methods).some((method) => isSignInMethodId(method) && signsUp(method) && methods[method]?.allowAsSignInMethod === true);
}

/**
 * What is wrong with a methods setting the form of which {@link parseMethodSettings} accepted, as a message
 * for the admin; null if nothing is. `configured` and `signsUp` are the server's ({@link isConfigured},
 * {@link canSignUp}).
 */
export function checkMethodSettings(
  methods: MethodSettings,
  server: { configured: (method: string) => boolean; signsUp: (method: string) => boolean; providers?: { id: string; kind: string }[] },
): string | null {
  const providerIds = (server.providers ?? []).filter((provider) => provider.kind === 'oidc').map((provider) => provider.id);
  for (const [method, setting] of Object.entries(methods)) {
    if (!setting) continue;
    if (!isMethodId(method) && !providerIds.includes(method)) return `"${method}" is no sign-in method of this server: add the provider first.`;
    if (isAlwaysSignIn(method) && !setting.allowAsSignInMethod) {
      return `"${method}" always signs in: set its allowAsSignInMethod to true, or leave it out to switch it off.`;
    }
    if (method === 'sms' && setting.allowAsSignInMethod) return '"sms" is only a second factor: set its allowAsSignInMethod to false.';
    if (setting.secondFactor === 'none') continue;
    if (!setting.allowAsSignInMethod) return `"${method}" does not sign in on its own, so it asks for no second factor: set its secondFactor to "none".`;
    if (!hasSecondFactor(method)) return `"${method}" is a second factor itself: set its secondFactor to "none".`;
    if (!factorsOn(server.configured, methods, method).length) {
      const others = SECOND_FACTORS.filter((factor) => factor !== method && server.configured(factor));
      return `"${method}" asks for a second factor, but none is on: list ${others.join(' or ')} as well.`;
    }
  }
  if (!anyOn(server.signsUp, methods)) {
    const usable = [...SIGN_IN_METHODS, ...providerIds].filter(server.signsUp);
    return `At least one sign-in method that creates users must stay on. On this server these do: ${usable.join(', ')}.`;
  }
  return null;
}
