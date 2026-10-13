// Settings that admins change while the server runs, kept in the store: which sign-in methods are on, which
// of them sign in on their own, which ask for a second factor, and the rules for new passwords. See "Sign-in
// methods" and "Password rules" in docs/server.md.
import type { Row, StoreAdapter } from './store/schema.js';

/**
 * The sign-in methods madAuth has: Google, GitHub, e-mail & password, the authenticator app on its own
 * (`totp`: the e-mail address and a code from the app), the passwordless e-mail link (`email-link`: the
 * address, then the link or the code from an e-mail) and passkeys (`passkey`: WebAuthn, added by a user who
 * signed in another way).
 */
export const SIGN_IN_METHODS = ['google', 'github', 'password', 'totp', 'email-link', 'passkey'] as const;
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
export const SECOND_FACTORS = ['passkey', 'totp', 'sms'] as const;
export type SecondFactor = (typeof SECOND_FACTORS)[number];

/** The methods that can ask for a second factor after they succeeded. */
export const METHODS_WITH_SECOND_FACTOR = ['google', 'github', 'password', 'email-link', 'passkey'] as const;
export type MethodWithSecondFactor = (typeof METHODS_WITH_SECOND_FACTOR)[number];

/** The methods that always sign in when they are on: they are nothing else. */
const ALWAYS_SIGN_IN: readonly MethodId[] = ['google', 'github', 'password', 'email-link'];

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

/** The sign-in methods that are on, each with its settings. A method that is not listed is off. */
export type MethodSettings = Partial<Record<MethodId, MethodSetting>>;

/** The id of the setting that holds {@link MethodSettings}. */
export const METHODS_SETTING = 'methods';

/** The id of the setting that holds {@link PasswordRules}. */
export const PASSWORD_SETTING = 'password';

/** The rules for new passwords, at sign-up, reset and `create-user`. */
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
/** Whether a method takes a `secondFactor` policy other than `none`. */
export const hasSecondFactor = (method: string): method is MethodWithSecondFactor =>
  (METHODS_WITH_SECOND_FACTOR as readonly string[]).includes(method);
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
    if (!isMethodId(method) || !isObject(value)) return null;
    const { allowAsSignInMethod, secondFactor, ...rest } = value;
    if (Object.keys(rest).length || typeof allowAsSignInMethod !== 'boolean' || !isPolicy(secondFactor)) return null;
    settings[method] = { allowAsSignInMethod, secondFactor };
  }
  return settings;
}

/**
 * A methods setting as madAuth before 0.6 stored it: `{}` for a method that is on, `{ secondFactor }` for
 * Google, GitHub, password and the e-mail link. Then the authenticator app was a second factor whenever a
 * policy asked for one, listed or not; SMS was only ever a second factor. Listing the app let it sign in on
 * its own, but only for the users who signed up with it, which 0.6 can't say: the app signs in everyone who
 * has one, or nobody. A listed app is read as a second factor only, which weakens no account, and the server
 * doesn't start until an admin chooses (see {@link legacyAppProblem}). Returns the same as
 * {@link MethodSettings}, or null if `input` is not in that form.
 */
export function parseLegacyMethodSettings(input: unknown): MethodSettings | null {
  if (!isObject(input)) return null;
  const legacy = ['google', 'github', 'password', 'totp', 'email-link', 'sms'];
  const settings: MethodSettings = {};
  for (const [method, value] of Object.entries(input)) {
    if (!legacy.includes(method) || !isObject(value)) return null;
    const { secondFactor = 'none', ...rest } = value;
    if (Object.keys(rest).length || !isPolicy(secondFactor) || (secondFactor !== 'none' && !hasSecondFactor(method))) return null;
    settings[method as MethodId] = { allowAsSignInMethod: method !== 'sms' && method !== 'totp', secondFactor };
  }
  const asks = Object.values(settings).some((setting) => setting.secondFactor !== 'none');
  if (asks && !settings.totp) settings.totp = { allowAsSignInMethod: false, secondFactor: 'none' };
  return settings;
}

/**
 * Why a stored methods setting can't be used as it is, as a message for the operator; null if it can. A list
 * that madAuth before 0.6 stored with the authenticator app on its own (`totp`) has no meaning in 0.6 (see
 * {@link parseLegacyMethodSettings}): the message names the two `set-methods` commands to choose from.
 */
export function legacyAppProblem(stored: unknown): string | null {
  if (stored === undefined || parseMethodSettings(stored) || !isObject(stored) || !('totp' in stored)) return null;
  const legacy = parseLegacyMethodSettings(stored);
  if (!legacy) return null;
  const listed = Object.keys(stored).map((method) => {
    const policy = legacy[method as MethodId]!.secondFactor;
    return policy === 'none' ? method : `${method}=${policy}`;
  });
  const command = (totp: string) => `set-methods ${listed.map((arg) => (arg === 'totp' ? totp : arg)).join(' ')}`;
  const intro =
    'The sign-in methods were saved by madAuth before 0.6 and let the authenticator app sign in on its own (totp). ' +
    'Then it did so only for the users who signed up with it; now it does for everyone who has one, also for those who set it up ' +
    'as a second factor, or for nobody.';
  // With nothing else that signs in, the app has to: a list with it as a second factor only would be refused.
  if (!Object.keys(stored).some((method) => method !== 'totp' && method !== 'sms')) {
    return `${intro} Here it is the only method that signs in, so keep it: run "${command('totp')}", then start the server again. See docs/upgrading.md.`;
  }
  return (
    `${intro} Choose, then start the server again: ` +
    `"${command('totp=second-factor')}" keeps the app a second factor (users who signed up with it alone can't sign in until you allow it), ` +
    `"${command('totp')}" lets everyone who has the app sign in with it alone. See docs/upgrading.md.`
  );
}

/** What decides whether the server has what a method needs. `MadauthConfig` has these fields. */
export interface MethodConfig {
  google?: object;
  github?: object;
  password?: object;
  /** The webhook sends the e-mails that confirm an address, so people can sign up. */
  emailVerification?: boolean;
  /** The webhook sends the sign-in e-mails of the e-mail link (`email.send_signin_link`). */
  emailLink?: boolean;
  /** The webhook sends the SMS (`sms.send_code`). */
  sms?: boolean;
}

/** Whether the server has what a method needs; only a configured method can be on. */
export function isConfigured(config: MethodConfig, method: MethodId): boolean {
  if (method === 'google') return !!config.google;
  if (method === 'github') return !!config.github;
  if (method === 'password') return !!config.password;
  if (method === 'email-link') return !!config.emailLink;
  if (method === 'sms') return !!config.sms;
  // The authenticator app and passkeys need nothing but the store, which every server has.
  return true;
}

/**
 * Whether a method creates users on this server: Google, GitHub, password and the e-mail link when configured, the
 * authenticator app only when the webhook sends the confirmation e-mails (sign-up with it). An app that
 * existing users set up is no way in for anyone new, and neither is a passkey: only a signed-in user adds one.
 */
export function canSignUp(config: MethodConfig, method: SignInMethod): boolean {
  if (method === 'passkey') return false;
  return method === 'totp' ? !!config.emailVerification : isConfigured(config, method);
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
  if (!config.google && !config.github && !config.password && !config.emailLink && config.emailVerification) methods.totp = signIn;
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

  /** The rules for new passwords; the defaults until an admin set them. */
  async passwordRules(): Promise<PasswordRules> {
    const stored = await this.get(PASSWORD_SETTING);
    if (stored === undefined) return DEFAULT_PASSWORD_RULES;
    const parsed = parsePasswordRules(stored);
    if (parsed) return parsed;
    if (!this.warnedRules) {
      this.warnedRules = true;
      console.warn('[madauth] The stored password rules are not in the form this version expects. Set them again with set-password-rules; until then the defaults count.');
    }
    return DEFAULT_PASSWORD_RULES;
  }

  /** Replaces the rules for new passwords. */
  async setPasswordRules(rules: PasswordRules, updatedBy: string | null): Promise<PasswordRules> {
    await this.set(PASSWORD_SETTING, rules, updatedBy);
    return rules;
  }

  /**
   * The stored methods, or the initial ones if nothing (usable) is stored. A value stored by madAuth before
   * 0.6 keeps its meaning (see {@link parseLegacyMethodSettings}), but for the app on its own, which counts as
   * a second factor only: a server doesn't start with such a list, see `loadConfig`.
   */
  private current(stored: unknown): MethodSettings {
    if (stored === undefined) return this.initial;
    const parsed = parseMethodSettings(stored) ?? parseLegacyMethodSettings(stored);
    if (parsed && !this.warnedLegacy && legacyAppProblem(stored)) {
      // loadConfig refuses such a list; an app made without it gets the safe reading, and the operator is told.
      this.warnedLegacy = true;
      console.warn(`[madauth] ${legacyAppProblem(stored)} Until then the app is a second factor only.`);
    }
    if (parsed) return parsed;
    if (!this.warned) {
      this.warned = true;
      console.warn('[madauth] The stored sign-in methods are not in the form this version expects. Set them again with set-methods; until then the initial methods count.');
    }
    return this.initial;
  }
}

/** Whether a method is on: configured on the server, and listed in the settings. */
export function isOn(method: MethodId, configured: (method: MethodId) => boolean, methods: MethodSettings): boolean {
  return configured(method) && methods[method] !== undefined;
}

/** Whether a method signs in on its own: it is on, and not only a second factor. */
export function signsIn(method: MethodId, configured: (method: MethodId) => boolean, methods: MethodSettings): boolean {
  return isOn(method, configured, methods) && methods[method]!.allowAsSignInMethod;
}

/** The second-factor policy of a method, `none` unless set. */
export function policyOf(method: MethodId, methods: MethodSettings): SecondFactorPolicy {
  return methods[method]?.secondFactor ?? 'none';
}

/** The second factors that are on, in the order a sign-in offers them; `except` is the method whose sign-in it is. */
export function factorsOn(configured: (method: MethodId) => boolean, methods: MethodSettings, except?: MethodId): SecondFactor[] {
  return SECOND_FACTORS.filter((factor) => factor !== except && isOn(factor, configured, methods));
}

/** The methods that sign in and require a second factor, so a user's last one can't go. */
export function requiringSecondFactor(configured: (method: MethodId) => boolean, methods: MethodSettings): MethodWithSecondFactor[] {
  return METHODS_WITH_SECOND_FACTOR.filter((method) => signsIn(method, configured, methods) && policyOf(method, methods) === 'required');
}

/**
 * Whether the settings leave on at least one method that creates users, so that nobody is locked out:
 * `signsUp` is {@link canSignUp} for the server. The app alone, on a server where nobody can sign up with
 * it, would let in only the users who already have an app.
 */
export function anyOn(signsUp: (method: SignInMethod) => boolean, methods: MethodSettings): boolean {
  return SIGN_IN_METHODS.some((method) => signsUp(method) && methods[method]?.allowAsSignInMethod === true);
}

/**
 * What is wrong with a methods setting the form of which {@link parseMethodSettings} accepted, as a message
 * for the admin; null if nothing is. `configured` and `signsUp` are the server's ({@link isConfigured},
 * {@link canSignUp}).
 */
export function checkMethodSettings(
  methods: MethodSettings,
  server: { configured: (method: MethodId) => boolean; signsUp: (method: SignInMethod) => boolean },
): string | null {
  for (const method of METHODS) {
    const setting = methods[method];
    if (!setting) continue;
    if (ALWAYS_SIGN_IN.includes(method) && !setting.allowAsSignInMethod) {
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
    const usable = SIGN_IN_METHODS.filter(server.signsUp);
    return `At least one sign-in method that creates users must stay on. On this server these do: ${usable.join(', ')}.`;
  }
  return null;
}
