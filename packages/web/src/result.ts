/** The signed-in user. */
export interface MadauthUser {
  /** Stable id (`usr_…`), the same whichever way the user signs in. */
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  /** What admins attached to the user, e.g. `{ roles: ['admin'] }`. Absent without claims. */
  claims?: Record<string, unknown>;
  /**
   * How the session was authenticated (RFC 8176): `pwd` (password), `google`, `github`, `email` (the e-mail link),
   * `otp` (the authenticator app, on its own or as the second factor), `sms` (a code by SMS as the second
   * factor), `passkey` (a passkey, on its own or as the second factor), e.g. `['pwd', 'otp']`. Present on a
   * user that comes with a session.
   */
  amr?: string[];
}

/** The second factors, in the order a sign-in offers them: a passkey, a code from the authenticator app, one sent by SMS. */
export const SECOND_FACTORS = ['passkey', 'authenticator', 'sms'] as const;
export type SecondFactor = (typeof SECOND_FACTORS)[number];

export const isSecondFactor = (value: unknown): value is SecondFactor => (SECOND_FACTORS as readonly unknown[]).includes(value);

const errorCodes = [
  'invalid_options',
  'network',
  'flow_not_enabled',
  'gis_load_failed',
  'not_initialized',
  'cancelled',
  'verification_failed',
  'email_unverified',
  'no_session',
  'invalid_credentials',
  'invalid_email',
  'weak_password',
  'too_many_attempts',
  'link_invalid',
  'code_invalid',
  'codes_locked',
  'temporarily_unavailable',
  'signup_rejected',
  'method_disabled',
  'forbidden',
  'invalid_claims',
  'user_not_found',
  'invalid_settings',
  'authenticator_required',
  'authenticator_setup_required',
  'second_factor_setup_required',
  'passkey_setup_required',
  'sms_required',
  'passkey_required',
  'passkey_unknown',
  'passkey_unsupported',
  'reauth_required',
  'account_taken',
  'already_added',
  'method_not_found',
  'forbidden_origin',
  'invalid_phone',
  'no_phone',
  'too_soon',
  'challenge_expired',
  'setup_expired',
  'required_by_policy',
  'code_required',
  'no_authenticator',
  'only_method',
  'own_admin_role',
  'other_method',
  'unknown',
] as const;

export type MadauthErrorCode = (typeof errorCodes)[number];

export interface MadauthError {
  code: MadauthErrorCode;
  /** Human-readable details, e.g. which option is invalid. */
  message: string;
  /**
   * With `passkey_required`, `authenticator_required`, `sms_required`, `second_factor_setup_required`,
   * `authenticator_setup_required` and `passkey_setup_required`: the method whose sign-in goes on with the next
   * step (`authenticator` or `passkey` for a sign-up with the app or a passkey alone).
   */
  method?: string;
  /**
   * With `passkey_required`, `authenticator_required` and `sms_required`: the second factors the user can finish the
   * sign-in with, e.g. `['authenticator', 'sms']`. With `second_factor_setup_required`: those they can choose to set
   * up. With `authenticator_setup_required` or `passkey_setup_required` (a sign-up with the app or a passkey alone,
   * its address confirmed): `['authenticator']` or `['passkey']`.
   */
  factors?: SecondFactor[];
  /** With `other_method`: how the address signs in instead, e.g. `['password']`. */
  methods?: string[];
  /** With `weak_password` for a password that is too short: the fewest characters it may have. */
  minLength?: number;
  /** With `weak_password` for a password that is too easy to guess: the strength score it needs (0 to 4). */
  minScore?: number;
}

/** What every madAuth method resolves to. Expected failures are returned, never thrown. */
export type Result<T extends object = {}> = ({ isSuccess: true } & T) | { isSuccess: false; error: MadauthError };

export function toErrorCode(value: unknown): MadauthErrorCode {
  return (errorCodes as readonly unknown[]).includes(value) ? (value as MadauthErrorCode) : 'unknown';
}

export function ok<T extends object = {}>(value?: T): Result<T> {
  return { isSuccess: true, ...value } as Result<T>;
}

export function fail(code: MadauthErrorCode, message: string): { isSuccess: false; error: MadauthError } {
  return { isSuccess: false, error: { code, message } };
}
