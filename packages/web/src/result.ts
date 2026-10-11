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
   * How the session was authenticated (RFC 8176): `pwd` (password), `google`, `email` (the e-mail link),
   * `otp` (the authenticator app, on its own or as the second factor), `sms` (a code by SMS as the second
   * factor), e.g. `['pwd', 'otp']`. Present on a user that comes with a session.
   */
  amr?: string[];
}

/** A second factor: a code from the authenticator app, or one sent by SMS. */
export type SecondFactor = 'totp' | 'sms';

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
  'totp_required',
  'totp_setup_required',
  'sms_required',
  'invalid_phone',
  'no_phone',
  'too_soon',
  'challenge_expired',
  'setup_expired',
  'required_by_policy',
  'code_required',
  'no_authenticator',
  'only_method',
  'other_method',
  'unknown',
] as const;

export type MadauthErrorCode = (typeof errorCodes)[number];

export interface MadauthError {
  code: MadauthErrorCode;
  /** Human-readable details, e.g. which option is invalid. */
  message: string;
  /** With `totp_required`, `sms_required` and `totp_setup_required`: the method whose sign-in goes on with the second step. */
  method?: string;
  /** With `totp_required` and `sms_required`: the second factors the user can finish the sign-in with, e.g. `['totp', 'sms']`. */
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
