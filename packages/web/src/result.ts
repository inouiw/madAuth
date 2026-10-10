/** The signed-in user. */
export interface MadauthUser {
  /** Stable id (`usr_…`), the same whichever way the user signs in. */
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  /** What admins attached to the user, e.g. `{ roles: ['admin'] }`. Absent without claims. */
  claims?: Record<string, unknown>;
}

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
  'unknown',
] as const;

export type MadauthErrorCode = (typeof errorCodes)[number];

export interface MadauthError {
  code: MadauthErrorCode;
  /** Human-readable details, e.g. which option is invalid. */
  message: string;
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
