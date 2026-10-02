/** The signed-in user. */
export interface MadauthUser {
  /** Stable id, e.g. `google:<sub>`. */
  id: string;
  email?: string;
  name?: string;
  picture?: string;
}

export type MadauthErrorCode =
  | 'invalid_options'
  | 'network'
  | 'flow_not_enabled'
  | 'gis_load_failed'
  | 'not_initialized'
  | 'cancelled'
  | 'verification_failed'
  | 'email_unverified'
  | 'no_session'
  | 'unknown';

export interface MadauthError {
  code: MadauthErrorCode;
  /** Human-readable details, e.g. which option is invalid. */
  message: string;
}

/** What every madAuth method resolves to. Expected failures are returned, never thrown. */
export type Result<T extends object = {}> = ({ isSuccess: true } & T) | { isSuccess: false; error: MadauthError };

const errorCodes: readonly MadauthErrorCode[] = [
  'invalid_options',
  'network',
  'flow_not_enabled',
  'gis_load_failed',
  'not_initialized',
  'cancelled',
  'verification_failed',
  'email_unverified',
  'no_session',
  'unknown',
];

export function toErrorCode(value: unknown): MadauthErrorCode {
  return errorCodes.includes(value as MadauthErrorCode) ? (value as MadauthErrorCode) : 'unknown';
}

export function ok<T extends object = {}>(value?: T): Result<T> {
  return { isSuccess: true, ...value } as Result<T>;
}

export function fail(code: MadauthErrorCode, message: string): { isSuccess: false; error: MadauthError } {
  return { isSuccess: false, error: { code, message } };
}
