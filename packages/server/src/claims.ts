// Claims: what admins attach to a user, e.g. `{ roles: ['admin'], plan: 'pro' }`. They go into the session
// token as `claims`, so apps and backends can tell what a user may do. madAuth itself only knows the role
// `admin` in `claims.roles`: the role that may manage claims and settings.
import type { MadauthUser } from './user.js';

/** A user's claims: a JSON object. */
export type Claims = Record<string, unknown>;

/** The role that may manage claims and settings through the HTTP API. */
export const ADMIN_ROLE = 'admin';

/** Roles one user can hold. */
export const MAX_ROLES = 20;
/** Length of the claims as JSON: they travel in every session token and cookie. */
export const MAX_CLAIMS_LENGTH = 2048;

const ROLE_NAME = /^[a-z][a-z0-9_-]{0,31}$/;
const CLAIM_NAME = /^[a-zA-Z][a-zA-Z0-9_]{0,63}$/;

/**
 * Checks role names and returns them sorted and without duplicates, or null if `input` is not a list of
 * valid names: lower-case letters, digits, `-` and `_`, starting with a letter, at most 32 characters.
 */
export function parseRoles(input: unknown): string[] | null {
  if (!Array.isArray(input)) return null;
  if (!input.every((role): role is string => typeof role === 'string' && ROLE_NAME.test(role))) return null;
  const roles = [...new Set(input)].sort();
  return roles.length <= MAX_ROLES ? roles : null;
}

/**
 * Checks a claims object and returns it in canonical form (keys sorted, `roles` sorted and without
 * duplicates), or null if `input` is not one: a JSON object whose keys are names (letters, digits and `_`,
 * starting with a letter, at most 64 characters), whose `roles`, if any, is a valid list of role names,
 * and which is at most {@link MAX_CLAIMS_LENGTH} characters as JSON.
 */
export function parseClaims(input: unknown): Claims | null {
  if (!isJsonObject(input)) return null;
  const claims: Claims = {};
  for (const key of Object.keys(input).sort()) {
    const value = input[key];
    if (!CLAIM_NAME.test(key) || !isJsonValue(value)) return null;
    if (key === 'roles') {
      const roles = parseRoles(value);
      if (!roles) return null;
      claims[key] = roles;
    } else {
      claims[key] = value;
    }
  }
  return JSON.stringify(claims).length <= MAX_CLAIMS_LENGTH ? claims : null;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/** Whether JSON carries the value as it is (a function, undefined, NaN or Infinity would change or vanish). */
function isJsonValue(value: unknown): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  return isJsonObject(value) && Object.values(value).every(isJsonValue);
}

/** Whether two claims objects hold the same values (in canonical form, as {@link parseClaims} returns them). */
export function sameClaims(a: Claims | undefined, b: Claims | undefined): boolean {
  return JSON.stringify(a ?? {}) === JSON.stringify(b ?? {});
}

/** The stored JSON of a user's claims as an object; empty if there is none or it is not an object. */
export function claimsFromJson(json: string | null | undefined): Claims {
  if (!json) return {};
  try {
    const parsed: unknown = JSON.parse(json);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Claims) : {};
  } catch {
    return {};
  }
}

/** The roles in a user's claims; empty without any. */
export function rolesOf(user: Pick<MadauthUser, 'claims'>): string[] {
  const roles = user.claims?.roles;
  return Array.isArray(roles) ? roles.filter((role): role is string => typeof role === 'string') : [];
}

export function isAdmin(user: Pick<MadauthUser, 'claims'>): boolean {
  return rolesOf(user).includes(ADMIN_ROLE);
}
