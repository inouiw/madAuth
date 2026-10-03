// Roles: names such as `admin` that madAuth puts into the session of an e-mail address. They are stored
// per address, not per user, so they apply whichever way the owner of the address signs in; Google
// sign-in stores no user at all.
import type { StoreAdapter } from './store/schema.js';

/** The role that may read and set roles through the HTTP API. */
export const ADMIN_ROLE = 'admin';

/** Roles one address can hold. */
export const MAX_ROLES = 20;

const ROLE_NAME = /^[a-z][a-z0-9_-]{0,31}$/;

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

export function sameRoles(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((role, i) => role === b[i]);
}

/** The roles of e-mail addresses, on top of the StoreAdapter. Addresses are passed normalized. */
export class Roles {
  constructor(private readonly store: StoreAdapter) {}

  /** The address's roles, sorted; empty if it has none. */
  async get(emailNormalized: string): Promise<string[]> {
    const record = await this.store.findOne('role', { id: emailNormalized });
    return typeof record?.roles === 'string' && record.roles ? record.roles.split(' ') : [];
  }

  /** Replaces the address's roles. `updatedBy` is the address of the admin, or null for the command line. */
  async set(emailNormalized: string, roles: string[], updatedBy: string | null): Promise<void> {
    if (!roles.length) {
      await this.remove(emailNormalized);
      return;
    }
    const data = { roles: roles.join(' '), updatedAt: Date.now(), updatedBy };
    if ((await this.store.update('role', { id: emailNormalized }, data)) === 1) return;
    // No record yet. If another request created it meanwhile, write over that one.
    if (!(await this.store.create('role', { id: emailNormalized, ...data }))) {
      await this.store.update('role', { id: emailNormalized }, data);
    }
  }

  async remove(emailNormalized: string): Promise<void> {
    await this.store.delete('role', { id: emailNormalized });
  }
}
