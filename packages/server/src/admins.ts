// The role `admin`: who holds it is in each user's claims (`claims.roles`), where the admin API and
// INITIAL_ADMIN_EMAIL put it. Two settings go with it: the admins madAuth knows of, so the last one keeps the
// role, and the value of INITIAL_ADMIN_EMAIL that was applied. See "The first admin" in docs/server.md.
import { ADMIN_ROLE, claimsFromJson, isAdmin, parseClaims, rolesOf, type Claims } from './claims.js';
import type { Settings } from './settings.js';
import type { StoredUser, Users } from './users.js';

/**
 * The id of the setting that lists the admins madAuth knows of, by their user ids: those who got the role
 * from the admin API or INITIAL_ADMIN_EMAIL, and those it met as admins at a sign-in or a call of the admin
 * API (e.g. admins from before madAuth 0.6).
 */
export const ADMINS_SETTING = 'admins';

/**
 * The id of the setting that lists the values of INITIAL_ADMIN_EMAIL that were applied, each with the user it
 * gave the role to. All of them, not only the last: while a deployment replaces its instances, old and new
 * values run side by side, and neither may apply again.
 */
export const INITIAL_ADMIN_SETTING = 'initialAdmin';

/** An entry of {@link INITIAL_ADMIN_SETTING}. */
export interface AppliedInitialAdmin {
  /** The value, normalized. */
  email: string;
  userId: string;
}

/** Whether `value` is among the applied values, as stored. */
const wasApplied = (stored: unknown, value: string): boolean =>
  Array.isArray(stored) && stored.some((entry: Partial<AppliedInitialAdmin> | null) => entry?.email === value);

/** Whether a stored user holds the role. */
const holdsRole = (user: StoredUser | null): boolean => !!user && isAdmin({ claims: claimsFromJson(user.claims) });

/** The claims with the role `admin` added; null if they have no room for it (see `parseClaims`). */
const withAdminRole = (claims: Claims): Claims | null => parseClaims({ ...claims, roles: [...rolesOf({ claims }), ADMIN_ROLE] });

export class Admins {
  constructor(
    private readonly settings: Settings,
    private readonly users: Users,
  ) {}

  /** Notes that the user holds the role: they got it, or madAuth met an admin it didn't know of yet. Writes only then. */
  async note(userId: string, updatedBy: string | null): Promise<void> {
    await this.settings.change<string[]>(ADMINS_SETTING, (known = []) => (known.includes(userId) ? null : [...known, userId].sort()), updatedBy);
  }

  /**
   * Takes the user off the list before their role or their account goes. Resolves to false, changing nothing,
   * if no other admin would be left: none of the others on the list still holds the role. The list's write
   * decides, so of two changes at once that would each leave only the other admin, one is refused.
   */
  async release(userId: string, updatedBy: string | null): Promise<boolean> {
    const left = await this.settings.change<string[]>(
      ADMINS_SETTING,
      async (known = []) => {
        // Others whose role went meanwhile (e.g. straight in the store) don't count, and leave the list.
        const others = known.filter((id) => id !== userId);
        const holders = (await Promise.all(others.map(async (id) => (holdsRole(await this.users.findById(id)) ? [id] : [])))).flat();
        return holders.length ? holders : null;
      },
      updatedBy,
    );
    return left !== null;
  }

  /**
   * INITIAL_ADMIN_EMAIL (`value`, normalized): gives the role to the user with that address as they start a
   * session, with their address proven, once per value. The setting's write decides, so of two sign-ins at
   * once only one applies it, and a value that was applied does nothing again, also when its user lost the
   * role since or it comes back after another one. Resolves to the user with their new claims, or null when
   * nothing changed.
   */
  async applyInitial(user: StoredUser, value: string): Promise<{ user: StoredUser; claims: Claims } | null> {
    if (user.emailNormalized !== value || !user.emailVerified) return null;
    if (wasApplied(await this.settings.get(INITIAL_ADMIN_SETTING), value)) return null;
    // Checked before the value counts as applied: claims without room for the role leave it for a later sign-in.
    if (!withAdminRole(claimsFromJson(user.claims))) {
      console.error(`[madauth] INITIAL_ADMIN_EMAIL: the claims of ${value} have no room for the role "${ADMIN_ROLE}" (at most 20 roles, 2048 characters).`);
      return null;
    }
    const won = await this.settings.change<AppliedInitialAdmin[]>(
      INITIAL_ADMIN_SETTING,
      (current) => (wasApplied(current, value) ? null : [...(Array.isArray(current) ? current : []), { email: value, userId: user.id }]),
      null,
    );
    if (!won) return null;
    const written = holdsRole(user) ? user : await this.users.changeClaims(user, (claims) => withAdminRole(claims) ?? claims);
    if (!written) {
      console.error(`[madauth] INITIAL_ADMIN_EMAIL: the role "${ADMIN_ROLE}" could not be added to ${value}: their claims kept changing, or the user is gone.`);
      return null;
    }
    await this.note(user.id, null);
    return written === user ? null : { user: written, claims: claimsFromJson(written.claims) };
  }
}
