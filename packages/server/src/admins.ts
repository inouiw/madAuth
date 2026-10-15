// The first admin: INITIAL_ADMIN_EMAIL gives the role `admin` (in the user's claims, `claims.roles`) to the user
// with that address, once per value. The setting `initialAdmin` records the values applied. See "The first
// admin" in docs/server.md.
import { ADMIN_ROLE, claimsFromJson, isAdmin, parseClaims, rolesOf, type Claims } from './claims.js';
import type { Settings } from './settings.js';
import type { StoredUser, Users } from './users.js';

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
  /** The INITIAL_ADMIN_EMAIL value this instance knows to be applied: applied stays applied. */
  private applied: string | undefined;

  constructor(
    private readonly settings: Settings,
    private readonly users: Users,
  ) {}

  /**
   * INITIAL_ADMIN_EMAIL (`value`, normalized): gives the role to the user with that address as they start a
   * session, with their address proven, once per value. The setting's write decides, so of two sign-ins at
   * once only one applies it, and a value that was applied does nothing again, also when its user lost the
   * role since or it comes back after another one. Resolves to the user with their new claims, or null when
   * nothing changed.
   */
  async applyInitial(userId: string, value: string): Promise<{ user: StoredUser; claims: Claims } | null> {
    if (this.applied === value) return null;
    if (wasApplied(await this.settings.get(INITIAL_ADMIN_SETTING), value)) {
      this.applied = value;
      return null;
    }
    const user = await this.users.findById(userId);
    if (!user || user.emailNormalized !== value || !user.emailVerified) return null;
    // Checked before the value counts as applied: claims without room for the role leave it for a later sign-in.
    if (!withAdminRole(claimsFromJson(user.claims))) {
      console.error(`[madauth] INITIAL_ADMIN_EMAIL: the claims of ${value} have no room for the role "${ADMIN_ROLE}" (at most 20 roles, 2048 characters).`);
      return null;
    }
    const entry: AppliedInitialAdmin = { email: value, userId: user.id };
    const won = await this.settings.change<AppliedInitialAdmin[]>(
      INITIAL_ADMIN_SETTING,
      (current) => (wasApplied(current, value) ? null : [...(Array.isArray(current) ? current : []), entry]),
      null,
    );
    if (!won) return null;
    const written = holdsRole(user) ? user : await this.users.changeClaims(user, (claims) => withAdminRole(claims) ?? claims);
    if (!written) {
      // The value counts as applied only with the role in place: taken back, it applies at a later sign-in.
      await this.settings.change<AppliedInitialAdmin[]>(INITIAL_ADMIN_SETTING, (current = []) => current.filter((applied) => applied.email !== value), null);
      console.error(`[madauth] INITIAL_ADMIN_EMAIL: the role "${ADMIN_ROLE}" could not be added to ${value}: their claims kept changing, or the user is gone.`);
      return null;
    }
    this.applied = value;
    return written === user ? null : { user: written, claims: claimsFromJson(written.claims) };
  }
}
