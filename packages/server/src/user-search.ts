// Searching users, for admins (POST /auth/admin/users/search): by role, by address and by when they signed up.
// The store is read page by page (StoreAdapter.scan) and the users are filtered here, so it works on every store
// and needs no index; its cost grows with the number of users, which is fine for admins now and then. What it
// finds is for showing: it may be outdated by the time it is shown, so no rule relies on it. See "Searching
// users" in docs/server.md.
import { claimsFromJson, parseRoles, rolesOf, type Claims } from './claims.js';
import { isValidEmail, normalizeEmail } from './password.js';
import { methodOf, type StoredUser, type Users } from './users.js';

export interface UserSearch {
  /** Users whose `claims.roles` hold it. */
  role?: string;
  /** The user with this address, normalized. */
  email?: string;
  /** Users who signed up after this time (milliseconds since 1970). */
  signedUpAfter?: number;
  /** Users who signed up before this time. */
  signedUpBefore?: number;
  /** true: only pending sign-ups, whose address isn't confirmed yet; false: only complete ones; absent: both. */
  pending?: boolean;
  limit: number;
  /** Where the previous page ended: its `cursor`. */
  cursor?: string;
}

/** A user as the search answers them. */
export interface FoundUser {
  id: string;
  email: string;
  name: string | null;
  emailVerified: boolean;
  claims: Claims;
  /** The methods of the user's sign-in methods and second factors, e.g. `['passkey', 'password']`. */
  methods: string[];
  /** When the sign-up was complete; null while it is pending. */
  signedUpAt: number | null;
  pending: boolean;
}

export const DEFAULT_SEARCH_LIMIT = 50;
export const MAX_SEARCH_LIMIT = 100;
/** The users one request reads at most; a search over more answers with a cursor to go on from. */
const MAX_READ = 1000;
/** The users read from the store at once. */
const PAGE = 100;
/** A cursor is a user's id. */
const MAX_CURSOR_LENGTH = 200;

const FIELDS = ['role', 'email', 'signedUpAfter', 'signedUpBefore', 'pending', 'limit', 'cursor'];

const isTime = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0;

/** The search in a request's body, or why it is none: an address that is not one is `invalid_email`. */
export function parseUserSearch(data: Record<string, unknown>): { search: UserSearch } | { error: 'invalid_email' | 'invalid_search'; message: string } {
  const invalid = (message: string) => ({ error: 'invalid_search' as const, message });
  // A filter madAuth doesn't have would otherwise find everyone.
  const unknown = Object.keys(data).find((key) => !FIELDS.includes(key));
  if (unknown) return invalid(`"${unknown}" is not a filter: the search takes ${FIELDS.join(', ')}.`);
  const { role, email, signedUpAfter, signedUpBefore, pending, limit = DEFAULT_SEARCH_LIMIT, cursor } = data;
  if (email !== undefined && !isValidEmail(email)) return { error: 'invalid_email', message: 'This is not a valid e-mail address.' };
  if (role !== undefined && (typeof role !== 'string' || !parseRoles([role]))) {
    return invalid('role must be a role name: lower-case letters, digits, "-" and "_", starting with a letter.');
  }
  if ((signedUpAfter !== undefined && !isTime(signedUpAfter)) || (signedUpBefore !== undefined && !isTime(signedUpBefore))) {
    return invalid('signedUpAfter and signedUpBefore must be times in milliseconds since 1970.');
  }
  if (pending !== undefined && typeof pending !== 'boolean') return invalid('pending must be true or false.');
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > MAX_SEARCH_LIMIT) {
    return invalid(`limit must be a whole number from 1 to ${MAX_SEARCH_LIMIT}.`);
  }
  if (cursor !== undefined && (typeof cursor !== 'string' || !cursor || cursor.length > MAX_CURSOR_LENGTH)) {
    return invalid('cursor must be the cursor of the previous page.');
  }
  return {
    search: {
      ...(role === undefined ? {} : { role }),
      ...(email === undefined ? {} : { email: normalizeEmail(email) }),
      ...(signedUpAfter === undefined ? {} : { signedUpAfter }),
      ...(signedUpBefore === undefined ? {} : { signedUpBefore }),
      ...(pending === undefined ? {} : { pending }),
      limit,
      ...(cursor === undefined ? {} : { cursor }),
    },
  };
}

/**
 * When the user's sign-up was complete; null while it is pending (0). Users from before schema version 7 have
 * no time and count as complete since they were created.
 */
const signedUpAt = (user: StoredUser): number | null => (user.signedUpAt === 0 ? null : (user.signedUpAt ?? user.createdAt));

/** Whether a user matches every filter of the search but the address. A pending sign-up has no time to match. */
function matches(user: StoredUser, search: UserSearch): boolean {
  const time = signedUpAt(user);
  return (
    (search.pending === undefined || search.pending === (time === null)) &&
    (search.role === undefined || rolesOf({ claims: claimsFromJson(user.claims) }).includes(search.role)) &&
    (search.signedUpAfter === undefined || (time !== null && time > search.signedUpAfter)) &&
    (search.signedUpBefore === undefined || (time !== null && time < search.signedUpBefore))
  );
}

async function found(users: Users, list: StoredUser[]): Promise<FoundUser[]> {
  return Promise.all(
    list.map(async (user) => {
      const time = signedUpAt(user);
      const methods = [...new Set((await users.accounts(user.id)).map(methodOf))].sort();
      return {
        id: user.id,
        email: user.emailNormalized,
        name: user.name,
        emailVerified: user.emailVerified,
        claims: claimsFromJson(user.claims),
        methods,
        signedUpAt: time,
        pending: time === null,
      };
    }),
  );
}

/**
 * The users that match, at most `limit`, in the store's order. `cursor` is there when more may follow: the
 * next page starts after it. A search reads at most a thousand users, so a page may hold fewer than `limit`, or
 * none, and still have a cursor. With an address, it is that one user or nobody.
 */
export async function searchUsers(users: Users, search: UserSearch): Promise<{ users: FoundUser[]; cursor?: string }> {
  if (search.email !== undefined) {
    const user = await users.findByEmail(search.email);
    return { users: await found(users, user && matches(user, search) ? [user] : []) };
  }
  const picked: StoredUser[] = [];
  let after = search.cursor;
  let read = 0;
  for (;;) {
    const page = await users.scan(after, PAGE);
    for (const user of page) {
      read++;
      after = user.id;
      if (matches(user, search)) picked.push(user);
      // The rest of the page is read again by the next request, which starts after this user.
      if (picked.length === search.limit) return { users: await found(users, picked), cursor: after };
    }
    if (page.length < PAGE) return { users: await found(users, picked) };
    if (read >= MAX_READ) return { users: await found(users, picked), cursor: after };
  }
}
