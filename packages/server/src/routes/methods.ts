// A signed-in user's sign-in methods: listing them, and removing one. Adding one is up to each method's own
// routes (a password, the e-mail link, Google, GitHub, a passkey, the authenticator app); all of them only for
// a user who signed in recently, see `recentUser`. The rules are described in docs/sign-in-methods.md.
import type { Hono } from 'hono';
import type { AppContext } from '../app.js';
import { isMethodId, signsIn, type MethodId } from '../settings.js';
import { methodOf, toMadauthUser, type StoredAccount } from '../users.js';
import { requiredByPolicy } from './challenge.js';
import { body, error, noSession, recentUser } from './helpers.js';

/** A sign-in method of the user as the list shows it. */
export interface MethodEntry {
  /** The account's id (`acc_…`), which removing it takes. */
  id: string;
  method: MethodId;
  /** Whether it signs the user in on its own right now (the admin allows it as a sign-in method). */
  signIn: boolean;
  /** Whether `POST /auth/methods/remove` removes it; the authenticator app takes a code of its own. */
  removable: boolean;
  createdAt: number;
  /** Google and GitHub: the provider's address at the last sign-in. */
  email?: string;
  /** A passkey: its name, and when it last signed in (0 never). */
  name?: string;
  lastUsedAt?: number;
}

/** The methods the generic route removes; the authenticator app and the phone take a code of their own to remove. */
const REMOVABLE: readonly string[] = ['password', 'google', 'github', 'email-link', 'passkey'];

/**
 * The routes. `onRemoved` runs after an account was removed, before the answer: GitHub revokes its grant
 * there with the token kept on the account.
 */
export function methodRoutes(app: Hono, ctx: AppContext, onRemoved: (account: StoredAccount) => Promise<void>): void {
  const { users } = ctx;

  app.get('/auth/methods', async (c) => {
    const session = await ctx.currentUser(c);
    if (!session) return noSession(c);
    const methods = await ctx.methods(c);
    const accounts = await users.methodAccounts(session.id);
    const entries = accounts.map((account): MethodEntry => {
      const method = methodOf(account) as MethodId;
      return {
        id: account.id,
        method,
        signIn: signsIn(method, ctx.configured, methods),
        removable: REMOVABLE.includes(method),
        createdAt: account.createdAt,
        ...((method === 'google' || method === 'github') && account.email ? { email: account.email } : {}),
        ...(method === 'passkey' ? { name: account.name ?? '', lastUsedAt: account.lastUsedAt ?? 0 } : {}),
      };
    });
    return c.json({ methods: entries });
  });

  app.post('/auth/methods/remove', async (c) => {
    const user = await recentUser(c, ctx);
    if (user instanceof Response) return user;
    const data = await body(c);
    const account = typeof data.id === 'string' ? (await users.methodAccounts(user.id)).find((a) => a.id === data.id) : undefined;
    if (!account) return error(c, 404, 'method_not_found', 'You have no such sign-in method.');
    const method = methodOf(account) as MethodId;
    if (!REMOVABLE.includes(method)) {
      return error(c, 400, 'invalid_options', 'The authenticator app is removed with a code from it: use /auth/totp/remove.');
    }
    const methods = await ctx.methods(c);
    if (method === 'passkey') {
      // The user's passkeys may be their second factor: one of several may go, the last only with another factor.
      const others = (await users.passkeys(user.id)).length > 1;
      const required = await requiredByPolicy(c, ctx, user.id, 'passkey', 'your last passkey', others);
      if (required) return required;
    }
    // Without it, nobody could sign in as the user.
    if (await users.isLastWayIn(user.id, (m) => isMethodId(m) && signsIn(m, ctx.configured, methods), (a) => a.id === account.id)) {
      return error(c, 403, 'only_method', "This is the only way you sign in, so it can't be removed. Add another way to sign in first, or delete your account.");
    }
    if (!(await users.unlinkAccount(account.key))) return c.json({});
    await onRemoved(account);
    await ctx.emit('user.method_removed', { user: toMadauthUser(user), method, ...(method === 'passkey' ? { passkey: { id: account.id, name: account.name } } : {}) });
    return c.json({});
  });
}
