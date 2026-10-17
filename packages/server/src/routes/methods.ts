// A signed-in user's sign-in methods: listing them, and removing one. Adding one is up to each method's own
// routes (a password, the e-mail link, Google, GitHub, a passkey, the authenticator app); all of them only for
// a user who signed in recently, see `recentUser`. The rules are described in docs/sign-in-methods.md.
import type { Context, Hono } from 'hono';
import type { AppContext } from '../app.js';
import {
  SECOND_FACTORS,
  factorsOn,
  requiringSecondFactor,
  signInPredicate,
  type MethodWithSecondFactor,
} from '../settings.js';
import { factorsAmong, isProviderAccount, lastWayIn, methodOf, toMadauthUser, type StoredAccount } from '../users.js';
import { body, error, noSession, recentUser } from './helpers.js';

/** A sign-in method of the user as the list shows it. */
export interface MethodEntry {
  /** The account's id (`acc_…`), which removing it takes. */
  id: string;
  /** A built-in method, or the id of an OpenID Connect provider. */
  method: string;
  /** Whether it signs the user in on its own right now (the admin allows it as a sign-in method). */
  signIn: boolean;
  /** Whether `POST /auth/methods/remove` removes it; the authenticator app takes a code of its own. */
  removable: boolean;
  createdAt: number;
  /** A provider (Google, GitHub, an OpenID Connect provider): its address at the last sign-in. */
  email?: string;
  /** A passkey: its name, and when it last signed in (0 never). */
  name?: string;
  lastUsedAt?: number;
}

/** Whether the generic route removes a method: the authenticator app and the phone take a code of their own to remove. */
const isRemovable = (method: string) => method !== 'authenticator' && method !== 'sms';

/** How a message names the methods whose policy can require a second factor. A method without a name here does not compile. */
const POLICY_NAMES = {
  google: 'Google',
  github: 'GitHub',
  password: 'e-mail & password',
  'email-link': 'the e-mail link',
  passkey: 'a passkey',
} satisfies Record<MethodWithSecondFactor, string>;

const isFactor = (method: string) => (SECOND_FACTORS as readonly string[]).includes(method);

/**
 * Why `account` can't go, as the answer to send; null if it can. `accounts` are all of the user's, as read.
 * Each method whose policy is `required` needs a second factor the user keeps, which is on and isn't the
 * method itself (a passkey is no second factor of a passkey sign-in), unless the removal takes the method
 * away (the last passkey). And the user must keep a way to sign in (`only_method`). `what` names the account.
 */
export async function removalRefused(c: Context, ctx: AppContext, accounts: StoredAccount[], account: StoredAccount, what: string): Promise<Response | null> {
  const { configured, settings: methods, providers } = await ctx.methods(c);
  const after = accounts.filter((a) => a.id !== account.id);
  const left = factorsAmong(after, factorsOn(configured, methods));
  const stillUsed = (method: string) => !isFactor(method) || after.some((a) => methodOf(a) === method);
  const lacking = requiringSecondFactor(configured, methods).filter((method) => stillUsed(method) && !left.some((f) => f !== method));
  if (lacking.length) {
    // An OpenID Connect provider's method is its id: it is named as its admin named it.
    const nameOf = (method: string) => POLICY_NAMES[method as MethodWithSecondFactor] ?? providers.find((provider) => provider.id === method)?.name ?? method;
    const names = lacking.map(nameOf).join(' and ');
    return error(c, 403, 'required_by_policy', `Signing in with ${names} requires a second factor, so ${what} can't be removed. Set up another second factor first, or delete your account.`);
  }
  return lastWayIn(accounts, signInPredicate(configured, methods), (a) => a.id === account.id) ? onlyMethod(c) : null;
}

const onlyMethod = (c: Context) =>
  error(c, 403, 'only_method', "This is the only way you sign in, so it can't be removed. Add another way to sign in first, or delete your account.");

/**
 * Removes `account`, which {@link removalRefused} let go, from `accounts` (all of the user's, as read).
 * Another removal at the same time may have taken the user's other way in: then this one is put back
 * (`only_method`). Resolves to true when it was removed, false when it was gone already.
 */
export async function removeAccount(c: Context, ctx: AppContext, accounts: StoredAccount[], account: StoredAccount): Promise<boolean | Response> {
  if (!(await ctx.users.unlinkAccount(account.key))) return false;
  const methods = await ctx.methods(c);
  const signsIn = signInPredicate(methods.configured, methods.settings);
  const now = await ctx.users.accounts(account.userId);
  if (accounts.some((a) => signsIn(methodOf(a))) && !now.some((a) => signsIn(methodOf(a)))) {
    await ctx.users.restoreAccount(account);
    return onlyMethod(c);
  }
  return true;
}

/**
 * The routes. `onRemoved` runs after an account was removed, before the answer: GitHub revokes its grant
 * there with the token kept on the account.
 */
export function methodRoutes(app: Hono, ctx: AppContext, onRemoved: (account: StoredAccount) => Promise<void>): void {
  const { users } = ctx;

  app.get('/auth/methods', async (c) => {
    const session = await ctx.currentUser(c);
    if (!session) return noSession(c);
    const [methods, accounts] = await Promise.all([ctx.methods(c), users.accounts(session.id)]);
    const signsIn = signInPredicate(methods.configured, methods.settings);
    const entries = accounts
      .filter((account) => methodOf(account) !== 'sms')
      .map((account): MethodEntry => {
        const method = methodOf(account);
        return {
          id: account.id,
          method,
          signIn: signsIn(method),
          removable: isRemovable(method),
          createdAt: account.createdAt,
          ...(isProviderAccount(account) && account.email ? { email: account.email } : {}),
          ...(method === 'passkey' ? { name: account.name ?? '', lastUsedAt: account.lastUsedAt ?? 0 } : {}),
        };
      });
    return c.json({ methods: entries });
  });

  app.post('/auth/methods/remove', async (c) => {
    const user = await recentUser(c, ctx);
    if (user instanceof Response) return user;
    const [data, accounts] = await Promise.all([body(c), users.accounts(user.id)]);
    const account = accounts.find((a) => a.id === data.id && methodOf(a) !== 'sms');
    if (!account) return error(c, 404, 'method_not_found', 'You have no such sign-in method.');
    const method = methodOf(account);
    if (!isRemovable(method)) {
      return error(c, 400, 'invalid_options', 'The authenticator app is removed with a code from it: use /auth/authenticator/remove.');
    }
    const refused = await removalRefused(c, ctx, accounts, account, method === 'passkey' ? 'this passkey' : 'this sign-in method');
    if (refused) return refused;
    const removed = await removeAccount(c, ctx, accounts, account);
    if (removed instanceof Response) return removed;
    if (!removed) return c.json({});
    await onRemoved(account);
    await ctx.emit('user.method_removed', { user: toMadauthUser(user), method, ...(method === 'passkey' ? { passkey: { id: account.id, name: account.name } } : {}) });
    return c.json({});
  });
}
