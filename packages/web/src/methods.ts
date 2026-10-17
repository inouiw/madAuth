import { en } from './strings.js';

/** A built-in sign-in method shown in the login dialog. */
export interface LoginMethod {
  id: BuiltInMethodId;
  /** English name. The dialog shows the name in its own language, see `strings.ts`. */
  label: string;
  /** Short English hint, the tooltip of the method's button. */
  description: string;
}

/** madAuth's own sign-in methods. */
export type BuiltInMethodId = 'password' | 'google' | 'github' | 'authenticator' | 'email-link' | 'passkey';

/** A sign-in method: one of madAuth's own, or the id of an OpenID Connect provider an admin added, e.g. `'gitlab'`. */
export type LoginMethodId = BuiltInMethodId | (string & {});

const order: BuiltInMethodId[] = ['passkey', 'google', 'github', 'password', 'authenticator', 'email-link'];

export const isBuiltInMethodId = (value: unknown): value is BuiltInMethodId => typeof value === 'string' && (order as string[]).includes(value);

/**
 * The built-in sign-in methods, in the order they appear in the dialog. The dialog lists only the methods
 * whose provider is passed to `Madauth.initialize` and not left out because the server doesn't offer them,
 * and the OpenID Connect providers the server offers after GitHub.
 */
export const loginMethods: LoginMethod[] = order.map((id) => ({ id, ...en.methods[id] }));
