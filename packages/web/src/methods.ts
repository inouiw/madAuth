import { en } from './strings.js';

/** A sign-in method shown in the login dialog. */
export interface LoginMethod {
  id: LoginMethodId;
  /** English name. The dialog shows the name in its own language, see `strings.ts`. */
  label: string;
  /** Short English hint, the tooltip of the method's button. */
  description: string;
}

export type LoginMethodId = 'password' | 'google' | 'github' | 'totp' | 'email-link';

const order: LoginMethodId[] = ['google', 'github', 'password', 'totp', 'email-link'];

export const isLoginMethodId = (value: unknown): value is LoginMethodId => typeof value === 'string' && (order as string[]).includes(value);

/**
 * All sign-in methods, in the order they appear in the dialog. The dialog lists only the methods whose
 * provider is passed to `Madauth.initialize` and not left out because the server doesn't offer them.
 */
export const loginMethods: LoginMethod[] = order.map((id) => ({ id, ...en.methods[id] }));
