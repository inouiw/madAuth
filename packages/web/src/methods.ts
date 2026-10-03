import { en } from './strings.js';

/** A sign-in method shown in the login dialog. */
export interface LoginMethod {
  id: LoginMethodId;
  /** English name. The dialog shows the name in its own language, see `strings.ts`. */
  label: string;
  /** Short English hint, the tooltip of the method's button. */
  description: string;
}

export type LoginMethodId = 'password' | 'google' | 'totp' | 'email' | 'sms';

const order: LoginMethodId[] = ['google', 'password', 'totp', 'email', 'sms'];

/**
 * All sign-in methods, in the order they appear in the dialog. A method is offered when a provider for it
 * is passed to `Madauth.initialize`; the others show "coming soon".
 */
export const loginMethods: LoginMethod[] = order.map((id) => ({ id, ...en.methods[id] }));
