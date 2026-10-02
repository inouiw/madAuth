/** A sign-in method shown in the login dialog. */
export interface LoginMethod {
  id: LoginMethodId;
  label: string;
  /** Short hint shown under the label. */
  description: string;
}

export type LoginMethodId = 'password' | 'google' | 'totp' | 'email' | 'sms';

/**
 * All sign-in methods, in the order they appear in the dialog. A method is offered when a provider for it
 * is passed to `Madauth.initialize`; the others show "coming soon".
 */
export const loginMethods: LoginMethod[] = [
  {
    id: 'google',
    label: 'Continue with Google',
    description: 'Use your Google account',
  },
  {
    id: 'password',
    label: 'Username & password',
    description: 'Classic sign-in with your credentials',
  },
  {
    id: 'totp',
    label: 'Authenticator app',
    description: 'One-time code from your authenticator',
  },
  {
    id: 'email',
    label: 'E-mail link',
    description: 'Passwordless sign-in by e-mail',
  },
  {
    id: 'sms',
    label: 'SMS code',
    description: 'One-time code sent to your phone',
  },
];
