/** A sign-in method shown in the login dialog. */
export interface LoginMethod {
  id: LoginMethodId;
  label: string;
  /** Short hint shown under the label. */
  description: string;
  status: 'available' | 'coming-soon';
}

export type LoginMethodId = 'password' | 'google' | 'totp' | 'email' | 'sms';

/**
 * All sign-in methods, in the order they appear in the dialog.
 * To add a method: add an entry here and handle its id in madauth-login.ts.
 */
export const loginMethods: LoginMethod[] = [
  {
    id: 'password',
    label: 'Username & password',
    description: 'Classic sign-in with your credentials',
    status: 'coming-soon',
  },
  {
    id: 'google',
    label: 'Continue with Google',
    description: 'Use your Google account',
    status: 'coming-soon',
  },
  {
    id: 'totp',
    label: 'Authenticator app',
    description: 'One-time code from your authenticator',
    status: 'coming-soon',
  },
  {
    id: 'email',
    label: 'E-mail link',
    description: 'Passwordless sign-in by e-mail',
    status: 'coming-soon',
  },
  {
    id: 'sms',
    label: 'SMS code',
    description: 'One-time code sent to your phone',
    status: 'coming-soon',
  },
];
