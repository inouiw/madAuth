import { MadauthLogin } from './madauth-login.js';

export { Madauth, type AuthStateListener, type MadauthOptions, type SignInOptions } from './madauth.js';
export type { MadauthError, MadauthErrorCode, MadauthUser, Result } from './result.js';
export { GoogleFedcm, type GoogleFedcmOptions } from './providers/google-fedcm.js';
export { GoogleRedirect } from './providers/google-redirect.js';
export { Password } from './providers/password.js';
export type { SignInProvider } from './providers/provider.js';
export type {
  ConfirmResetOptions,
  PasswordApi,
  SendEmailOptions,
  SignInWithPasswordOptions,
  SignUpOptions,
} from './scopes/password.js';
export type { GoogleApi, GoogleButtonOptions } from './scopes/google.js';
export type { AdminApi, Claims, MethodSetting, Settings } from './scopes/admin.js';
export { MadauthLogin, type ErrorDetail, type SignedInDetail } from './madauth-login.js';
export { loginMethods, type LoginMethod, type LoginMethodId } from './methods.js';

if (!customElements.get('madauth-login')) {
  customElements.define('madauth-login', MadauthLogin);
}
