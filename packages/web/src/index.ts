import { MadauthLogin } from './madauth-login.js';

export {
  Madauth,
  type AuthStateListener,
  type DeleteAccountOptions,
  type InitializeResult,
  type MadauthOptions,
  type SignInOptions,
} from './madauth.js';
export type { MadauthError, MadauthErrorCode, MadauthUser, Result, SecondFactor } from './result.js';
export { GoogleFedcm, type GoogleFedcmOptions } from './providers/google-fedcm.js';
export { GoogleRedirect } from './providers/google-redirect.js';
export { Password } from './providers/password.js';
export { Totp } from './providers/totp.js';
export { EmailLink } from './providers/email-link.js';
export type { DeletedAccount, PendingStep, SecondFactorPolicy, SignInProvider } from './providers/provider.js';
export type {
  ConfirmResetOptions,
  PasswordApi,
  SendEmailOptions,
  SignInWithPasswordOptions,
  SignUpOptions,
} from './scopes/password.js';
export type { GoogleApi, GoogleButtonOptions } from './scopes/google.js';
export type { CodeOptions, SignInWithTotpOptions, TotpApi, TotpPolicy, TotpSetup, TotpSignUpOptions } from './scopes/totp.js';
export type { EmailLinkApi } from './scopes/email-link.js';
export type { SmsApi } from './scopes/sms.js';
export type { AdminApi, Claims, MethodSetting, MethodsToSet, Settings } from './scopes/admin.js';
export { MadauthLogin, type AuthenticatorEnabledDetail, type ErrorDetail, type SignedInDetail, type SmsEnabledDetail, type SmsFailedDetail } from './madauth-login.js';
export { loginMethods, type LoginMethod, type LoginMethodId } from './methods.js';

if (!customElements.get('madauth-login')) {
  customElements.define('madauth-login', MadauthLogin);
}
