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
export { GitHub } from './providers/github.js';
export { Password } from './providers/password.js';
export { Totp } from './providers/totp.js';
export { EmailLink } from './providers/email-link.js';
export { Passkey } from './providers/passkey.js';
export type { DeletedAccount, PendingStep, SecondFactorPolicy, SignInProvider } from './providers/provider.js';
export type {
  ConfirmResetOptions,
  PasswordApi,
  SendEmailOptions,
  SignInWithPasswordOptions,
  SignUpOptions,
} from './scopes/password.js';
export type { GoogleApi, GoogleButtonOptions } from './scopes/google.js';
export type { GitHubApi, GitHubButtonOptions } from './scopes/github.js';
export type { CodeOptions, SignInWithTotpOptions, TotpApi, TotpPolicy, TotpSetup, TotpSignUpOptions } from './scopes/totp.js';
export type { EmailLinkApi } from './scopes/email-link.js';
export type { SmsApi } from './scopes/sms.js';
export type { PasskeyApi, PasskeyInfo, PasskeySignInOptions, PasskeySignUpOptions } from './scopes/passkey.js';
export type { MethodsApi, SignInMethodInfo } from './scopes/methods.js';
export type { ButtonRenderOptions } from './scopes/button.js';
export type { AdminApi, Claims, MethodId, MethodSetting, MethodToSet, MethodsToSet, PasswordRules, Settings } from './scopes/admin.js';
export type { RatePassword } from './strength.js';
export {
  MadauthLogin,
  type AuthenticatorEnabledDetail,
  type ErrorDetail,
  type PasskeyAddedDetail,
  type SignedInDetail,
  type SmsEnabledDetail,
  type SmsFailedDetail,
} from './madauth-login.js';
export { loginMethods, type LoginMethod, type LoginMethodId } from './methods.js';

if (!customElements.get('madauth-login')) {
  customElements.define('madauth-login', MadauthLogin);
}
