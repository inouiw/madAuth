// `@madauth/web`: the client and the dialog, which registers itself as `<madauth-login>`. `./client.ts` is the
// same without the dialog (`@madauth/web/client`).
import { MadauthLogin } from './madauth-login.js';

export * from './client.js';
export {
  MadauthLogin,
  type AuthenticatorEnabledDetail,
  type ErrorDetail,
  type PasskeyAddedDetail,
  type SignedInDetail,
  type SmsEnabledDetail,
  type SmsFailedDetail,
} from './madauth-login.js';

if (!customElements.get('madauth-login')) {
  customElements.define('madauth-login', MadauthLogin);
}
