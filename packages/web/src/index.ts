import { MadauthLogin } from './madauth-login.js';

export { MadauthLogin, type SignedInDetail } from './madauth-login.js';
export { loginMethods, type LoginMethod, type LoginMethodId } from './methods.js';

if (!customElements.get('madauth-login')) {
  customElements.define('madauth-login', MadauthLogin);
}
