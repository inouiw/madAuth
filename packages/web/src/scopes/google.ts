import { createButtonApi, type ButtonApi, type ButtonRenderOptions } from './button.js';
import type { Core } from './core.js';

export type GoogleButtonOptions = ButtonRenderOptions;

/** Google sign-in for custom login screens. Needs `GoogleFedcm` or `GoogleRedirect` in `Madauth.initialize`. */
export interface GoogleApi extends ButtonApi {
  /**
   * Renders Google's sign-in button into `container`: the FedCM button with `GoogleFedcm`, or a button that
   * starts the redirect with `GoogleRedirect`. Can be called before `initialize` has finished.
   */
  renderButton(container: HTMLElement, options?: GoogleButtonOptions): ReturnType<ButtonApi['renderButton']>;
}

export const createGoogleApi = (core: Core): GoogleApi =>
  createButtonApi(core, 'google', 'Pass new GoogleFedcm() or new GoogleRedirect() to Madauth.initialize to use Madauth.google.');
