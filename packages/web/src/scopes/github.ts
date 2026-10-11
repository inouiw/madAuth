import { createButtonApi, type ButtonApi, type ButtonRenderOptions } from './button.js';
import type { Core } from './core.js';

export type GitHubButtonOptions = ButtonRenderOptions;

/** GitHub sign-in for custom login screens. Needs `GitHub` in `Madauth.initialize`. */
export interface GitHubApi extends ButtonApi {
  /** Renders a "Continue with GitHub" button that starts the redirect into `container`. Can be called before `initialize` has finished. */
  renderButton(container: HTMLElement, options?: GitHubButtonOptions): ReturnType<ButtonApi['renderButton']>;
}

export const createGitHubApi = (core: Core): GitHubApi => createButtonApi(core, 'github', 'Pass new GitHub() to Madauth.initialize to use Madauth.github.');
