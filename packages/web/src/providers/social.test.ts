// GitLab, LinkedIn and Slack (presets of the OpenID Connect providers), Facebook and X in the web library: the
// buttons madAuth adds when the server offers them, each with its logo. See "Providers" in docs/custom-ui.md.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { SERVER, fakeServer, resetAll, settle } from '../test-helpers.js';
import { Password } from './password.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

const shadow = () => document.querySelector('madauth-login')!.shadowRoot!;
const $ = <T extends HTMLElement = HTMLElement>(selector: string) => shadow().querySelector<T>(selector);
const $$ = (selector: string) => [...shadow().querySelectorAll<HTMLElement>(selector)];

describe('the social providers’ buttons', () => {
  it('SW1: each shows "Continue with <name>" with its logo and colours, and starts its redirect', async () => {
    const server = fakeServer();
    server.oidc = [
      { id: 'gitlab-corp', name: 'Corp GitLab', secondFactor: 'none', preset: 'gitlab' },
      { id: 'linkedin', name: 'LinkedIn', secondFactor: 'none', preset: 'linkedin' },
      { id: 'slack', name: 'Slack', secondFactor: 'none', preset: 'slack' },
      { id: 'okta', name: 'Okta', secondFactor: 'none' },
      { id: 'facebook', kind: 'facebook', name: 'Facebook', secondFactor: 'none' },
      { id: 'x', kind: 'x', name: 'X', secondFactor: 'none' },
    ];
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    history.replaceState(null, '', '/page');

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    void Madauth.showSignInDialog();
    await settle();

    expect($$('.button-slot').map((slot) => slot.dataset.button)).toEqual(['gitlab-corp', 'linkedin', 'slack', 'okta', 'facebook', 'x']);
    const button = (id: string) => $<HTMLButtonElement>(`[data-button="${id}"] button`)!;
    expect(button('gitlab-corp').textContent).toBe('Continue with Corp GitLab');
    expect(button('gitlab-corp').querySelector('path')!.getAttribute('fill')).toBe('#fc6d26');
    expect(button('linkedin').style.background).toBe('#0a66c2');
    expect(button('facebook').style.background).toBe('#1877f2');
    expect(button('x').style.background).toBe('#000000');
    // A provider without a preset keeps the neutral mark.
    expect(button('okta').querySelector('path')!.getAttribute('fill')).toBeNull();

    button('x').click();
    expect(assign).toHaveBeenCalledExactlyOnceWith(`${SERVER}/auth/providers/x/start?return_to=${encodeURIComponent('https://app.example.com/page')}&locale=${encodeURIComponent(navigator.language)}`);
  });
});
