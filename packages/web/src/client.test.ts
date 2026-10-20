import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as client from './client.js';
import { SERVER, fakeServer, resetAll } from './test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

describe('@madauth/web/client', () => {
  it('exports the public API without the dialog, and registers no element', () => {
    expect(Object.keys(client).sort()).toEqual(
      ['EmailLink', 'GitHub', 'GoogleFedcm', 'GoogleRedirect', 'Madauth', 'Passkey', 'Password', 'Authenticator', 'loginMethods'].sort(),
    );
    expect(customElements.get('madauth-login')).toBeUndefined();
  });

  it('fails the dialog calls, naming the import to use, and adds nothing to the page', async () => {
    fakeServer();
    const { Madauth } = client;
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(await Madauth.showSignInDialog()).toMatchObject({
      isSuccess: false,
      error: { code: 'invalid_options', message: "Madauth.showSignInDialog() opens madAuth's dialog, which '@madauth/web/client' leaves out: import from '@madauth/web' instead." },
    });
    expect(await Madauth.showSetUpAuthenticatorDialog()).toMatchObject({
      isSuccess: false,
      error: { code: 'invalid_options', message: expect.stringContaining('Or use Madauth.authenticator.startSetup() and confirmSetup().') },
    });
    for (const call of [Madauth.showSetUpSmsDialog, Madauth.showSetUpPasskeyDialog, Madauth.showManageSignInMethodsDialog, Madauth.showManageApiKeysDialog, Madauth.showAdminDialog]) {
      expect(await call()).toMatchObject({ isSuccess: false, error: { code: 'invalid_options', message: expect.stringContaining("'@madauth/web/client'") } });
    }
    expect(document.querySelector('madauth-login')).toBeNull();
  });

  it('reports the initialize error first', async () => {
    fakeServer().down = true;
    await client.Madauth.initialize({ serverUrl: SERVER, providers: [] });
    expect(await client.Madauth.showSignInDialog()).toMatchObject({ isSuccess: false, error: { code: 'network' } });
  });
});
