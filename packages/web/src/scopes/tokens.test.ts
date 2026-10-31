import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Madauth } from '../madauth.js';
import { SERVER, fakeServer, resetAll } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

const app = { id: 'mc_1', name: 'Phone app', public: true, redirectUris: [], postLogoutRedirectUris: [], deviceFlow: false, tokenExchange: true, createdAt: 1, updatedAt: 1 };

describe('Madauth.tokens', () => {
  it('gets the nonce, exchanges the Google ID token for tokens without cookies, and refreshes them', async () => {
    const server = fakeServer();
    server.clients.push(app);
    await Madauth.initialize({ serverUrl: SERVER, providers: [], locale: 'de' });

    expect(await Madauth.tokens.nonce({ clientId: 'mc_1' })).toEqual({ isSuccess: true, nonce: 'nonce-token', googleClientId: 'google-client', expiresIn: 300 });
    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', path: '/auth/oidc/nonce', body: { client_id: 'mc_1' } });

    expect(await Madauth.tokens.exchange({ clientId: 'mc_1', credential: 'google-id-token' })).toEqual({
      isSuccess: true,
      accessToken: 'at',
      tokenType: 'Bearer',
      expiresIn: 900,
      idToken: 'idt',
      refreshToken: 'rt2',
      scope: 'openid email profile offline_access',
    });
    expect(server.requests.at(-1)!.body).toEqual({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: 'mc_1',
      subject_token: 'google-id-token',
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      scope: 'openid email profile offline_access',
      locale: 'de',
    });
    // Without openid and offline_access: an access token alone.
    const bare = await Madauth.tokens.exchange({ clientId: 'mc_1', credential: 'google-id-token', scope: 'email' });
    expect(bare).toEqual({ isSuccess: true, accessToken: 'at', tokenType: 'Bearer', expiresIn: 900, scope: 'email' });

    expect(await Madauth.tokens.refresh({ clientId: 'mc_1', refreshToken: 'rt1' })).toMatchObject({ isSuccess: true, refreshToken: 'rt2' });
    expect(await Madauth.tokens.refresh({ clientId: 'mc_1', refreshToken: 'rt2' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_grant', message: 'ended' } });
  });

  it('reports the OAuth errors with the server’s description, and a second step with its factors', async () => {
    const server = fakeServer();
    server.clients.push({ ...app, tokenExchange: false });
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    expect(await Madauth.tokens.nonce({ clientId: 'mc_1' })).toMatchObject({ isSuccess: false, error: { code: 'unauthorized_client' } });
    expect(await Madauth.tokens.nonce({ clientId: 'mc_x' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_client' } });
    server.clients[0].tokenExchange = true;
    expect(await Madauth.tokens.exchange({ clientId: 'mc_1', credential: 'wrong' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_grant', message: 'subject_token: nonce mismatch.' } });
    expect(await Madauth.tokens.exchange({ clientId: 'mc_1', credential: 'needs-second-factor' })).toMatchObject({
      isSuccess: false,
      error: { code: 'interaction_required', message: 'a browser step', factors: ['authenticator'] },
    });
  });

  it('waits for initialize', async () => {
    expect(await Madauth.tokens.nonce({ clientId: 'mc_1' })).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
  });
});
