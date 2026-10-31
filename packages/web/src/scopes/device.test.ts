import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Madauth } from '../madauth.js';
import { SERVER, fakeServer, grace, resetAll } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

const tv = { code: 'BCDFGHJK', client: { id: 'mc_tv', name: 'Living room TV' }, scope: ['openid', 'email', 'offline_access'], expiresAt: 1_700_000_600_000 };

describe('Madauth.device', () => {
  it('looks a code up in any form, then approves or denies it, each once', async () => {
    const server = fakeServer();
    server.user = grace;
    server.devices.push({ ...tv });
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(await Madauth.device.lookup('bcdf ghjk')).toEqual({ isSuccess: true, code: 'BCDF-GHJK', client: tv.client, scope: tv.scope, expiresAt: tv.expiresAt });
    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', path: '/auth/device/lookup', body: { code: 'bcdf ghjk' } });
    expect(await Madauth.device.approve('BCDF-GHJK')).toEqual({ isSuccess: true });
    expect(await Madauth.device.approve('BCDF-GHJK')).toMatchObject({ isSuccess: false, error: { code: 'device_code_invalid' } });

    server.devices.push({ ...tv, code: 'LMNPQRST' });
    expect(await Madauth.device.deny('LMNP-QRST')).toMatchObject({ isSuccess: false, error: { code: 'device_code_invalid' } });
    expect(await Madauth.device.lookup('LMNP-QRST')).toMatchObject({ isSuccess: true });
    expect(await Madauth.device.deny('LMNP-QRST')).toEqual({ isSuccess: true });
  });

  it('fails with no_session, device_code_invalid and too_many_attempts', async () => {
    const server = fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    expect(await Madauth.device.lookup('BCDF-GHJK')).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
    server.user = grace;
    expect(await Madauth.device.lookup('BCDF-GHJK')).toMatchObject({ isSuccess: false, error: { code: 'device_code_invalid' } });
    server.deviceLookupBlocked = true;
    expect(await Madauth.device.lookup('BCDF-GHJK')).toMatchObject({ isSuccess: false, error: { code: 'too_many_attempts' } });
  });
});
