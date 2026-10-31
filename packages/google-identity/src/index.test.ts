import { afterEach, beforeEach, describe, expect, it, vi, type Mocked } from 'vitest';
import {
  cancel,
  disableAutoSelect,
  GIS_SRC,
  isFedcmSupported,
  loadGis,
  renderButton,
  resetGisForTests,
  revoke,
  signIn,
  type GoogleAccountsId,
  type PromptMomentNotification,
} from './index.js';

const CLIENT_ID = 'client.apps.googleusercontent.com';

/** Installs a fake `window.google.accounts.id`. */
function fakeGis(): { id: Mocked<GoogleAccountsId>; credential(token?: string, selectBy?: string): void; moment(n: Partial<PromptMomentNotification>): void } {
  const id: Mocked<GoogleAccountsId> = {
    initialize: vi.fn(),
    prompt: vi.fn(),
    renderButton: vi.fn(),
    disableAutoSelect: vi.fn(),
    cancel: vi.fn(),
    revoke: vi.fn(),
  };
  (window as { google?: unknown }).google = { accounts: { id } };
  return {
    id,
    /** Google hands a credential to the callback of the latest initialize(). */
    credential(token = 'google-id-token', selectBy = 'user') {
      id.initialize.mock.lastCall![0].callback!({ credential: token, select_by: selectBy });
    },
    /** One Tap reports a moment to the listener of the latest prompt(). */
    moment(n: Partial<PromptMomentNotification>) {
      const notification: PromptMomentNotification = {
        isDisplayMoment: () => false,
        isNotDisplayed: () => false,
        getNotDisplayedReason: () => '',
        isSkippedMoment: () => false,
        isDismissedMoment: () => false,
        getDismissedReason: () => '',
        ...n,
      };
      id.prompt.mock.lastCall![0]!(notification);
    },
  };
}

/** A browser with FedCM, whose dialog answers as `answer` says. */
function fakeFedcm(answer: (options: CredentialRequestOptions) => Promise<unknown>) {
  const get = vi.fn(answer);
  vi.stubGlobal('IdentityCredential', class {});
  Object.defineProperty(navigator, 'credentials', { value: { get, preventSilentAccess: vi.fn(async () => {}) }, configurable: true });
  return { get };
}

const scripts = () => document.querySelectorAll(`script[src="${GIS_SRC}"]`);

beforeEach(() => {
  resetGisForTests();
  delete (window as { google?: unknown }).google;
  delete (navigator as { credentials?: unknown }).credentials;
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('loadGis', () => {
  it('L1: resolves with google.accounts.id, once, and adds no script when the page has it already', async () => {
    const fake = fakeGis();

    const [a, b] = await Promise.all([loadGis(), loadGis()]);

    expect(a).toBe(fake.id);
    expect(b).toBe(fake.id);
    expect(scripts()).toHaveLength(0);
  });

  it('L2: rejects when the script loads without google.accounts.id, and a later call tries again', async () => {
    await expect(loadGis()).rejects.toThrow(/google.accounts.id is missing/);
    expect(scripts()).toHaveLength(0);

    const fake = fakeGis();
    await expect(loadGis()).resolves.toBe(fake.id);
  });

  it('L3: adds Google’s script to the head when the page has none', async () => {
    // happy-dom reports a script as loaded the moment it is appended, so the append itself is observed.
    const append = vi.spyOn(document.head, 'append');

    await loadGis().catch(() => {});

    const script = append.mock.calls[0][0] as HTMLScriptElement;
    expect(script.src).toBe(GIS_SRC);
    expect(script.async).toBe(true);
  });
});

describe('signIn with the browser’s FedCM API', () => {
  it('F1: asks the browser for Google’s token with the client ID and nonce, and reports an auto-selected account', async () => {
    const fedcm = fakeFedcm(async () => ({ token: 'tok', isAutoSelected: true }));

    expect(isFedcmSupported()).toBe(true);
    const result = await signIn({ clientId: CLIENT_ID, nonce: 'n1', autoSelect: true, context: 'use' });

    expect(result).toEqual({ isSuccess: true, idToken: 'tok', isAutoSelected: true });
    const request = fedcm.get.mock.calls[0][0] as unknown as { identity: { context: string; providers: { clientId: string; nonce: string; params: { nonce: string } }[] }; mediation: string };
    expect(request.mediation).toBe('optional');
    expect(request.identity.context).toBe('use');
    expect(request.identity.providers[0]).toMatchObject({ clientId: CLIENT_ID, nonce: 'n1', params: { nonce: 'n1', response_type: 'id_token' } });
    expect(scripts()).toHaveLength(0); // Google's script is not needed for the browser's dialog.
  });

  it('F2: without autoSelect the user must pick (mediation required), and a token without the flag is not auto-selected', async () => {
    const fedcm = fakeFedcm(async () => ({ token: 'tok' }));

    const result = await signIn({ clientId: CLIENT_ID, nonce: 'n1' });

    expect(result).toEqual({ isSuccess: true, idToken: 'tok', isAutoSelected: false });
    expect((fedcm.get.mock.calls[0][0] as { mediation?: string }).mediation).toBe('required');
  });

  it('F3: cancel() aborts the dialog, and the sign-in resolves with cancelled', async () => {
    fakeFedcm((options) => new Promise((_, reject) => options.signal!.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))));

    const pending = signIn({ clientId: CLIENT_ID, nonce: 'n1' });
    cancel();

    expect(await pending).toEqual({ isSuccess: false, reason: 'cancelled' });
  });

  it('F4: the caller’s signal cancels too, also before the call', async () => {
    const fedcm = fakeFedcm((options) => new Promise((_, reject) => options.signal!.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))));
    const controller = new AbortController();

    const pending = signIn({ clientId: CLIENT_ID, nonce: 'n1', signal: controller.signal });
    controller.abort();
    expect(await pending).toEqual({ isSuccess: false, reason: 'cancelled' });

    expect(await signIn({ clientId: CLIENT_ID, nonce: 'n1', signal: controller.signal })).toEqual({ isSuccess: false, reason: 'cancelled' });
    expect(fedcm.get).toHaveBeenCalledTimes(1);
  });

  it('F5: maps the browser’s errors: a closed dialog is cancelled, a dialog not shown is skipped, the rest an error', async () => {
    fakeFedcm(async () => {
      throw new DOMException('Error retrieving a token.', 'NetworkError');
    });
    expect(await signIn({ clientId: CLIENT_ID, nonce: 'n1' })).toEqual({ isSuccess: false, reason: 'cancelled' });

    fakeFedcm(async () => {
      throw new DOMException('The request is not allowed', 'NotAllowedError');
    });
    expect(await signIn({ clientId: CLIENT_ID, nonce: 'n1' })).toMatchObject({ isSuccess: false, reason: 'skipped', detail: /NotAllowedError/ });

    fakeFedcm(async () => {
      throw new DOMException('Error retrieving a token.', 'IdentityCredentialError');
    });
    expect(await signIn({ clientId: CLIENT_ID, nonce: 'n1' })).toMatchObject({ isSuccess: false, reason: 'error', detail: /IdentityCredentialError/ });

    fakeFedcm(async () => null);
    expect(await signIn({ clientId: CLIENT_ID, nonce: 'n1' })).toMatchObject({ isSuccess: false, reason: 'skipped' });
  });

  it('F6: fedcm: false goes through Google’s script instead', async () => {
    const fedcm = fakeFedcm(async () => ({ token: 'tok' }));
    const gis = fakeGis();

    const pending = signIn({ clientId: CLIENT_ID, nonce: 'n1', fedcm: false });
    await vi.waitFor(() => expect(gis.id.prompt).toHaveBeenCalled());
    gis.credential('tok2', 'auto');

    expect(await pending).toEqual({ isSuccess: true, idToken: 'tok2', isAutoSelected: true });
    expect(fedcm.get).not.toHaveBeenCalled();
  });
});

describe('signIn with One Tap through Google’s script', () => {
  it('P1: initializes Google’s script with the client ID, nonce and FedCM on, prompts, and resolves with the credential', async () => {
    expect(isFedcmSupported()).toBe(false);
    const gis = fakeGis();

    const pending = signIn({ clientId: CLIENT_ID, nonce: 'n1', autoSelect: true, cancelOnTapOutside: false });
    await vi.waitFor(() => expect(gis.id.prompt).toHaveBeenCalledOnce());
    expect(gis.id.initialize).toHaveBeenCalledWith(
      expect.objectContaining({ client_id: CLIENT_ID, nonce: 'n1', auto_select: true, cancel_on_tap_outside: false, context: 'signin', use_fedcm_for_prompt: true, use_fedcm_for_button: true, itp_support: true }),
    );
    gis.credential('tok', 'user');

    expect(await pending).toEqual({ isSuccess: true, idToken: 'tok', isAutoSelected: false });
  });

  it('P2: reports the moments: skipped, dismissed by cancel(), dismissed otherwise, and a configuration error', async () => {
    const gis = fakeGis();

    let pending = signIn({ clientId: CLIENT_ID, nonce: 'n1' });
    await vi.waitFor(() => expect(gis.id.prompt).toHaveBeenCalled());
    gis.moment({ isSkippedMoment: () => true });
    expect(await pending).toEqual({ isSuccess: false, reason: 'skipped' });

    pending = signIn({ clientId: CLIENT_ID, nonce: 'n2' });
    await vi.waitFor(() => expect(gis.id.prompt).toHaveBeenCalledTimes(2));
    cancel();
    expect(gis.id.cancel).toHaveBeenCalledOnce();
    gis.moment({ isDismissedMoment: () => true, getDismissedReason: () => 'cancel_called' });
    expect(await pending).toEqual({ isSuccess: false, reason: 'cancelled' });

    pending = signIn({ clientId: CLIENT_ID, nonce: 'n3' });
    await vi.waitFor(() => expect(gis.id.prompt).toHaveBeenCalledTimes(3));
    gis.moment({ isDismissedMoment: () => true, getDismissedReason: () => 'flow_restarted' });
    expect(await pending).toEqual({ isSuccess: false, reason: 'skipped', detail: 'flow_restarted' });

    pending = signIn({ clientId: CLIENT_ID, nonce: 'n4' });
    await vi.waitFor(() => expect(gis.id.prompt).toHaveBeenCalledTimes(4));
    gis.moment({ isDisplayMoment: () => true, isNotDisplayed: () => true, getNotDisplayedReason: () => 'unregistered_origin' });
    expect(await pending).toEqual({ isSuccess: false, reason: 'configuration_error', detail: 'unregistered_origin' });
  });

  it('P3: credential_returned is left to the callback, which resolves once', async () => {
    const gis = fakeGis();

    const pending = signIn({ clientId: CLIENT_ID, nonce: 'n1' });
    await vi.waitFor(() => expect(gis.id.prompt).toHaveBeenCalled());
    gis.moment({ isDismissedMoment: () => true, getDismissedReason: () => 'credential_returned' });
    gis.credential('tok');
    gis.moment({ isSkippedMoment: () => true });

    expect(await pending).toEqual({ isSuccess: true, idToken: 'tok', isAutoSelected: false });
  });

  it('P4: the signal cancels One Tap', async () => {
    const gis = fakeGis();
    const controller = new AbortController();

    const pending = signIn({ clientId: CLIENT_ID, nonce: 'n1', signal: controller.signal });
    await vi.waitFor(() => expect(gis.id.prompt).toHaveBeenCalled());
    controller.abort();

    expect(await pending).toEqual({ isSuccess: false, reason: 'cancelled' });
    expect(gis.id.cancel).toHaveBeenCalledOnce();
  });

  it('P5: resolves with load_failed when Google’s script cannot be loaded', async () => {
    expect(await signIn({ clientId: CLIENT_ID, nonce: 'n1' })).toMatchObject({ isSuccess: false, reason: 'load_failed', detail: /google.accounts.id is missing/ });
  });
});

describe('renderButton', () => {
  it('B1: renders Google’s button in a light wrapper, with the options, and hands each credential over', async () => {
    const gis = fakeGis();
    const container = document.createElement('div');
    const onCredential = vi.fn();

    const rendered = await renderButton(container, { clientId: CLIENT_ID, nonce: 'n1', context: 'use', onCredential, button: { theme: 'filled_black', width: 300 }, uxMode: 'popup' });

    expect(rendered.isSuccess).toBe(true);
    const wrapper = container.firstElementChild as HTMLElement;
    expect(wrapper.style.colorScheme).toBe('light');
    expect(gis.id.initialize).toHaveBeenCalledWith(expect.objectContaining({ client_id: CLIENT_ID, nonce: 'n1', context: 'use', use_fedcm_for_button: true, ux_mode: 'popup' }));
    expect(gis.id.initialize.mock.lastCall![0]).not.toHaveProperty('login_uri');
    expect(gis.id.renderButton).toHaveBeenCalledWith(wrapper, { type: 'standard', theme: 'filled_black', width: 300 });

    gis.credential('tok', 'auto');
    gis.credential('tok2', 'btn');
    expect(onCredential).toHaveBeenNthCalledWith(1, { idToken: 'tok', isAutoSelected: true });
    expect(onCredential).toHaveBeenNthCalledWith(2, { idToken: 'tok2', isAutoSelected: false });

    (rendered as { remove(): void }).remove();
    expect(container.childElementCount).toBe(0);
  });

  it('B2: resolves with load_failed when Google’s script cannot be loaded', async () => {
    const container = document.createElement('div');

    expect(await renderButton(container, { clientId: CLIENT_ID, nonce: 'n1', onCredential: vi.fn() })).toMatchObject({ isSuccess: false, reason: 'load_failed' });
    expect(container.childElementCount).toBe(0);
  });
});

describe('disableAutoSelect and revoke', () => {
  it('D1: disableAutoSelect tells Google’s script and the browser', async () => {
    const fedcm = fakeFedcm(async () => null);
    const gis = fakeGis();

    await disableAutoSelect();

    expect(gis.id.disableAutoSelect).toHaveBeenCalledOnce();
    expect((navigator.credentials as unknown as { preventSilentAccess: ReturnType<typeof vi.fn> }).preventSilentAccess).toHaveBeenCalledOnce();
    void fedcm;
  });

  it('D2: disableAutoSelect does nothing without the browser API, and does not fail without the script', async () => {
    await expect(disableAutoSelect()).resolves.toBeUndefined();
  });

  it('R1: revoke resolves with Google’s answer', async () => {
    const gis = fakeGis();
    gis.id.revoke.mockImplementation((_hint, callback) => callback?.({ successful: true }));
    expect(await revoke('sub-1')).toEqual({ isSuccess: true });
    expect(gis.id.revoke).toHaveBeenCalledWith('sub-1', expect.any(Function));

    gis.id.revoke.mockImplementation((_hint, callback) => callback?.({ successful: false, error: 'unknown user' }));
    expect(await revoke('sub-2')).toEqual({ isSuccess: false, error: 'unknown user' });
  });

  it('R2: revoke fails when Google’s script cannot be loaded', async () => {
    expect(await revoke('sub-1')).toMatchObject({ isSuccess: false, error: /google.accounts.id is missing/ });
  });
});
