import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { GoogleFedcm } from '../providers/google-fedcm.js';
import { GoogleRedirect } from '../providers/google-redirect.js';
import { Password } from '../providers/password.js';
import { SERVER, ada, fakeGis, fakeServer, resetAll, settle } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

function container(): HTMLElement {
  const el = document.createElement('div');
  document.body.append(el);
  return el;
}

describe('Madauth.google.renderButton', () => {
  it('H10: renders the FedCM button for a custom screen and reports the sign-in', async () => {
    fakeServer();
    const gis = fakeGis();
    void Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });
    const onResult = vi.fn();
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    const el = container();

    // Works before initialize has finished.
    const rendered = Madauth.google.renderButton(el, { theme: 'dark', onResult });
    await settle();

    expect(rendered.isSuccess).toBe(true);
    expect(gis.id.renderButton).toHaveBeenCalledOnce();
    // Inside a light wrapper, so Google's iframe gets no opaque background on a dark page.
    const target = gis.id.renderButton.mock.lastCall![0];
    expect(target.parentElement).toBe(el);
    expect(target.style.colorScheme).toBe('light');
    expect(gis.id.renderButton.mock.lastCall![1].theme).toBe('filled_black');

    gis.signIn();
    await settle();

    expect(onResult).toHaveBeenCalledExactlyOnceWith({ isSuccess: true, user: ada });
    expect(listener).toHaveBeenLastCalledWith(ada);

    el.append(document.createElement('iframe'));
    if (rendered.isSuccess) rendered.remove();
    expect(el.childElementCount).toBe(0);
  });

  it('H10: renders a button that starts the redirect with GoogleRedirect', async () => {
    fakeServer().codeFlow = true;
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });
    const el = container();

    Madauth.google.renderButton(el);
    await settle();
    el.querySelector('button')!.click();

    expect(el.querySelector('button')!.textContent).toBe('Continue with Google');
    expect(assign).toHaveBeenCalledExactlyOnceWith(
      `${SERVER}/auth/google/start?return_to=${encodeURIComponent('https://app.example.com/page')}`,
    );
  });

  it('labels the redirect button in the configured language until it is removed', async () => {
    fakeServer().codeFlow = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()], locale: 'de-CH', ui: 'custom' });
    const el = container();

    const rendered = Madauth.google.renderButton(el);
    await settle();
    const button = el.querySelector('button')!;
    expect(button.textContent).toBe('Weiter mit Google');

    Madauth.setLocale('en');
    expect(button.textContent).toBe('Continue with Google');

    if (rendered.isSuccess) rendered.remove();
    Madauth.setLocale('de');
    expect(button.textContent).toBe('Continue with Google');
  });

  it('H10: fails without a Google provider or before initialize', async () => {
    fakeServer();

    expect(Madauth.google.renderButton(container())).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    expect(Madauth.google.renderButton(container())).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
  });

  it('reports a failed initialize through onResult', async () => {
    fakeServer().down = true;
    fakeGis();
    void Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });
    const onResult = vi.fn();

    Madauth.google.renderButton(container(), { onResult });
    await settle();

    expect(onResult).toHaveBeenCalledWith(expect.objectContaining({ isSuccess: false, error: expect.objectContaining({ code: 'network' }) }));
  });

  it('renders nothing when removed before initialize has finished', async () => {
    fakeServer();
    const gis = fakeGis();
    void Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });

    const rendered = Madauth.google.renderButton(container());
    if (rendered.isSuccess) rendered.remove();
    await settle();

    expect(gis.id.renderButton).not.toHaveBeenCalled();
  });
});
