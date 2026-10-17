import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { GitHub } from '../providers/github.js';
import { Password } from '../providers/password.js';
import { SERVER, fakeServer, resetAll, settle } from '../test-helpers.js';

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

describe('Madauth.github.renderButton', () => {
  it('B9: renders a button that starts the redirect, for a custom screen', async () => {
    fakeServer().github = true;
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    void Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub()], ui: 'custom' });
    const el = container();

    // Works before initialize has finished.
    const rendered = Madauth.github.renderButton(el);
    await settle();
    el.querySelector('button')!.click();

    expect(rendered.isSuccess).toBe(true);
    expect(el.querySelector('button')!.textContent).toBe('Continue with GitHub');
    expect(assign).toHaveBeenCalledExactlyOnceWith(`${SERVER}/auth/providers/github/start?return_to=${encodeURIComponent('https://app.example.com/page')}&locale=${encodeURIComponent(navigator.language)}`);
    if (rendered.isSuccess) rendered.remove();
    expect(el.childElementCount).toBe(0);
  });

  it('B9: labels the button in the configured language until it is removed', async () => {
    fakeServer().github = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub()], locale: 'de-CH', ui: 'custom' });
    const el = container();

    const rendered = Madauth.github.renderButton(el);
    await settle();
    const button = el.querySelector('button')!;
    expect(button.textContent).toBe('Weiter mit GitHub');

    Madauth.setLocale('en');
    expect(button.textContent).toBe('Continue with GitHub');

    if (rendered.isSuccess) rendered.remove();
    Madauth.setLocale('de');
    expect(button.textContent).toBe('Continue with GitHub');
  });

  it('B9: fails without a GitHub provider, when the server has no GitHub sign-in, or before initialize', async () => {
    fakeServer();

    expect(Madauth.github.renderButton(container())).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    expect(Madauth.github.renderButton(container())).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled', message: expect.stringContaining('new GitHub()') } });
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub(), new Password()] });
    expect(Madauth.github.renderButton(container())).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
  });

  it('reports a failed initialize through onResult', async () => {
    fakeServer().down = true;
    void Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub()] });
    const onResult = vi.fn();

    Madauth.github.renderButton(container(), { onResult });
    await settle();

    expect(onResult).toHaveBeenCalledWith(expect.objectContaining({ isSuccess: false, error: expect.objectContaining({ code: 'network' }) }));
  });
});
