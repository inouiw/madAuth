import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import './index.js';
import { MadauthLogin } from './madauth-login.js';
import { loginMethods } from './methods.js';

let login: MadauthLogin;
let onCancel: Mock<() => void>;

function $<T extends Element>(selector: string): T {
  return login.shadowRoot!.querySelector<T>(selector)!;
}

function dialog(): HTMLDialogElement {
  return $('dialog');
}

beforeEach(async () => {
  login = document.createElement('madauth-login');
  onCancel = vi.fn();
  login.addEventListener('madauth-cancel', onCancel);
  document.body.append(login);
  await login.updateComplete;
});

afterEach(() => {
  login.remove();
});

describe('<madauth-login>', () => {
  it('is registered as a custom element', () => {
    expect(customElements.get('madauth-login')).toBe(MadauthLogin);
    expect(login).toBeInstanceOf(MadauthLogin);
  });

  it('is closed initially', () => {
    expect(dialog().open).toBe(false);
  });

  it('opens as a modal dialog when open() is called', async () => {
    const showModal = vi.spyOn(dialog(), 'showModal');

    await login.open();

    expect(showModal).toHaveBeenCalledOnce();
    expect(dialog().open).toBe(true);
  });

  it('shows the default heading and allows overriding it', async () => {
    expect($('h2').textContent).toBe('Sign in');

    login.heading = 'Log in to projectmatch';
    await login.updateComplete;

    expect($('h2').textContent).toBe('Log in to projectmatch');
  });

  it('lists every login method in registry order', () => {
    const ids = [...login.shadowRoot!.querySelectorAll<HTMLButtonElement>('[data-method]')].map(
      (b) => b.dataset.method,
    );
    expect(ids).toEqual(loginMethods.map((m) => m.id));
  });

  it('shows coming-soon methods as disabled with a badge', () => {
    for (const m of loginMethods.filter((m) => m.status === 'coming-soon')) {
      const button = $<HTMLButtonElement>(`[data-method="${m.id}"]`);
      expect(button.disabled).toBe(true);
      expect(button.querySelector('.badge')!.textContent).toBe('Soon');
    }
  });

  it('labels each method button', () => {
    for (const m of loginMethods) {
      const label = m.id === 'password' ? 'Sign in' : m.label;
      expect($(`[data-method="${m.id}"] .label`).textContent).toBe(label);
    }
  });

  it('offers a username and password form whose fields are disabled while coming soon', () => {
    const comingSoon = loginMethods.find((m) => m.id === 'password')!.status === 'coming-soon';
    for (const id of ['username', 'password']) {
      const input = $<HTMLInputElement>(`form input#${id}`);
      expect($(`label[for="${id}"]`)).not.toBeNull();
      expect(input.disabled).toBe(comingSoon);
    }
  });

  it('closes and fires madauth-cancel when the close button is clicked', async () => {
    await login.open();

    $<HTMLButtonElement>('.close').click();

    expect(dialog().open).toBe(false);
    await vi.waitFor(() => expect(onCancel).toHaveBeenCalledOnce());
  });

  it('fires madauth-cancel when the browser closes the dialog (e.g. Escape)', async () => {
    await login.open();

    // Browsers close the dialog on Escape without a return value; simulate that.
    dialog().close();

    await vi.waitFor(() => expect(onCancel).toHaveBeenCalledOnce());
  });

  it('closes and fires madauth-cancel when the backdrop is clicked', async () => {
    await login.open();

    // Clicks on the backdrop are dispatched with the <dialog> itself as target.
    dialog().dispatchEvent(new MouseEvent('click', { bubbles: true }));

    expect(dialog().open).toBe(false);
    await vi.waitFor(() => expect(onCancel).toHaveBeenCalledOnce());
  });

  it('stays open when clicking inside the dialog', async () => {
    await login.open();

    $<HTMLElement>('h2').click();

    expect(dialog().open).toBe(true);
  });

  it('closes without firing madauth-cancel when close() is called', async () => {
    await login.open();

    login.close();
    await new Promise((r) => setTimeout(r, 10));

    expect(dialog().open).toBe(false);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('fires madauth-cancel again after being reopened and cancelled', async () => {
    await login.open();
    login.close();
    await login.open();

    $<HTMLButtonElement>('.close').click();

    await vi.waitFor(() => expect(onCancel).toHaveBeenCalledOnce());
  });
});
