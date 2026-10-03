import { beforeAll, describe, expect, it, vi } from 'vitest';
import html from '../index.html?raw';

const ada = { id: 'google:1', name: 'Ada Lovelace', email: 'ada@example.com', picture: 'https://example.com/ada.png' };
let sessionUser: typeof ada | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// A minimal madAuth server and Google Identity Services.
vi.stubGlobal(
  'fetch',
  vi.fn(async (input: string, init: RequestInit = {}) => {
    switch (`${init.method ?? 'GET'} ${new URL(input).pathname}`) {
      case 'GET /auth/config':
        return json({ google: { clientId: 'cid.apps.googleusercontent.com', codeFlow: false }, password: { minLength: 8 } });
      case 'GET /auth/session':
        return sessionUser ? json({ user: sessionUser }) : json({ error: 'no_session' }, 401);
      case 'POST /auth/google/nonce':
        return json({ nonce: 'n' });
      case 'POST /auth/google/verify':
        sessionUser = ada;
        return json({ user: ada });
      case 'POST /auth/logout':
        sessionUser = null;
        return new Response(null, { status: 204 });
    }
    return json({}, 404);
  }),
);
// Records what the page does with Google Identity Services. (Plain counters: Vitest clears mock calls between tests.)
const gis = { prompts: 0, buttons: 0, callback: undefined as ((response: { credential: string }) => void) | undefined };
window.google = {
  accounts: {
    id: {
      initialize: (config) => (gis.callback = config.callback),
      prompt: () => gis.prompts++,
      renderButton: () => gis.buttons++,
      disableAutoSelect: () => {},
      cancel: () => {},
    },
  },
};

beforeAll(async () => {
  // Render the demo page's markup (without loading its script and stylesheet), then run main.ts.
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('script, link').forEach((el) => el.remove());
  document.body.replaceChildren(template.content);
  await import('./main.js');
});

describe('demo page', () => {
  it('shows only a sign-in button while signed out', () => {
    const buttons = [...document.querySelectorAll<HTMLButtonElement>('main button')].filter((b) => !b.closest('[hidden]'));
    expect(buttons).toHaveLength(1);
    expect(buttons[0].textContent).toBe('Sign in');
  });

  it('prompts Google One Tap on load', async () => {
    await expect.poll(() => gis.prompts).toBe(1);
  });

  it('opens the login dialog with the Google button when the sign-in button is clicked', async () => {
    document.querySelector<HTMLButtonElement>('#sign-in')!.click();

    const login = await vi.waitFor(() => {
      const element = document.querySelector('madauth-login');
      if (!element) throw new Error('the dialog was not created');
      return element;
    });
    await expect.poll(() => login.shadowRoot!.querySelector('dialog')!.open).toBe(true);
    await expect.poll(() => gis.buttons).toBe(1);
  });

  it('shows the user after signing in with Google, and the sign-in button after signing out', async () => {
    gis.callback!({ credential: 'token' });

    await expect.poll(() => document.querySelector<HTMLElement>('#account')!.hidden).toBe(false);
    expect(document.querySelector<HTMLElement>('#sign-in')!.hidden).toBe(true);
    expect(document.querySelector('#user-name')!.textContent).toBe('Ada Lovelace');
    expect(document.querySelector('#user-email')!.textContent).toBe('ada@example.com');
    expect(document.querySelector<HTMLImageElement>('#avatar')!.src).toBe(ada.picture);

    document.querySelector<HTMLButtonElement>('#sign-out')!.click();

    await expect.poll(() => document.querySelector<HTMLElement>('#sign-in')!.hidden).toBe(false);
    expect(document.querySelector<HTMLElement>('#account')!.hidden).toBe(true);
  });

  it('switches between light and dark theme when the theme button is clicked', () => {
    const root = document.documentElement;
    const toggle = document.querySelector<HTMLButtonElement>('#theme-toggle')!;
    const initial = root.dataset.theme!;
    const other = initial === 'dark' ? 'light' : 'dark';
    expect(['light', 'dark']).toContain(initial);
    expect(toggle.getAttribute('aria-label')).toBe(`Switch to ${other} theme`);

    toggle.click();

    expect(root.dataset.theme).toBe(other);
    expect(toggle.getAttribute('aria-label')).toBe(`Switch to ${initial} theme`);

    toggle.click();

    expect(root.dataset.theme).toBe(initial);
  });
});
