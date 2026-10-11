import { beforeAll, describe, expect, it, vi } from 'vitest';
import html from '../index.html?raw';

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// A madAuth server with a GitHub OAuth App, where GitHub asks for the authenticator app once a user has one.
vi.stubGlobal(
  'fetch',
  vi.fn(async (input: string, init: RequestInit = {}) => {
    switch (`${init.method ?? 'GET'} ${new URL(input).pathname}`) {
      case 'GET /auth/config':
        return json({
          google: { clientId: 'cid.apps.googleusercontent.com', codeFlow: false, secondFactor: 'none' },
          github: { secondFactor: 'optional' },
          password: { minLength: 8, secondFactor: 'none' },
          totp: { signIn: false, signUp: false },
          email: { verification: true },
        });
      case 'GET /auth/session':
        return json({ error: 'no_session' }, 401);
    }
    return json({}, 404);
  }),
);

beforeAll(async () => {
  // The server-side Google demo (no Google script to load here), back from GitHub with the first step done:
  // the server names the method next to the step.
  history.replaceState(null, '', '/?google=redirect#madauth_next=totp&madauth_factors=totp&madauth_method=github');
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('script, link').forEach((el) => el.remove());
  document.body.replaceChildren(template.content);
  await import('./main.js');
});

describe('demo page with GitHub sign-in', () => {
  it('offers GitHub: the note about a server without it stays hidden', async () => {
    await expect.poll(() => document.querySelector('madauth-login')).not.toBeNull();
    expect($('#github-note').hidden).toBe(true);
  });

  it('goes on with the authenticator app when the redirect came back from GitHub with that step', async () => {
    const login = await vi.waitFor(() => {
      const element = document.querySelector('madauth-login');
      if (!element) throw new Error('the dialog was not created');
      return element;
    });
    await expect.poll(() => login.shadowRoot!.querySelector('dialog')!.open).toBe(true);
    expect(login.shadowRoot!.querySelector('h2')!.textContent!.trim()).toBe('Enter your code');
    expect(location.hash).toBe('');
  });

  it('has a row for GitHub in the settings table, with its policy', () => {
    expect($<HTMLInputElement>('#method-github')).not.toBeNull();
    expect($<HTMLSelectElement>('#policy-github').value).toBe('none');
  });
});
