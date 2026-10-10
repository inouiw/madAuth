import { beforeAll, describe, expect, it, vi } from 'vitest';
import html from '../index.html?raw';

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// A madAuth server without GOOGLE_CLIENT_SECRET: the redirect flow is off, e-mail & password is on.
vi.stubGlobal(
  'fetch',
  vi.fn(async (input: string, init: RequestInit = {}) => {
    switch (`${init.method ?? 'GET'} ${new URL(input).pathname}`) {
      case 'GET /auth/config':
        return json({ google: { clientId: 'cid.apps.googleusercontent.com', codeFlow: false }, password: { minLength: 8 } });
      case 'GET /auth/session':
        return json({ error: 'no_session' }, 401);
    }
    return json({}, 404);
  }),
);

beforeAll(async () => {
  // Opened with ?google=redirect: the server-side demo.
  history.replaceState(null, '', '/?google=redirect');
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('script, link').forEach((el) => el.remove());
  document.body.replaceChildren(template.content);
  await import('./main.js');
});

describe('demo page with the server-side redirect flow', () => {
  it('marks the redirect demo as the current one', () => {
    expect($<HTMLAnchorElement>('#flow a[aria-current="page"]').dataset.flow).toBe('redirect');
    expect($('.flow-description[data-flow="redirect"]').hidden).toBe(false);
    expect($('.flow-description[data-flow="fedcm"]').hidden).toBe(true);
  });

  it('says so when the server has no client secret for the redirect flow', async () => {
    await expect.poll(() => $('#flow-note').hidden).toBe(false);
  });

  it('does not load Google Identity Services: the redirect needs no script from Google', () => {
    expect(document.querySelector('script[src*="accounts.google.com"]')).toBeNull();
  });
});
