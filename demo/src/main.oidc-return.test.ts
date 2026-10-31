import { beforeAll, expect, it, vi } from 'vitest';
import html from '../index.html?raw';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// The demo as the login page of madAuth as an OpenID Connect provider: an application's authorization request
// sent the visitor here, and they are signed in already (e.g. in another tab).
const AUTHORIZE = `${location.origin}/auth/oidc/authorize?client_id=mc_1&response_type=code`;
// Where the page navigates to. (A plain list: Vitest clears mock calls between beforeAll and the test.)
const navigations: string[] = [];
vi.stubGlobal(
  'fetch',
  vi.fn(async (input: string, init: RequestInit = {}) => {
    switch (`${init.method ?? 'GET'} ${new URL(input).pathname}`) {
      case 'GET /auth/config':
        return json({ google: null, password: { minLength: 8, secondFactor: 'none' }, authenticator: { signIn: false, signUp: false }, email: { verification: true } });
      case 'GET /auth/session':
        return json({ user: { id: 'usr_1', email: 'ada@example.com', amr: ['pwd'] } });
    }
    return json({}, 404);
  }),
);

beforeAll(async () => {
  history.replaceState(null, '', `/?madauth_return=${encodeURIComponent(AUTHORIZE)}`);
  // The server's cookie that says a session exists.
  document.cookie = `madauth_session_expires=${Math.floor(Date.now() / 1000) + 600}; path=/`;
  // jsdom can't navigate: the page's `location` is the real one, but for `assign`.
  const { href, origin, hostname, pathname, search, hash } = window.location;
  const assign = (url: string) => navigations.push(url);
  vi.spyOn(window, 'location', 'get').mockReturnValue({ href, origin, hostname, pathname, search, hash, assign } as unknown as Location);
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('script, link').forEach((el) => el.remove());
  document.body.replaceChildren(template.content);
  await import('./main.js');
});

it('goes back to the authorization request once the visitor is signed in', async () => {
  await expect.poll(() => navigations).toEqual([AUTHORIZE]);
});
