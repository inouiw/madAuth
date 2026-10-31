import { beforeAll, expect, it, vi } from 'vitest';
import html from '../index.html?raw';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// The demo as the page a device's user approves its sign-in on: the QR code's URL carries the code, and the visitor
// is signed in already.
const requests: string[] = [];
vi.stubGlobal(
  'fetch',
  vi.fn(async (input: string, init: RequestInit = {}) => {
    const key = `${init.method ?? 'GET'} ${new URL(input).pathname}`;
    requests.push(key);
    switch (key) {
      case 'GET /auth/config':
        return json({ google: null, password: { minLength: 8, secondFactor: 'none' }, authenticator: { signIn: false, signUp: false }, email: { verification: true } });
      case 'GET /auth/session':
        return json({ user: { id: 'usr_1', email: 'ada@example.com', amr: ['pwd'] } });
      case 'POST /auth/device/lookup':
        return json({ code: 'BCDF-GHJK', client: { id: 'mc_tv', name: 'Living room TV' }, scope: ['openid'], expiresAt: Date.now() + 600_000 });
    }
    return json({}, 404);
  }),
);

beforeAll(async () => {
  history.replaceState(null, '', '/?madauth_device=BCDF-GHJK');
  document.cookie = `madauth_session_expires=${Math.floor(Date.now() / 1000) + 600}; path=/`;
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('script, link').forEach((el) => el.remove());
  document.body.replaceChildren(template.content);
  await import('./main.js');
});

it('opens the approval of the device whose code is in the URL', async () => {
  await expect.poll(() => requests.includes('POST /auth/device/lookup')).toBe(true);
  const dialog = document.querySelector('madauth-login')!.shadowRoot!;
  await expect.poll(() => dialog.querySelector('.lead')?.textContent?.trim()).toBe('Living room TV asks to sign in as you.');
});
