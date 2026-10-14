import { beforeAll, expect, it, vi } from 'vitest';
import html from '../index.html?raw';

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// A madAuth server with Google switched off by an admin: a valid setting, so the redirect demo has no note.
// (A plain counter: Vitest clears mock calls between beforeAll and the test.)
let configCalls = 0;
vi.stubGlobal(
  'fetch',
  vi.fn(async (input: string, init: RequestInit = {}) => {
    switch (`${init.method ?? 'GET'} ${new URL(input).pathname}`) {
      case 'GET /auth/config':
        configCalls++;
        return json({ google: null, password: { minLength: 8, secondFactor: 'none' }, authenticator: { signIn: false, signUp: false }, email: { verification: true } });
      case 'GET /auth/session':
        return json({ error: 'no_session' }, 401);
    }
    return json({}, 404);
  }),
);

beforeAll(async () => {
  history.replaceState(null, '', '/?google=redirect');
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('script, link').forEach((el) => el.remove());
  document.body.replaceChildren(template.content);
  await import('./main.js');
});

it('shows a visitor no note when Google is switched off, in the redirect demo', async () => {
  // initialize asked for the config once, and the page once more to tell "off" from "no client secret".
  await expect.poll(() => configCalls).toBe(2);
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect($('#flow-note').hidden).toBe(true);
  expect($('#github-note').hidden).toBe(true);
});
