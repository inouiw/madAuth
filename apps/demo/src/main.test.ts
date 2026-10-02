import { beforeAll, describe, expect, it } from 'vitest';
import html from '../index.html?raw';

beforeAll(async () => {
  // Render the demo page's markup (without loading its script and stylesheet), then run main.ts.
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('script, link').forEach((el) => el.remove());
  document.body.replaceChildren(template.content);
  await import('./main.js');
});

describe('demo page', () => {
  it('shows only a sign-in button', () => {
    const buttons = document.querySelectorAll('main button');
    expect(buttons).toHaveLength(1);
    expect(buttons[0].textContent).toBe('Sign in');
  });

  it('opens the login dialog when the sign-in button is clicked', async () => {
    const login = document.querySelector('madauth-login')!;
    await login.updateComplete;
    const dialog = login.shadowRoot!.querySelector('dialog')!;
    expect(dialog.open).toBe(false);

    document.querySelector<HTMLButtonElement>('#sign-in')!.click();

    await expect.poll(() => dialog.open).toBe(true);
  });
});
