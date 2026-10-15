import { describe, expect, it } from 'vitest';
import html from '../custom.html?raw';

// The example mirrors the table under "Password managers" in docs/custom-ui.md: each form's inputs by name.
const expected: Record<string, Record<string, string>> = {
  'signin-form': { email: 'email', password: 'current-password' },
  'signup-form': { name: 'name', email: 'email', password: 'new-password' },
  'forgot-form': { email: 'email' },
  'code-form': { code: 'one-time-code' },
  'reset-form': { password: 'new-password' },
  'authenticator-form': { email: 'email', code: 'off' },
  'authenticator-signup-form': { name: 'name', email: 'email' },
  'passkey-signup-form': { name: 'name', email: 'email' },
  'authenticator-code-form': { code: 'off' },
  'authenticator-setup-form': { code: 'off' },
};

describe('custom.html', () => {
  it('uses the autocomplete values documented in custom-ui.md', () => {
    // A template is inert: no stylesheet or script of the page is fetched.
    const template = document.createElement('template');
    template.innerHTML = html;
    for (const [form, fields] of Object.entries(expected)) {
      const inputs = [...template.content.querySelectorAll<HTMLInputElement>(`#${form} input`)];
      expect(inputs.length, form).toBeGreaterThan(0);
      expect(Object.fromEntries(inputs.map((input) => [input.name, input.getAttribute('autocomplete')])), form).toEqual(fields);
    }
  });
});
