// The web library's strength meter must rate passwords exactly as the server's check does.
import { describe, expect, it } from 'vitest';
import { loadPasswordRating } from '../../web/src/strength.js';
import { RATED_LENGTH, passwordScore } from './strength.js';

const samples: [string, string[]][] = [
  ['password1234', []],
  ['summer2024', []],
  ['Sommer2024!', []],
  ['new password!', []],
  ['qwertzuiop', []],
  ['correct horse battery', []],
  ['Grace Hopper 1', []],
  ['Grace Hopper 1', ['grace@example.com', 'Grace Hopper']],
  ['Kaffee-Tasse-Berg', []],
  // Past the rated length only the first 64 characters count, on both sides.
  ['a'.repeat(RATED_LENGTH) + 'Xq7!pL0#vZ', []],
];

describe('password strength', () => {
  it('the web library rates every sample as the server does', async () => {
    const rate = await loadPasswordRating();

    for (const [password, userInputs] of samples) {
      expect([password, rate(password, userInputs)]).toEqual([password, await passwordScore(password, userInputs)]);
    }
  });

  it('rates only the first 64 characters, so a long password takes no longer than a 64-character one', async () => {
    expect(await passwordScore('a'.repeat(RATED_LENGTH) + 'Xq7!pL0#vZ')).toBe(0);

    const started = performance.now();
    await passwordScore('1'.repeat(256));
    expect(performance.now() - started).toBeLessThan(400);
  });
});
