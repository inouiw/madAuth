// Behaviour described in docs/password-security.md; update the doc when changing it.
import { describe, expect, it } from 'vitest';
import {
  HASH_PARAMS,
  checkPasswordPolicy,
  deriveCodeKey,
  generateCode,
  hashCode,
  hashPassword,
  isValidEmail,
  normalizeEmail,
  verifyPassword,
} from './password.js';
import { signingKey } from './test/helpers.js';

describe('password hashing', () => {
  it('P1: hashes are salted and verify only the right password', async () => {
    const a = await hashPassword('correct horse');
    const b = await hashPassword('correct horse');

    expect(a).not.toBe(b);
    expect(a).toMatch(new RegExp(`^scrypt\\$${HASH_PARAMS.logN}\\$${HASH_PARAMS.r}\\$${HASH_PARAMS.p}\\$`));
    expect(await verifyPassword('correct horse', a)).toEqual({ ok: true, needsRehash: false });
    expect(await verifyPassword('correct horse', b)).toEqual({ ok: true, needsRehash: false });
    expect(await verifyPassword('Correct horse', a)).toEqual({ ok: false, needsRehash: false });
  });

  it('P2: reports hashes with older parameters for rehashing', async () => {
    const old = await hashPassword('correct horse', { logN: 14, r: 8, p: 1 });

    expect(await verifyPassword('correct horse', old)).toEqual({ ok: true, needsRehash: true });
  });

  it('treats a malformed stored hash as a wrong password', async () => {
    expect(await verifyPassword('x', 'bcrypt$2b$10$abc')).toEqual({ ok: false, needsRehash: false });
    expect(await verifyPassword('x', 'scrypt$x$8$1$salt$hash')).toEqual({ ok: false, needsRehash: false });
  });

  it('treats differently composed Unicode characters as the same password', async () => {
    const hash = await hashPassword('Café au lait');

    expect((await verifyPassword('Café au lait', hash)).ok).toBe(true);
  });
});

describe('password policy', () => {
  const length = (minLength: number) => ({ minLength, minScore: 0 as const });

  it('P3: checks the length, between the minimum and 256 characters', async () => {
    expect(await checkPasswordPolicy('1234567', length(8))).toEqual({ message: 'The password must have at least 8 characters.', minLength: 8 });
    expect(await checkPasswordPolicy('12345678', length(8))).toBeNull();
    expect(await checkPasswordPolicy('x'.repeat(256), length(8))).toBeNull();
    expect(await checkPasswordPolicy('x'.repeat(257), length(8))).toEqual({ message: 'The password must have at most 256 characters.' });
    expect(await checkPasswordPolicy('  spaced  ', length(8))).toBeNull();
    // Counted in characters, not UTF-16 units: four emoji are four characters.
    expect(await checkPasswordPolicy('🔑🔑🔑🔑', length(5))).toMatchObject({ minLength: 5 });
    expect(await checkPasswordPolicy(undefined, length(8))).toEqual({ message: 'password is missing' });
  });

  it('refuses a password that is too easy to guess, after the length', async () => {
    const rules = { minLength: 8, minScore: 2 as const };
    const weak = { message: expect.stringMatching(/too easy to guess/), minScore: 2 };

    for (const common of ['password', '12345678', 'Password1!', 'qwertzuiop', 'summer2024']) {
      expect(await checkPasswordPolicy(common, rules)).toEqual(weak);
    }
    expect(await checkPasswordPolicy('correct horse battery', rules)).toBeNull();
    expect(await checkPasswordPolicy('Kaffee-Tasse-Berg', rules)).toBeNull();
    expect(await checkPasswordPolicy('short', rules)).toMatchObject({ minLength: 8 });
    // 0 checks the length only.
    expect(await checkPasswordPolicy('password', { minLength: 8, minScore: 0 })).toBeNull();
  });

  it('counts the user’s address and name as easy to guess', async () => {
    const rules = { minLength: 8, minScore: 2 as const };

    expect(await checkPasswordPolicy('Grace Hopper 1', rules)).toBeNull();
    expect(await checkPasswordPolicy('Grace Hopper 1', rules, ['grace@example.com', 'Grace Hopper'])).toMatchObject({ minScore: 2 });
  });
});

describe('e-mail addresses and codes', () => {
  it('normalizes and validates e-mail addresses', () => {
    expect(normalizeEmail('  Ada@Example.COM ')).toBe('ada@example.com');
    expect(isValidEmail('ada@example.com')).toBe(true);
    expect(isValidEmail('ada@example')).toBe(false);
    expect(isValidEmail('ada example@example.com')).toBe(false);
    expect(isValidEmail(`${'a'.repeat(250)}@x.de`)).toBe(false);
    expect(isValidEmail(42)).toBe(false);
  });

  it('generates 6-digit codes and stores them keyed by the signing key', () => {
    const codes = Array.from({ length: 50 }, generateCode);
    expect(codes.every((c) => /^\d{6}$/.test(c))).toBe(true);

    const key = deriveCodeKey(signingKey.d!);
    expect(hashCode(key, '123456')).toBe(hashCode(deriveCodeKey(signingKey.d!), '123456'));
    expect(hashCode(key, '123456')).not.toBe(hashCode(deriveCodeKey('b3RoZXIta2V5'), '123456'));
  });
});
