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
  it('P3: checks only the length, between the minimum and 256 characters', () => {
    expect(checkPasswordPolicy('1234567', 8)).toMatch(/at least 8/);
    expect(checkPasswordPolicy('12345678', 8)).toBeNull();
    expect(checkPasswordPolicy('x'.repeat(256), 8)).toBeNull();
    expect(checkPasswordPolicy('x'.repeat(257), 8)).toMatch(/at most 256/);
    expect(checkPasswordPolicy('  spaced  ', 8)).toBeNull();
    // Counted in characters, not UTF-16 units: four emoji are four characters.
    expect(checkPasswordPolicy('🔑🔑🔑🔑', 5)).toMatch(/at least 5/);
    expect(checkPasswordPolicy(undefined, 8)).toBe('password is missing');
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
