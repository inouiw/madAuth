// Behaviour described in docs/totp-security.md; update the doc when changing it.
import { describe, expect, it } from 'vitest';
import { deriveCodeKey } from './password.js';
import { signingKey } from './test/helpers.js';
import {
  RECOVERY_CODES,
  base32Decode,
  base32Encode,
  decryptSecret,
  deriveTotpKey,
  encryptSecret,
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  hotp,
  normalizeRecoveryCode,
  otpauthUri,
  stepOf,
  totp,
  verifyTotp,
} from './totp.js';

/** The secret of the test vectors in RFC 4226 and RFC 6238. */
const rfcSecret = Buffer.from('12345678901234567890');

describe('codes', () => {
  it('U1: computes the HOTP test vectors of RFC 4226', () => {
    const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

    expect(expected.map((_, counter) => hotp(rfcSecret, counter))).toEqual(expected);
  });

  it('U2: computes the TOTP test vectors of RFC 6238 (SHA-1, 8 digits)', () => {
    const vectors: [number, string][] = [
      [59, '94287082'],
      [1111111109, '07081804'],
      [1111111111, '14050471'],
      [1234567890, '89005924'],
      [2000000000, '69279037'],
      [20000000000, '65353130'],
    ];

    for (const [seconds, code] of vectors) expect(totp(rfcSecret, stepOf(seconds * 1000), 8)).toBe(code);
    expect(stepOf(59_000)).toBe(1);
  });

  it('U3: base32 follows RFC 4648 without padding, and decodes what a person types', () => {
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'MY'],
      ['fo', 'MZXQ'],
      ['foo', 'MZXW6'],
      ['foob', 'MZXW6YQ'],
      ['fooba', 'MZXW6YTB'],
      ['foobar', 'MZXW6YTBOI'],
    ];
    for (const [text, encoded] of vectors) {
      expect(base32Encode(Buffer.from(text))).toBe(encoded);
      expect(base32Decode(encoded)?.toString()).toBe(text);
    }
    expect(base32Encode(rfcSecret)).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');

    expect(base32Decode('mzxw 6ytb oi==')?.toString()).toBe('foobar');
    for (const wrong of ['0', '1', '8', 'MZXW6YTBOI!']) expect(base32Decode(wrong)).toBe(null);
    for (let length = 0; length <= 40; length++) {
      const bytes = generateTotpSecret().subarray(0, length);
      expect(base32Decode(base32Encode(bytes))).toEqual(Buffer.from(bytes));
    }
    expect(generateTotpSecret()).toHaveLength(20);
  });

  it('U4: a code is accepted one step before and after its time, and only as six digits', () => {
    const now = 1_700_000_015_000;
    const step = stepOf(now);
    const codeAt = (offset: number) => totp(rfcSecret, step + offset);

    expect(verifyTotp(rfcSecret, codeAt(0), now)).toBe(step);
    expect(verifyTotp(rfcSecret, codeAt(-1), now)).toBe(step - 1);
    expect(verifyTotp(rfcSecret, codeAt(1), now)).toBe(step + 1);
    expect(verifyTotp(rfcSecret, codeAt(-2), now)).toBe(null);
    expect(verifyTotp(rfcSecret, codeAt(2), now)).toBe(null);
    expect(verifyTotp(rfcSecret, codeAt(1), now, 0)).toBe(null);

    const code = codeAt(0);
    expect(verifyTotp(rfcSecret, `${code.slice(0, 3)} ${code.slice(3)}`, now)).toBe(step);
    expect(verifyTotp(rfcSecret, code.slice(0, 5), now)).toBe(null);
    expect(verifyTotp(rfcSecret, `${code}1`, now)).toBe(null);
    expect(verifyTotp(rfcSecret, 'abcdef', now)).toBe(null);
    expect(verifyTotp(generateTotpSecret(), code, now)).toBe(null);
  });

  it('U5: the otpauth URI names the issuer and the account and carries the key', () => {
    expect(otpauthUri({ issuer: 'My App', account: 'grace@example.com', secret: rfcSecret })).toBe(
      'otpauth://totp/My%20App:grace%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=My%20App&algorithm=SHA1&digits=6&period=30',
    );
  });
});

describe('secrets at rest', () => {
  const key = deriveTotpKey(signingKey.d!);

  it('U6: a secret is encrypted with a random IV and comes back only with the same key, untouched', () => {
    const secret = generateTotpSecret();
    const stored = encryptSecret(key, secret);

    expect(stored).toMatch(/^v1\.[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(stored).not.toContain(base32Encode(secret));
    expect(encryptSecret(key, secret)).not.toBe(stored);
    expect(decryptSecret(key, stored)).toEqual(secret);

    expect(decryptSecret(deriveTotpKey(generateTotpSecret().toString('base64url')), stored)).toBe(null);
    const [version, iv, encrypted, tag] = stored.split('.');
    const flipped = Buffer.from(tag, 'base64url');
    flipped[0] ^= 1;
    expect(decryptSecret(key, [version, iv, encrypted, flipped.toString('base64url')].join('.'))).toBe(null);
    expect(decryptSecret(key, [version, iv, encrypted, tag, 'x'].join('.'))).toBe(null);
    for (const malformed of ['', 'v2.a.b.c', 'v1.a.b', `v1.${iv}.${encrypted}.c`]) expect(decryptSecret(key, malformed)).toBe(null);
  });

  it('U6: the key is derived from the signing key and differs from the key for e-mail codes', () => {
    expect(key).toHaveLength(32);
    expect(deriveTotpKey(signingKey.d!)).toEqual(key);
    expect(key.equals(deriveCodeKey(signingKey.d!))).toBe(false);
  });
});

describe('recovery codes', () => {
  it('U7: ten distinct codes of two groups, read back in any form, hashed with the code key', () => {
    const codes = generateRecoveryCodes();

    expect(codes).toHaveLength(RECOVERY_CODES);
    expect(new Set(codes).size).toBe(RECOVERY_CODES);
    for (const code of codes) expect(code).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);

    const [code] = codes;
    const normalized = code.replace('-', '');
    expect(normalizeRecoveryCode(code)).toBe(normalized);
    expect(normalizeRecoveryCode(` ${code.toUpperCase()} `)).toBe(normalized);
    expect(normalizeRecoveryCode(normalized)).toBe(normalized);
    expect(normalizeRecoveryCode(`${code}x`)).toBe(null);
    expect(normalizeRecoveryCode('abcde-fghi0')).toBe(null);
    expect(normalizeRecoveryCode(123)).toBe(null);

    const codeKey = deriveCodeKey(signingKey.d!);
    expect(hashRecoveryCode(codeKey, normalized)).toBe(hashRecoveryCode(codeKey, normalized));
    expect(hashRecoveryCode(codeKey, normalized)).not.toBe(hashRecoveryCode(codeKey, codes[1].replace('-', '')));
  });
});
