import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';

export const SIGNING_ALG = 'ES256';

/** Creates a new private ES256 JWK for MADAUTH_SIGNING_KEY. */
export async function generateSigningKey(): Promise<JWK> {
  const { privateKey } = await generateKeyPair(SIGNING_ALG, { extractable: true });
  const jwk = await exportJWK(privateKey);
  return { ...jwk, alg: SIGNING_ALG, kid: await calculateJwkThumbprint(jwk) };
}

/** Why `jwk` is not a private ES256 (P-256) key, or null if it is one. */
export function signingJwkProblem(jwk: unknown): string | null {
  const { kty, crv, d, x, y } = (jwk && typeof jwk === 'object' ? jwk : {}) as JWK;
  return kty === 'EC' && crv === 'P-256' && d && x && y ? null : 'must be a private EC P-256 JWK (kty "EC", crv "P-256", with d, x and y)';
}

/** Throws if `jwk` is not a private ES256 (P-256) key. */
export function assertPrivateSigningJwk(jwk: JWK): void {
  const problem = signingJwkProblem(jwk);
  if (problem) throw new Error(problem);
}
