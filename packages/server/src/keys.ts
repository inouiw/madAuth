import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';

/** The algorithm of madAuth's own tokens (sessions, access tokens) and the default of the ID tokens. */
export const SIGNING_ALG = 'ES256';

/** The algorithm an OpenID Connect client that can't verify ES256 gets its ID tokens in, with a key of its own. */
export const RSA_SIGNING_ALG = 'RS256';

export type SigningAlg = typeof SIGNING_ALG | typeof RSA_SIGNING_ALG;

/** Every algorithm madAuth signs with: the key service's keys of both kinds verify. */
export const SIGNING_ALGS: readonly SigningAlg[] = [SIGNING_ALG, RSA_SIGNING_ALG];

/** The shortest RSA modulus madAuth accepts, in base64url characters: 2048 bits. */
const MIN_RSA_MODULUS_CHARS = 342;

/** Creates a new private JWK for MADAUTH_SIGNING_KEY: ES256 (P-256) by default, or RS256 (RSA 2048). */
export async function generateSigningKey(alg: SigningAlg = SIGNING_ALG): Promise<JWK> {
  const { privateKey } = await generateKeyPair(alg, { extractable: true, ...(alg === RSA_SIGNING_ALG ? { modulusLength: 2048 } : {}) });
  const jwk = await exportJWK(privateKey);
  return { ...jwk, alg, kid: await calculateJwkThumbprint(jwk) };
}

/** The algorithm a signing JWK is for, by its key type; null if it is neither an EC P-256 nor an RSA key. */
export function algOf(jwk: Pick<JWK, 'kty' | 'crv'>): SigningAlg | null {
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') return SIGNING_ALG;
  if (jwk.kty === 'RSA') return RSA_SIGNING_ALG;
  return null;
}

/** The public part of a signing JWK, as the JWKS publishes it: the key's parameters, its algorithm, `use` and `kid`. */
export function publicSigningJwk(jwk: JWK, kid: string): JWK {
  return jwk.kty === 'RSA'
    ? { kty: 'RSA', n: jwk.n, e: jwk.e, alg: RSA_SIGNING_ALG, use: 'sig', kid }
    : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, alg: SIGNING_ALG, use: 'sig', kid };
}

/** The members of a JWK its thumbprint is made of (RFC 7638). */
export const thumbprintMembers = (jwk: JWK): JWK =>
  jwk.kty === 'RSA' ? { kty: 'RSA', n: jwk.n, e: jwk.e } : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };

/** Why `jwk` is not a private ES256 (P-256) or RS256 (RSA, 2048 bits or more) key, or null if it is one. */
export function signingJwkProblem(jwk: unknown): string | null {
  const { kty, crv, d, x, y, n, e, p, q, dp, dq, qi } = (jwk && typeof jwk === 'object' ? jwk : {}) as JWK;
  if (kty === 'EC' && crv === 'P-256' && d && x && y) return null;
  if (kty === 'RSA' && n && e && d) {
    // WebCrypto imports a private RSA key only with its CRT members, as generate-key writes them.
    if (!(p && q && dp && dq && qi)) return 'is an RSA key without p, q, dp, dq and qi: generate it with generate-key --rs256';
    return n.length >= MIN_RSA_MODULUS_CHARS ? null : 'is an RSA key shorter than 2048 bits';
  }
  return 'must be a private EC P-256 JWK (kty "EC", crv "P-256", with d, x and y) or a private RSA JWK (kty "RSA", with n, e, d, p, q, dp, dq and qi)';
}

/** Throws if `jwk` is not a private signing key. */
export function assertPrivateSigningJwk(jwk: JWK): void {
  const problem = signingJwkProblem(jwk);
  if (problem) throw new Error(problem);
}
