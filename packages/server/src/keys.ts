import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';

/** The algorithm of madAuth's own tokens (sessions, access tokens) and the default of the ID tokens. */
export const SIGNING_ALG = 'ES256';

/** The algorithm an OpenID Connect client that can't verify ES256 gets its ID tokens in, with a key of its own. */
export const RSA_SIGNING_ALG = 'RS256';

export type SigningAlg = typeof SIGNING_ALG | typeof RSA_SIGNING_ALG;

/** Every algorithm madAuth signs with: the key service's keys of both kinds verify. */
export const SIGNING_ALGS: readonly SigningAlg[] = [SIGNING_ALG, RSA_SIGNING_ALG];

/**
 * The algorithm of the webhook calls' asymmetric signatures (`v1a` of Standard Webhooks): Ed25519, as RFC 9864 names
 * it in a JWK. Its keys sign nothing else, and are published at /.well-known/webhook-keys.json, not in the JWKS.
 */
export const WEBHOOK_ALG = 'Ed25519';

/** The shortest RSA modulus madAuth accepts, in base64url characters: 2048 bits. */
const MIN_RSA_MODULUS_CHARS = 342;

/** Creates a new private JWK for MADAUTH_SIGNING_KEY: ES256 (P-256) by default, or RS256 (RSA 2048). */
export async function generateSigningKey(alg: SigningAlg = SIGNING_ALG): Promise<JWK> {
  const { privateKey } = await generateKeyPair(alg, { extractable: true, ...(alg === RSA_SIGNING_ALG ? { modulusLength: 2048 } : {}) });
  const jwk = await exportJWK(privateKey);
  return { ...jwk, alg, kid: await calculateJwkThumbprint(jwk) };
}

/** Creates a new private Ed25519 JWK for MADAUTH_SIGNING_KEY's set: the key that signs the webhook calls (`v1a`). */
export async function generateWebhookKey(): Promise<JWK> {
  const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const jwk = await exportJWK(privateKey);
  return { ...jwk, alg: WEBHOOK_ALG, kid: await calculateJwkThumbprint(thumbprintMembers(jwk)) };
}

/** Whether a JWK is an Ed25519 key: one that signs the webhook calls. */
export const isWebhookJwk = (jwk: Pick<JWK, 'kty' | 'crv'>): boolean => jwk.kty === 'OKP' && jwk.crv === 'Ed25519';

/** The public part of a webhook key, as /.well-known/webhook-keys.json publishes it. */
export const publicWebhookJwk = (jwk: JWK, kid: string): JWK => ({ kty: 'OKP', crv: 'Ed25519', x: jwk.x, alg: WEBHOOK_ALG, use: 'sig', kid });

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
  jwk.kty === 'RSA' ? { kty: 'RSA', n: jwk.n, e: jwk.e } : jwk.kty === 'OKP' ? { kty: 'OKP', crv: jwk.crv, x: jwk.x } : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };

/**
 * Why `jwk` is not a private ES256 (P-256), RS256 (RSA, 2048 bits or more) or Ed25519 (webhook) key, or null if it
 * is one.
 */
export function signingJwkProblem(jwk: unknown): string | null {
  const { kty, crv, d, x, y, n, e, p, q, dp, dq, qi } = (jwk && typeof jwk === 'object' ? jwk : {}) as JWK;
  if (kty === 'EC' && crv === 'P-256' && d && x && y) return null;
  if (kty === 'OKP' && crv === 'Ed25519' && d && x) return null;
  if (kty === 'RSA' && n && e && d) {
    // WebCrypto imports a private RSA key only with its CRT members, as generate-key writes them.
    if (!(p && q && dp && dq && qi)) return 'is an RSA key without p, q, dp, dq and qi: generate it with generate-key --rs256';
    return n.length >= MIN_RSA_MODULUS_CHARS ? null : 'is an RSA key shorter than 2048 bits';
  }
  return 'must be a private EC P-256 JWK (kty "EC", crv "P-256", with d, x and y), a private RSA JWK (kty "RSA", with n, e, d, p, q, dp, dq and qi) or a private Ed25519 JWK (kty "OKP", crv "Ed25519", with d and x)';
}

/** Throws if `jwk` is not a private signing key. */
export function assertPrivateSigningJwk(jwk: JWK): void {
  const problem = signingJwkProblem(jwk);
  if (problem) throw new Error(problem);
}
