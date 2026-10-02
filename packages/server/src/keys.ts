import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';

export const SIGNING_ALG = 'ES256';

/** The madAuth signing key, ready to sign tokens and to publish its public half. */
export interface SigningKeys {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** Public JWK published at /.well-known/jwks.json. */
  publicJwk: JWK;
  kid: string;
}

/** Creates a new private ES256 JWK for MADAUTH_SIGNING_KEY. */
export async function generateSigningKey(): Promise<JWK> {
  const { privateKey } = await generateKeyPair(SIGNING_ALG, { extractable: true });
  const jwk = await exportJWK(privateKey);
  return { ...jwk, alg: SIGNING_ALG, kid: await calculateJwkThumbprint(jwk) };
}

/** Throws if `jwk` is not a private ES256 (P-256) key. */
export function assertPrivateSigningJwk(jwk: JWK): void {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d || !jwk.x || !jwk.y) {
    throw new Error('must be a private EC P-256 JWK (kty "EC", crv "P-256", with d, x and y)');
  }
}

export async function importSigningKeys(jwk: JWK): Promise<SigningKeys> {
  assertPrivateSigningJwk(jwk);
  const { d: _d, ...pub } = jwk;
  const kid = jwk.kid ?? (await calculateJwkThumbprint(pub));
  const publicJwk: JWK = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y, alg: SIGNING_ALG, use: 'sig', kid };
  return {
    privateKey: (await importJWK({ ...jwk, alg: SIGNING_ALG }, SIGNING_ALG)) as CryptoKey,
    publicKey: (await importJWK(publicJwk, SIGNING_ALG)) as CryptoKey,
    publicJwk,
    kid,
  };
}
