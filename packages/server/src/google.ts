import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';

/** What a verified Google ID token says about its account. */
export interface GoogleProfile {
  /** Google's stable id of the account; its address may change. */
  sub: string;
  /** The account's current primary address, verified by Google. */
  email: string;
  name?: string;
  picture?: string;
}

const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

let googleJwks: JWTVerifyGetKey | undefined;

/** Google's published signing keys (fetched on first use, cached by jose). */
export function googleKeys(): JWTVerifyGetKey {
  googleJwks ??= createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
  return googleJwks;
}

export type GoogleVerifyResult =
  | { ok: true; profile: GoogleProfile }
  | { ok: false; error: 'verification_failed' | 'email_unverified'; reason: string };

/**
 * Verifies a Google ID token: signature, issuer, audience, expiry, nonce and a verified e-mail address.
 * Used by both the FedCM/One Tap flow and the server-side code flow.
 */
export async function verifyGoogleIdToken(
  idToken: string,
  opts: { clientId: string; nonce: string; keys?: JWTVerifyGetKey },
): Promise<GoogleVerifyResult> {
  let payload;
  try {
    ({ payload } = await jwtVerify(idToken, opts.keys ?? googleKeys(), {
      issuer: GOOGLE_ISSUERS,
      audience: opts.clientId,
      algorithms: ['RS256', 'ES256'],
    }));
  } catch (e) {
    return { ok: false, error: 'verification_failed', reason: (e as Error).message };
  }
  if (typeof payload.sub !== 'string' || !payload.sub) {
    return { ok: false, error: 'verification_failed', reason: 'missing sub' };
  }
  if (payload.nonce !== opts.nonce) {
    return { ok: false, error: 'verification_failed', reason: 'nonce mismatch' };
  }
  if (typeof payload.email !== 'string' || !payload.email || payload.email_verified !== true) {
    return { ok: false, error: 'email_unverified', reason: 'e-mail address not verified' };
  }
  const profile: GoogleProfile = { sub: payload.sub, email: payload.email };
  if (typeof payload.name === 'string') profile.name = payload.name;
  if (typeof payload.picture === 'string') profile.picture = payload.picture;
  return { ok: true, profile };
}
