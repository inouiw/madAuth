import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { MadauthUser } from './user.js';

const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

let googleJwks: JWTVerifyGetKey | undefined;

/** Google's published signing keys (fetched on first use, cached by jose). */
export function googleKeys(): JWTVerifyGetKey {
  googleJwks ??= createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
  return googleJwks;
}

export type GoogleVerifyResult =
  | { ok: true; user: MadauthUser }
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
  if (payload.email_verified !== true) {
    return { ok: false, error: 'email_unverified', reason: 'e-mail address not verified' };
  }
  const user: MadauthUser = { id: `google:${payload.sub}` };
  if (typeof payload.email === 'string') user.email = payload.email;
  if (typeof payload.name === 'string') user.name = payload.name;
  if (typeof payload.picture === 'string') user.picture = payload.picture;
  return { ok: true, user };
}
