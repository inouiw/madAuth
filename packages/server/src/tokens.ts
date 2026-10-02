import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import { SIGNING_ALG, type SigningKeys } from './keys.js';
import { SESSION_TYP, type MadauthUser } from './user.js';

/**
 * Signs a short-lived madAuth token. `typ` keeps the token kinds (session, nonce, OAuth state) apart,
 * so one can never be accepted as another.
 */
export async function signToken(
  keys: SigningKeys,
  issuer: string,
  typ: string,
  claims: JWTPayload,
  ttlSeconds: number,
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: SIGNING_ALG, kid: keys.kid, typ })
    .setIssuer(issuer)
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .sign(keys.privateKey);
}

/** Verifies a token from {@link signToken}. Returns null if it is invalid, expired or of another kind. */
export async function readToken<T extends JWTPayload>(
  keys: SigningKeys,
  issuer: string,
  typ: string,
  token: string | undefined,
): Promise<(T & { iat: number; exp: number }) | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify<T>(token, keys.publicKey, { issuer, typ, algorithms: [SIGNING_ALG] });
    return payload as T & { iat: number; exp: number };
  } catch {
    return null;
  }
}

/** Claims of a madAuth session JWT. */
export interface SessionClaims extends JWTPayload {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  amr: string[];
}

export function signSession(
  keys: SigningKeys,
  issuer: string,
  ttlSeconds: number,
  user: MadauthUser,
  amr: string[],
): Promise<string> {
  const claims: SessionClaims = {
    sub: user.id,
    email: user.email,
    email_verified: user.email ? true : undefined,
    name: user.name,
    picture: user.picture,
    amr,
  };
  return signToken(keys, issuer, SESSION_TYP, claims, ttlSeconds);
}

export function userFromClaims(claims: SessionClaims): MadauthUser {
  const user: MadauthUser = { id: claims.sub };
  if (claims.email) user.email = claims.email;
  if (claims.name) user.name = claims.name;
  if (claims.picture) user.picture = claims.picture;
  return user;
}
