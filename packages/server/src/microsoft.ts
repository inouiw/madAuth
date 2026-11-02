// Microsoft sign-in (the kind `microsoft` in providers.ts): personal Microsoft accounts and work or school accounts
// of Microsoft Entra ID, through the OpenID Connect providers' redirect flow (routes/oidc.ts). What differs is
// here: the endpoints are Microsoft's own, the issuer names the tenant of each account, and an address counts as
// verified only when Microsoft says the domain's owner verified it. See docs/microsoft-security.md.
import { decodeJwt, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import { suggestedAddress, verifyIdToken, type OidcEndpoints } from './oidc.js';

/** Where Microsoft's sign-in is: the Microsoft identity platform of the global cloud. */
const LOGIN_HOST = 'https://login.microsoftonline.com';

/** The tenant of every personal Microsoft account (Outlook, Xbox), as the tokens' `tid` names it. */
export const CONSUMER_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';

/** Who can sign in besides one tenant's accounts: everyone, work and school accounts, or personal accounts. */
const AUDIENCES = ['common', 'organizations', 'consumers'];
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Whether `value` can be the Microsoft provider's tenant: one of {@link AUDIENCES}, or one tenant's id (a GUID). */
export const isTenant = (value: unknown): value is string => typeof value === 'string' && (AUDIENCES.includes(value) || GUID.test(value));

/**
 * The endpoints of a tenant, as Microsoft documents them. They are not read from the discovery document: for
 * `common`, `organizations` and `consumers` its issuer is a template (`…/{tenantid}/v2.0`), which the generic
 * check refuses, and the endpoints never change.
 */
export function microsoftEndpoints(tenant: string): OidcEndpoints {
  const base = `${LOGIN_HOST}/${tenant}`;
  return {
    issuer: `${base}/v2.0`,
    authorizationEndpoint: `${base}/oauth2/v2.0/authorize`,
    tokenEndpoint: `${base}/oauth2/v2.0/token`,
    jwksUri: `${base}/discovery/v2.0/keys`,
    clientAuth: 'client_secret_post',
  };
}

/** Whether the tenant an account is in (`tid`) may sign in with the provider's `tenant`. */
function admits(tenant: string, tid: string): boolean {
  if (tenant === 'common') return true;
  if (tenant === 'consumers') return tid === CONSUMER_TENANT;
  if (tenant === 'organizations') return tid !== CONSUMER_TENANT;
  return tid === tenant.toLowerCase();
}

/** A JWT's claims without any check, or null if it is no JWT (jose throws for that). */
function unverifiedClaims(token: string): JWTPayload | null {
  try {
    return decodeJwt(token);
  } catch {
    return null;
  }
}

/**
 * The claims of a Microsoft ID token, checked as {@link verifyIdToken} checks any, with the issuer of the account's
 * own tenant (`https://login.microsoftonline.com/<tid>/v2.0`): the `tid` must be one `tenant` admits, and the
 * token must carry the account's `oid`. Null if anything doesn't hold.
 */
export async function verifyMicrosoftIdToken(
  idToken: string,
  expected: { tenant: string; clientId: string; nonce: string; keys: JWTVerifyGetKey },
): Promise<(JWTPayload & { tid: string; oid: string }) | null> {
  // The tenant comes from the token before its signature is checked; the issuer check that follows proves it.
  const unverified = unverifiedClaims(idToken);
  const tid = typeof unverified?.tid === 'string' ? unverified.tid.toLowerCase() : null;
  if (!tid || !GUID.test(tid) || !admits(expected.tenant, tid)) return null;
  const claims = await verifyIdToken(idToken, { issuer: `${LOGIN_HOST}/${tid}/v2.0`, clientId: expected.clientId, nonce: expected.nonce, keys: expected.keys });
  if (!claims || typeof claims.oid !== 'string' || !claims.oid) return null;
  return { ...claims, tid, oid: claims.oid };
}

/**
 * What Microsoft's ID token says about the user: the address, verified only when `xms_edov` (the optional claim
 * "email domain owner verified") is true, since a tenant's admin can give a user any address; and the name. With
 * no address, the {@link suggestedAddress} for the user to confirm.
 */
export function microsoftProfile(claims: JWTPayload): { email?: string; verified: boolean; name?: string; suggestion?: string } {
  const email = typeof claims.email === 'string' && claims.email ? claims.email : undefined;
  const name = typeof claims.name === 'string' && claims.name ? claims.name : undefined;
  const suggestion = suggestedAddress(claims);
  return {
    ...(email ? { email } : {}),
    verified: !!email && (claims.xms_edov === true || claims.xms_edov === 'true' || claims.xms_edov === 1),
    ...(name ? { name } : {}),
    ...(!email && suggestion ? { suggestion } : {}),
  };
}
