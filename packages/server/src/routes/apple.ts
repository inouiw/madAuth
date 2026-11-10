// Sign in with Apple beyond the redirect flow (which routes/oidc.ts runs for the kind `apple`): the identity token a
// native iOS or macOS app gets from Apple itself (ASAuthorizationAppleIDProvider) and hands to madAuth, as a Google ID
// token goes to /auth/providers/google/verify; and what every Apple sign-in shares: the credentials that sign the
// client secret, and giving the authorization back when the account or the user is deleted. See docs/apple-security.md.
import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AppContext } from '../app.js';
import { APPLE_ENDPOINTS, appleProfile, appleUserName, exchangeAppleCode, revokeAppleToken, verifyAppleIdToken, type AppleCredentials } from '../apple.js';
import type { KeyService } from '../key-service.js';
import { providerOf, type StoredProvider } from '../providers.js';
import { randomString, readToken, signToken } from '../tokens.js';
import { appleAccountKey, type StoredAccount } from '../users.js';
import { localeOf } from '../webhooks.js';
import { body, error, recentUser, signInAnswer } from './helpers.js';
import { linkProviderAccount, resolveProviderUser, type OAuthProvider, type ProviderProfile } from './oauth.js';

const NONCE_COOKIE = 'madauth_nonce';
const NONCE_TYP = 'madauth-nonce+jwt';
const NONCE_TTL = 5 * 60;
/** The nonce cookie comes back to Apple's routes only. */
const COOKIE_PATH = '/auth/providers/apple';

/** How the shared sign-in code names Apple's provider. */
export const asAppleProvider = (provider: StoredProvider): OAuthProvider => ({ method: provider.id, name: provider.name });

/**
 * What signs the client secret for the Apple provider: its Team ID and Key ID, and the `.p8` key, which is the
 * provider's secret. Null when the key can't be read any more (it was encrypted with a key that is gone).
 */
export async function appleCredentialsOf(ctx: AppContext, provider: StoredProvider): Promise<AppleCredentials | null> {
  const key = await ctx.clientSecret(provider);
  return key ? { teamId: provider.teamId!, keyId: provider.keyId!, key } : null;
}

/** What an Apple account keeps for giving the authorization back: the refresh token, and the client it was issued to. */
interface AppleGrant {
  clientId: string;
  refreshToken: string;
}

/** The account's secret: the grant, encrypted by the key service, as GitHub's token is. */
export const encryptAppleGrant = (keys: KeyService, grant: AppleGrant): Promise<string> => keys.encrypt('provider-token', Buffer.from(JSON.stringify(grant)));

/**
 * Gives the account's authorization back to Apple with the refresh token kept from its last sign-in, when the
 * account or the user is deleted (App Store Review Guideline 5.1.1 (v) asks for it). Best effort: the deletion
 * goes ahead whatever happens here, and a failure is logged. Nothing to do for an account without a token (a
 * native sign-in that passed no authorization code).
 */
export async function revokeAppleGrant(ctx: AppContext, account: StoredAccount | null, fetchFn: typeof fetch = fetch): Promise<void> {
  if (!account?.secret) return;
  const provider = providerOf(await ctx.methods(), 'apple');
  const credentials = provider && (await appleCredentialsOf(ctx, provider));
  if (!credentials) {
    console.error(`[madauth] The Apple authorization of user ${account.userId} can't be given back: there is no Apple provider, or its key can't be read. It stays until the user removes the app at Apple.`);
    return;
  }
  const opened = await ctx.keys.decrypt('provider-token', account.secret);
  const grant = opened ? (JSON.parse(Buffer.from(opened.plaintext).toString()) as Partial<AppleGrant>) : null;
  if (!grant?.clientId || !grant.refreshToken) {
    console.error(`[madauth] The Apple token of user ${account.userId} can't be read (was its key removed from the key service?): the authorization stays at Apple until the user removes the app there.`);
    return;
  }
  const status = await revokeAppleToken(credentials, { clientId: grant.clientId, refreshToken: grant.refreshToken }, fetchFn);
  if (status !== 200) {
    console.error(`[madauth] Apple did not take back the authorization of user ${account.userId}${status ? ` (HTTP ${status})` : ''}: it stays until the user removes the app at Apple.`);
  }
}

/**
 * Sign in with Apple for native apps: the app shows Apple's own sheet (Face ID, Touch ID) and gets an identity token
 * for its App ID, which it hands to madAuth with the nonce madAuth gave it first; the same cookie-based routes as
 * Google's. A WebView on another site than madAuth's gets no cookie: it uses the token exchange instead (see
 * routes/oidc-endpoints.ts). The Apple provider is read from the store with each request; without one, the routes
 * answer 404 as if they weren't there.
 */
export function appleRoutes(app: Hono, ctx: AppContext): void {
  const { config, keys, secure } = ctx;
  const { issuer } = config;
  const fetchFn = config.oidcFetch ?? fetch;
  const appleOf = async (c: Context) => providerOf(await ctx.methods(c), 'apple');

  const disabled = (c: Context) => error(c, 403, 'method_disabled', 'Sign in with Apple is switched off.');
  const notOffered = (c: Context) => error(c, 404, 'not_found', 'This server has no Apple provider.');

  // The nonce for Apple's sheet (`ASAuthorizationAppleIDRequest.nonce`), kept in a cookie for five minutes and used once.
  app.post('/auth/providers/apple/nonce', async (c) => {
    if (!(await appleOf(c))) return notOffered(c);
    if (!(await ctx.enabled(c, 'apple'))) return disabled(c);
    const nonce = randomString();
    const token = await signToken(keys, issuer, NONCE_TYP, { nonce }, NONCE_TTL);
    setCookie(c, NONCE_COOKIE, token, { path: COOKIE_PATH, httpOnly: true, secure, sameSite: 'Strict', maxAge: NONCE_TTL });
    return c.json({ nonce });
  });

  /**
   * The account behind the identity token in the request, checked against the nonce cookie and the provider's
   * App IDs (or its Services ID, for Apple's JS on a web page); else the answer to send. With `authorizationCode`,
   * the app's code is exchanged for the refresh token that gives the authorization back later; without one, the
   * account has none. `name` is Apple's `fullName`, which the app gets at the first sign-in only.
   */
  const verifiedCredential = async (c: Context, provider: StoredProvider, data: Record<string, unknown>): Promise<ProviderProfile | Response> => {
    if (typeof data.credential !== 'string' || !data.credential) return error(c, 400, 'verification_failed', 'credential is missing');
    const nonceClaims = await readToken<{ nonce: string }>(keys, issuer, NONCE_TYP, getCookie(c, NONCE_COOKIE));
    if (!nonceClaims) return error(c, 401, 'verification_failed', 'nonce cookie missing or expired');
    const claims = await verifyAppleIdToken(data.credential, { audiences: [provider.clientId, ...(provider.bundleIds ?? [])], nonce: nonceClaims.nonce, keys: ctx.providerKeys(APPLE_ENDPOINTS.jwksUri) });
    if (!claims) return error(c, 401, 'verification_failed', "The identity token is not one Apple issued for this server's Services ID or App IDs with this nonce.");
    deleteCookie(c, NONCE_COOKIE, { path: COOKIE_PATH, secure });
    const profile = appleProfile(claims);
    // Apple vouches for every address it sends; one without is the user's to type, but a native app gets one.
    if (!profile.email || !profile.verified) return error(c, 403, 'email_unverified', 'Apple sent no verified e-mail address.');
    const name = appleUserName(data.name === undefined ? undefined : { name: data.name });
    let secret: string | undefined;
    if (typeof data.authorizationCode === 'string' && data.authorizationCode) {
      const credentials = await appleCredentialsOf(ctx, provider);
      // The code belongs to the app the token is for: Apple exchanges it as that App ID.
      const tokens = credentials && (await exchangeAppleCode(credentials, { clientId: claims.aud, code: data.authorizationCode }, fetchFn));
      if (!tokens) return error(c, 401, 'verification_failed', "Apple did not accept the authorization code for the token's App ID.");
      if (tokens.refreshToken) secret = await encryptAppleGrant(keys, { clientId: claims.aud, refreshToken: tokens.refreshToken });
    }
    return { key: appleAccountKey(claims.sub), email: profile.email, ...(name ? { name } : {}), ...(secret ? { secret } : {}) };
  };

  app.post('/auth/providers/apple/verify', async (c) => {
    const provider = await appleOf(c);
    if (!provider) return notOffered(c);
    if (!(await ctx.enabled(c, 'apple'))) return disabled(c);
    const data = await body(c);
    const profile = await verifiedCredential(c, provider, data);
    if (profile instanceof Response) return profile;
    const resolved = await resolveProviderUser(ctx, asAppleProvider(provider), profile, localeOf(data.locale));
    if (!resolved.ok) {
      if (resolved.error === 'other_method') return c.json({ error: resolved.error, message: resolved.message, methods: resolved.methods }, 403);
      return error(c, resolved.error === 'temporarily_unavailable' ? 503 : 403, resolved.error, resolved.message);
    }
    return signInAnswer(c, await ctx.secondStep(c, resolved.user, ['apple'], 'apple', profile.name ? { name: profile.name } : undefined));
  });

  // A signed-in user adds their Apple ID to their methods, with an identity token from Apple's sheet.
  app.post('/auth/providers/apple/link', async (c) => {
    const provider = await appleOf(c);
    if (!provider) return notOffered(c);
    if (!(await ctx.enabled(c, 'apple'))) return disabled(c);
    const user = await recentUser(c, ctx);
    if (user instanceof Response) return user;
    const profile = await verifiedCredential(c, provider, await body(c));
    if (profile instanceof Response) return profile;
    const linked = await linkProviderAccount(ctx, asAppleProvider(provider), user, profile);
    if (!linked.ok) return error(c, 409, linked.error, linked.message);
    return c.json({});
  });
}
