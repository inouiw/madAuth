// Passkeys (WebAuthn): a signed-in user adds them; they sign the user in on their own when an admin allows
// them as a sign-in method, and are a second factor of the methods whose policy asks for one. The security
// rules are described in docs/passkey-security.md.
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { JWTPayload } from 'jose';
import type { AppContext } from '../app.js';
import { isWithin } from '../config.js';
import { isOn, signsIn } from '../settings.js';
import { readToken, signToken } from '../tokens.js';
import { passkeyAccountKey, toMadauthUser, type StoredAccount, type StoredUser } from '../users.js';
import { finishSignIn, methodOff, methodStillOn, pendingOrSignedIn, readChallenge, type ChallengeClaims } from './challenge.js';
import { body, error, noSession, originHost, recentUser, signInAnswer, type Body } from './helpers.js';

/** The routes, and where the ceremony cookie is sent. */
const ROUTE_PATH = '/auth/passkey';

const CEREMONY_COOKIE = 'madauth_passkey';
const CEREMONY_TYP = 'madauth-passkey+jwt';
/** How long the browser's passkey dialog may take, from the options to the answer. */
const CEREMONY_TTL = 5 * 60;

/**
 * The signature algorithms of the passkeys madAuth takes (COSE ids): EdDSA, ES256 and RS256, what every
 * authenticator offers. Given explicitly, so the library does not probe the runtime for newer ones, which
 * prints Node's warnings about experimental features at every ceremony.
 */
const SUPPORTED_ALGORITHMS = [-8, -7, -257];

/** The longest name a passkey keeps. */
const MAX_NAME_LENGTH = 64;

/**
 * What a ceremony is for: adding a passkey, signing in with one alone, or the second step of a sign-in.
 * Each purpose's answer is only accepted with its own options.
 */
type Purpose = 'register' | 'signin' | 'verify';

/**
 * The ceremony cookie: its purpose, the challenge the authenticator signs, the domain and the app it was
 * asked from, and (adding a passkey, the second step) whose ceremony it is.
 */
interface CeremonyClaims extends JWTPayload {
  purpose: Purpose;
  challenge: string;
  rpId: string;
  origin: string;
  sub?: string;
}

/** A passkey as the signed-in user's list shows it. */
export interface PasskeyEntry {
  id: string;
  name: string;
  createdAt: number;
  lastUsedAt: number;
}

const toEntry = (account: StoredAccount): PasskeyEntry => ({
  id: account.id,
  name: account.name ?? '',
  createdAt: account.createdAt,
  lastUsedAt: account.lastUsedAt ?? 0,
});

/** A name as the user gave it: trimmed and cut; null if there is none. */
const passkeyName = (value: unknown): string | null => (typeof value === 'string' && value.trim() ? value.trim().slice(0, MAX_NAME_LENGTH) : null);

/** The transports as stored, and back. */
const joinTransports = (transports: readonly string[] | undefined): string | null => (transports?.length ? transports.join(',') : null);
const splitTransports = (stored: string | null): AuthenticatorTransport[] | undefined =>
  stored ? (stored.split(',') as AuthenticatorTransport[]) : undefined;

/** Whether a request body's `response` looks like a credential from the browser; what is in it the library checks. */
const isCredential = (value: unknown): value is { id: string; response: Record<string, unknown> } =>
  !!value && typeof value === 'object' && typeof (value as { id?: unknown }).id === 'string' && !!(value as { response?: unknown }).response;

export function passkeyRoutes(app: Hono, ctx: AppContext): void {
  const { config, secure, users } = ctx;
  const cookie = { path: ROUTE_PATH, httpOnly: true, secure, sameSite: 'Strict' as const };

  // Every route: an admin switched passkeys off.
  app.use(`${ROUTE_PATH}/*`, async (c, next) => {
    if (!isOn('passkey', ctx.configured, await ctx.methods(c))) return error(c, 403, 'method_disabled', 'Passkeys are switched off.');
    await next();
  });

  /**
   * The domain the passkeys of the requesting app belong to: PASSKEY_RP_ID, else the app's host. Null when
   * the app is outside PASSKEY_RP_ID: the browser would refuse its passkeys.
   */
  const rpIdOf = (c: Context): { rpId: string; origin: string } | null => {
    // POST routes only: the origin is one of ALLOWED_ORIGINS (see app.ts).
    const origin = c.req.header('origin') ?? '';
    const host = URL.canParse(origin) ? new URL(origin).hostname : '';
    const rpId = config.passkeyRpId ?? host;
    return host && isWithin(host, rpId) ? { rpId, origin } : null;
  };
  const wrongDomain = (c: Context) =>
    error(c, 403, 'forbidden_origin', `Passkeys belong to ${config.passkeyRpId}: this app's address is outside it, so it can't use them.`);

  /** Starts a ceremony: the cookie with its challenge, the options for the browser as the answer. */
  const begin = async (c: Context, claims: CeremonyClaims, options: object) => {
    const token = await signToken(await ctx.keys, config.issuer, CEREMONY_TYP, { ...claims }, CEREMONY_TTL);
    setCookie(c, CEREMONY_COOKIE, token, { ...cookie, maxAge: CEREMONY_TTL });
    return c.json(options);
  };

  /**
   * The ceremony this answer finishes, for `purpose`; the cookie goes with it. Null if there is none, it
   * expired, or it is for another purpose or user. A browser that keeps the cookie can't use an answer
   * twice either: an accepted one is noted (see `Users.useCeremony`).
   */
  const finish = async (c: Context, purpose: Purpose, sub?: string): Promise<(CeremonyClaims & { exp: number }) | null> => {
    const claims = await readToken<CeremonyClaims>(await ctx.keys, config.issuer, CEREMONY_TYP, getCookie(c, CEREMONY_COOKIE));
    if (!claims || claims.purpose !== purpose || claims.sub !== sub || typeof claims.challenge !== 'string') return null;
    deleteCookie(c, CEREMONY_COOKIE, cookie);
    return claims;
  };
  const expired = (c: Context) => error(c, 400, 'setup_expired', 'The passkey dialog took too long or was opened in another browser. Please try again.');
  const failed = (c: Context) => error(c, 401, 'verification_failed', 'The passkey could not be verified. Please try again.');

  /**
   * Checks an answer from the browser against a passkey of the ceremony: the signature, the challenge, the
   * app and the domain, and that the user was verified (PIN, fingerprint, face). Resolves to the passkey's
   * new counter, or null if anything is wrong.
   */
  const verifyAssertion = async (response: AuthenticationResponseJSON, ceremony: CeremonyClaims, account: StoredAccount): Promise<number | null> => {
    if (!account.secret || !account.credentialId) return null;
    try {
      const { verified, authenticationInfo } = await verifyAuthenticationResponse({
        response,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: ceremony.origin,
        expectedRPID: ceremony.rpId,
        credential: {
          id: account.credentialId,
          publicKey: new Uint8Array(Buffer.from(account.secret, 'base64url')),
          counter: account.signCount ?? 0,
          transports: splitTransports(account.transports),
        },
        requireUserVerification: true,
      });
      return verified ? authenticationInfo.newCounter : null;
    } catch (e) {
      // The library throws for every answer that does not fit, e.g. a counter that went backwards (a cloned key).
      console.warn(`[madauth] A passkey of user ${account.userId} was refused: ${(e as Error).message}`);
      return null;
    }
  };

  /** Notes a passkey's use: its counter, and when. */
  const used = (account: StoredAccount, counter: number) => users.updateAccount(account.id, { signCount: counter, lastUsedAt: Date.now() });

  // --- Adding a passkey ---

  /**
   * Who adds a passkey: the user whose sign-in waits for a second factor's setup (a `required` policy), or
   * the signed-in user if they signed in recently; else the answer to send.
   */
  const whoAdds = async (c: Context): Promise<{ user: StoredUser; challenge: ChallengeClaims | null } | Response> => {
    const pending = await pendingOrSignedIn(c, ctx, 'passkey');
    if (pending?.challenge) {
      // A sign-up with the app has no first factor yet: it sets the app up, so a passkey is never added for it.
      if (!pending.challenge.amr.length) return noSession(c);
      return (await methodStillOn(c, ctx, pending.challenge)) ? pending : methodOff(c);
    }
    const user = await recentUser(c, ctx);
    return user instanceof Response ? user : { user, challenge: null };
  };

  app.post(`${ROUTE_PATH}/register/options`, async (c) => {
    const who = await whoAdds(c);
    if (who instanceof Response) return who;
    const domain = rpIdOf(c);
    if (!domain) return wrongDomain(c);
    const { user } = who;
    const existing = await users.passkeys(user.id);
    const options = await generateRegistrationOptions({
      rpName: config.totpIssuer || originHost(ctx, c),
      rpID: domain.rpId,
      userName: user.email,
      userDisplayName: user.name ?? user.email,
      // The user handle: the passkey names its user by madAuth's id, which says nothing about them.
      userID: new TextEncoder().encode(user.id),
      attestationType: 'none',
      // The browser refuses an authenticator that has a passkey of this user already.
      excludeCredentials: existing.flatMap((p) => (p.credentialId ? [{ id: p.credentialId, transports: splitTransports(p.transports) }] : [])),
      // A discoverable passkey (it signs in without the address first), and always with a PIN or biometrics.
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
    });
    return begin(c, { purpose: 'register', challenge: options.challenge, ...domain, sub: user.id }, options);
  });

  app.post(`${ROUTE_PATH}/register/verify`, async (c) => {
    const who = await whoAdds(c);
    if (who instanceof Response) return who;
    const { user, challenge } = who;
    const ceremony = await finish(c, 'register', user.id);
    if (!ceremony) return expired(c);
    const data = await body(c);
    if (!isCredential(data.response)) return failed(c);
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: data.response as unknown as RegistrationResponseJSON,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: ceremony.origin,
        expectedRPID: ceremony.rpId,
        requireUserVerification: true,
        supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
      });
    } catch (e) {
      console.warn(`[madauth] A new passkey of user ${user.id} was refused: ${(e as Error).message}`);
      return failed(c);
    }
    // The answer adds one passkey: the same options don't add another.
    if (!verification.verified || !(await users.useCeremony(user.id, ceremony.challenge, ceremony.exp * 1000))) return failed(c);
    const { credential } = verification.registrationInfo;
    const name = passkeyName(data.name) ?? 'Passkey';
    const account = await users.linkAccount(user.id, {
      key: passkeyAccountKey(credential.id),
      secret: Buffer.from(credential.publicKey).toString('base64url'),
      primary: false,
      passkey: { name, credentialId: credential.id, signCount: credential.counter, transports: joinTransports(credential.transports) },
    });
    if (!account) return error(c, 409, 'already_added', 'This passkey is added already.');
    const passkey = toEntry(account);
    await ctx.emit('user.method_added', { user: toMadauthUser(user), method: 'passkey', passkey: { id: passkey.id, name } });
    // The setup of a sign-in's second step: the new passkey finishes it.
    if (challenge) return c.json({ passkey, user: await finishSignIn(c, ctx, user, challenge, 'passkey', 'passkey') });
    return c.json({ passkey });
  });

  // --- Signing in with a passkey alone ---

  app.post(`${ROUTE_PATH}/signin/options`, async (c) => {
    if (!signsIn('passkey', ctx.configured, await ctx.methods(c))) return error(c, 403, 'method_disabled', 'Signing in with a passkey is switched off.');
    const domain = rpIdOf(c);
    if (!domain) return wrongDomain(c);
    // No list of passkeys: the browser offers the user's own (discoverable), so no address is asked for.
    const options = await generateAuthenticationOptions({ rpID: domain.rpId, userVerification: 'required' });
    return begin(c, { purpose: 'signin', challenge: options.challenge, ...domain }, options);
  });

  app.post(`${ROUTE_PATH}/signin/verify`, async (c) => {
    if (!signsIn('passkey', ctx.configured, await ctx.methods(c))) return error(c, 403, 'method_disabled', 'Signing in with a passkey is switched off.');
    const ceremony = await finish(c, 'signin');
    if (!ceremony) return expired(c);
    const data: Body = await body(c);
    if (!isCredential(data.response)) return failed(c);
    const response = data.response as unknown as AuthenticationResponseJSON;
    const account = await users.passkeyByCredential(response.id);
    const user = account ? await users.findById(account.userId) : null;
    // A passkey the user removed (or whose user is gone) is still offered by their device: say so, so they can delete it there.
    if (!account || !user) return error(c, 401, 'passkey_unknown', 'This passkey is not registered (any more). Sign in another way, and remove it from your device.');
    // The authenticator names the user it made the passkey for: it must be the passkey's.
    const handle = response.response.userHandle;
    if (handle && Buffer.from(handle, 'base64url').toString() !== user.id) return failed(c);
    const counter = await verifyAssertion(response, ceremony, account);
    if (counter === null || !(await users.useCeremony(user.id, ceremony.challenge, ceremony.exp * 1000))) return failed(c);
    await used(account, counter);
    return signInAnswer(c, await ctx.secondStep(c, user, ['passkey'], 'passkey'));
  });

  // --- The second step of a sign-in ---

  /** The sign-in that waits for a passkey, with its user; else the answer to send. */
  const waiting = async (c: Context): Promise<{ challenge: ChallengeClaims; user: StoredUser } | Response> => {
    const challenge = await readChallenge(c, ctx, 'passkey');
    const sessionEnded = () => error(c, 401, 'challenge_expired', 'The sign-in has expired. Please sign in again.');
    if (!challenge) return sessionEnded();
    if (!(await methodStillOn(c, ctx, challenge))) return methodOff(c);
    const user = await users.findById(challenge.sub);
    // The user is gone, or a password reset ended their sessions meanwhile.
    return user && user.sessionVersion === challenge.sv ? { challenge, user } : sessionEnded();
  };

  app.post(`${ROUTE_PATH}/verify/options`, async (c) => {
    const pending = await waiting(c);
    if (pending instanceof Response) return pending;
    const domain = rpIdOf(c);
    if (!domain) return wrongDomain(c);
    const passkeys = await users.passkeys(pending.user.id);
    if (!passkeys.length) return error(c, 401, 'challenge_expired', 'The sign-in has expired. Please sign in again.');
    // Only the user's own passkeys: they signed in already, the browser needs no choice of account.
    const options = await generateAuthenticationOptions({
      rpID: domain.rpId,
      userVerification: 'required',
      allowCredentials: passkeys.flatMap((p) => (p.credentialId ? [{ id: p.credentialId, transports: splitTransports(p.transports) }] : [])),
    });
    return begin(c, { purpose: 'verify', challenge: options.challenge, ...domain, sub: pending.user.id }, options);
  });

  app.post(`${ROUTE_PATH}/verify`, async (c) => {
    const pending = await waiting(c);
    if (pending instanceof Response) return pending;
    const { challenge, user } = pending;
    const ceremony = await finish(c, 'verify', user.id);
    if (!ceremony) return expired(c);
    const data = await body(c);
    if (!isCredential(data.response)) return failed(c);
    const response = data.response as unknown as AuthenticationResponseJSON;
    const account = await users.passkeyByCredential(response.id);
    // Only a passkey of this user finishes their sign-in.
    if (!account || account.userId !== user.id) return failed(c);
    const counter = await verifyAssertion(response, ceremony, account);
    if (counter === null || !(await users.useCeremony(user.id, ceremony.challenge, ceremony.exp * 1000))) return failed(c);
    await used(account, counter);
    return c.json({ user: await finishSignIn(c, ctx, user, challenge, 'passkey', 'passkey') });
  });

  // --- The signed-in user's passkeys ---

  app.post(`${ROUTE_PATH}/rename`, async (c) => {
    const session = await ctx.currentUser(c);
    if (!session) return noSession(c);
    const data = await body(c);
    const name = passkeyName(data.name);
    if (!name) return error(c, 400, 'invalid_options', `name must be a text of 1 to ${MAX_NAME_LENGTH} characters.`);
    const account = typeof data.id === 'string' ? (await users.passkeys(session.id)).find((p) => p.id === data.id) : undefined;
    if (!account || !(await users.updateAccount(account.id, { name }))) return error(c, 404, 'method_not_found', 'You have no such passkey.');
    return c.json({ passkey: toEntry({ ...account, name }) });
  });
}
