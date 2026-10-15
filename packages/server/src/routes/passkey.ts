// Passkeys (WebAuthn): a signed-in user adds them; they sign the user in on their own when an admin allows
// them as a sign-in method, and then people can sign up with one alone (the address confirmed by e-mail
// first); they are a second factor of the methods whose policy asks for one. The security rules are described
// in docs/passkey-security.md.
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
import { isWithin, type MadauthConfig } from '../config.js';
import { isOn } from '../settings.js';
import { readToken, signToken } from '../tokens.js';
import { passkeyAccountKey, toMadauthUser, type StoredAccount, type StoredUser } from '../users.js';
import { finishSignIn, isSignUpStep, pendingFactor, whoSetsUp } from './challenge.js';
import { reclaimConfirmation, signUpThenSetUp } from './email.js';
import { createEmails } from './emails.js';
import { body, error, nameOf, noSession, originHost, signInAnswer, type Body } from './helpers.js';

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

/**
 * The domain the passkeys of an app belong to: PASSKEY_RP_ID, else the app's host. Null when the app is
 * outside PASSKEY_RP_ID (the browser would refuse its passkeys), or `origin` is none.
 */
export function passkeyDomain(config: Pick<MadauthConfig, 'passkeyRpId'>, origin: string | undefined): string | null {
  const host = origin && URL.canParse(origin) ? new URL(origin).hostname : '';
  const rpId = config.passkeyRpId ?? host;
  return host && isWithin(host, rpId) ? rpId : null;
}

/** Whether a passkey answers on `rpId`: it was made for that domain (passkeys stored without one count). */
export const usableOn =
  (rpId: string | null) =>
  (account: StoredAccount): boolean =>
    !!rpId && (!account.rpId || account.rpId === rpId);

const toEntry = (account: StoredAccount): PasskeyEntry => ({
  id: account.id,
  name: account.name ?? '',
  createdAt: account.createdAt,
  lastUsedAt: account.lastUsedAt ?? 0,
});


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

  /** The domain the passkeys of the requesting app belong to, and the app; null when it can't use passkeys. */
  const rpIdOf = (c: Context): { rpId: string; origin: string } | null => {
    // POST routes only: the origin is one of ALLOWED_ORIGINS (see app.ts).
    const origin = c.req.header('origin') ?? '';
    const rpId = passkeyDomain(config, origin);
    return rpId ? { rpId, origin } : null;
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

  /**
   * Checks the browser's answer in `data` against the passkey it names and notes the answer as used. `owner`
   * is whose passkey may answer (null: not one of them, then `refused` is the answer). Resolves to the user,
   * and the write that notes the passkey's use (its counter, and when), which nothing else waits for.
   */
  const acceptAssertion = async (
    c: Context,
    ceremony: CeremonyClaims & { exp: number },
    data: Body,
    owner: (account: StoredAccount) => Promise<StoredUser | null>,
    refused: () => Response,
  ): Promise<{ user: StoredUser; used: Promise<boolean> } | Response> => {
    if (!isCredential(data.response)) return failed(c);
    const response = data.response as unknown as AuthenticationResponseJSON;
    const account = await users.passkeyByCredential(response.id);
    const user = account ? await owner(account) : null;
    if (!account || !user) return refused();
    // The authenticator names the user it made the passkey for: it must be the passkey's.
    const handle = response.response.userHandle;
    if (handle && Buffer.from(handle, 'base64url').toString() !== user.id) return failed(c);
    const counter = await verifyAssertion(response, ceremony, account);
    if (counter === null || !(await users.useCeremony(user.id, ceremony.challenge, ceremony.exp * 1000))) return failed(c);
    return { user, used: users.updateAccount(account.id, { signCount: counter, lastUsedAt: Date.now() }) };
  };

  /** The passkeys as the browser's options name them. */
  const descriptors = (passkeys: StoredAccount[]) =>
    passkeys.flatMap((p) => (p.credentialId ? [{ id: p.credentialId, transports: splitTransports(p.transports) }] : []));

  // --- Adding a passkey ---

  /**
   * Who adds a passkey: the user whose sign-in waits for a second factor's setup (a `required` policy) or
   * whose sign-up with a passkey waits for it, or the signed-in user if they signed in recently (a passkey is
   * a way in of its own); else the answer to send.
   */
  const whoAdds = (c: Context) => whoSetsUp(c, ctx, 'passkey', async () => true);

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
      excludeCredentials: descriptors(existing),
      // A discoverable passkey (it signs in without the address first), and always with a PIN or biometrics.
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
    });
    return begin(c, { purpose: 'register', challenge: options.challenge, ...domain, sub: user.id }, options);
  });

  app.post(`${ROUTE_PATH}/register/verify`, async (c) => {
    const who = await whoAdds(c);
    if (who instanceof Response) return who;
    const { user: adding, challenge } = who;
    const ceremony = await finish(c, 'register', adding.id);
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
      console.warn(`[madauth] A new passkey of user ${adding.id} was refused: ${(e as Error).message}`);
      return failed(c);
    }
    // The answer adds one passkey: the same options don't add another.
    if (!verification.verified || !(await users.useCeremony(adding.id, ceremony.challenge, ceremony.exp * 1000))) return failed(c);
    // A sign-up with a passkey alone: the new passkey is the method the user signs up with.
    const signUp = !!challenge && isSignUpStep(challenge);
    const user = signUp ? await reclaimConfirmation(users, adding) : adding;
    const { credential } = verification.registrationInfo;
    const name = nameOf(data.name, MAX_NAME_LENGTH) ?? 'Passkey';
    const key = passkeyAccountKey(credential.id);
    const account = await users.linkAccount(user.id, {
      key,
      secret: Buffer.from(credential.publicKey).toString('base64url'),
      primary: signUp,
      passkey: { name, credentialId: credential.id, signCount: credential.counter, transports: joinTransports(credential.transports), rpId: ceremony.rpId },
    });
    // The sign-up's passkey is refused when the sign-up got its method meanwhile: a password confirmed by its
    // own e-mail, or another passkey of this sign-up (a second tab).
    if (!account && signUp && !(await users.findAccountByKey(key))) {
      return error(c, 400, 'setup_expired', 'Your sign-up was finished meanwhile. Please sign in.');
    }
    if (!account) return error(c, 409, 'already_added', 'This passkey is added already.');
    const passkey = toEntry(account);
    // The passkey a user signs up with is part of their sign-up (`user.signed_up`), not a method they added.
    if (signUp) {
      // It signs in now, as a passkey sign-in would: its policy may ask for a second factor first.
      const step = await ctx.secondStep(c, user, ['passkey'], 'passkey');
      return 'user' in step ? c.json({ passkey, user: step.user }) : signInAnswer(c, step);
    }
    await ctx.emit('user.method_added', { user: toMadauthUser(user), method: 'passkey', passkey: { id: passkey.id, name } });
    // The setup of a sign-in's second step: the new passkey finishes it.
    if (challenge) return c.json({ passkey, user: await finishSignIn(c, ctx, user, challenge, 'passkey', 'passkey') });
    return c.json({ passkey });
  });

  // --- Signing up with a passkey alone: the address is confirmed by e-mail, then the passkey is created ---

  if (ctx.webhook && ctx.emailVerification) {
    const emails = createEmails(ctx, users, ctx.webhook);
    app.post(`${ROUTE_PATH}/signup`, async (c) => {
      if (!(await ctx.enabled(c, 'passkey'))) return error(c, 403, 'method_disabled', 'Signing up with a passkey is switched off.');
      // An app outside PASSKEY_RP_ID, or a link to one, could confirm the address, but never create the passkey.
      const target = ctx.allowedUrl((await body(c)).redirectTo);
      const outside = !rpIdOf(c) || (!!target && !passkeyDomain(config, target.origin));
      return outside ? wrongDomain(c) : signUpThenSetUp(c, ctx, emails, 'passkey');
    });
  }

  // --- Signing in with a passkey alone ---

  // Both routes: passkeys don't sign in on their own here.
  app.use(`${ROUTE_PATH}/signin/*`, async (c, next) => {
    if (!(await ctx.enabled(c, 'passkey'))) return error(c, 403, 'method_disabled', 'Signing in with a passkey is switched off.');
    await next();
  });

  app.post(`${ROUTE_PATH}/signin/options`, async (c) => {
    const domain = rpIdOf(c);
    if (!domain) return wrongDomain(c);
    // No list of passkeys: the browser offers the user's own (discoverable), so no address is asked for.
    const options = await generateAuthenticationOptions({ rpID: domain.rpId, userVerification: 'required' });
    return begin(c, { purpose: 'signin', challenge: options.challenge, ...domain }, options);
  });

  app.post(`${ROUTE_PATH}/signin/verify`, async (c) => {
    const ceremony = await finish(c, 'signin');
    if (!ceremony) return expired(c);
    // A passkey the user removed (or whose user is gone) is still offered by their device: say so, so they can delete it there.
    const unknown = () => error(c, 401, 'passkey_unknown', 'This passkey is not registered (any more). Sign in another way, and remove it from your device.');
    const accepted = await acceptAssertion(c, ceremony, await body(c), (account) => users.findById(account.userId), unknown);
    if (accepted instanceof Response) return accepted;
    const [step] = await Promise.all([ctx.secondStep(c, accepted.user, ['passkey'], 'passkey'), accepted.used]);
    return signInAnswer(c, step);
  });

  // --- The second step of a sign-in ---

  app.post(`${ROUTE_PATH}/verify/options`, async (c) => {
    const pending = await pendingFactor(c, ctx, 'passkey');
    if (pending instanceof Response) return pending;
    const domain = rpIdOf(c);
    if (!domain) return wrongDomain(c);
    // Only those that answer here: a passkey made for another domain can't.
    const passkeys = (await users.passkeys(pending.user.id)).filter(usableOn(domain.rpId));
    if (!passkeys.length) return error(c, 401, 'challenge_expired', 'The sign-in has expired. Please sign in again.');
    // Only the user's own passkeys: they signed in already, the browser needs no choice of account.
    const options = await generateAuthenticationOptions({
      rpID: domain.rpId,
      userVerification: 'required',
      allowCredentials: descriptors(passkeys),
    });
    return begin(c, { purpose: 'verify', challenge: options.challenge, ...domain, sub: pending.user.id }, options);
  });

  app.post(`${ROUTE_PATH}/verify`, async (c) => {
    const pending = await pendingFactor(c, ctx, 'passkey');
    if (pending instanceof Response) return pending;
    const { challenge, user } = pending;
    const ceremony = await finish(c, 'verify', user.id);
    if (!ceremony) return expired(c);
    // Only a passkey of this user finishes their sign-in.
    const accepted = await acceptAssertion(c, ceremony, await body(c), async (account) => (account.userId === user.id ? user : null), () => failed(c));
    if (accepted instanceof Response) return accepted;
    const [result] = await Promise.all([finishSignIn(c, ctx, user, challenge, 'passkey', 'passkey'), accepted.used]);
    return c.json({ user: result });
  });

  // --- The signed-in user's passkeys ---

  app.post(`${ROUTE_PATH}/rename`, async (c) => {
    const session = await ctx.currentUser(c);
    if (!session) return noSession(c);
    const data = await body(c);
    const name = nameOf(data.name, MAX_NAME_LENGTH);
    if (!name) return error(c, 400, 'invalid_options', `name must be a text of 1 to ${MAX_NAME_LENGTH} characters.`);
    const account = typeof data.id === 'string' ? (await users.passkeys(session.id)).find((p) => p.id === data.id) : undefined;
    if (!account || !(await users.updateAccount(account.id, { name }))) return error(c, 404, 'method_not_found', 'You have no such passkey.');
    return c.json({ passkey: toEntry({ ...account, name }) });
  });
}
