// The sign-in providers that speak OAuth 2.0 without OpenID Connect (the kinds `facebook` and `x`), as one table
// for the OpenID Connect providers' routes (routes/oidc.ts): where the user approves, how the code becomes an
// access token, and what the provider's API says about the account behind it. Another such provider is one more
// entry. See docs/facebook-security.md and docs/x-security.md.
import { exchangeFacebookCode, facebookAuthorizeUrl, fetchFacebookProfile } from './facebook.js';
import { facebookAccountKey, xAccountKey } from './users.js';
import { exchangeXCode, fetchXProfile, xAuthorizeUrl } from './x.js';

/** What a provider's API says about the account that signed in. */
export interface SocialProfile {
  /** The account's id at the provider, which never changes (Facebook's is app-scoped: this app's only). */
  id: string;
  /** The address, if the provider gave one. */
  email?: string;
  /** Whether the provider says it confirmed the address. */
  verified: boolean;
  name?: string;
  picture?: string;
}

export type SocialProfileResult = { ok: true; profile: SocialProfile } | { ok: false; reason: string };

/** The authorization request of a sign-in: `codeChallenge` is the PKCE challenge, which a provider without PKCE leaves out. */
export interface SocialAuthorizeRequest {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
}

/** What a provider without OpenID Connect does in a sign-in. */
export interface SocialFlow {
  authorizeUrl(request: SocialAuthorizeRequest): string;
  /** The access token for the callback's code, or null if the provider issued none. */
  exchange(app: { clientId: string; clientSecret: string }, exchange: { code: string; redirectUri: string; verifier: string }, fetchFn: typeof fetch): Promise<string | null>;
  /** The account behind the access token; `appSecret` for a provider that wants proof of it with each call (Facebook). */
  profile(token: string, appSecret: string, fetchFn: typeof fetch): Promise<SocialProfileResult>;
  /** The key of the account in the store, from the provider's id for it. */
  accountKey(id: string): string;
}

export const SOCIAL_FLOWS = {
  facebook: {
    authorizeUrl: facebookAuthorizeUrl,
    exchange: (app, { code, redirectUri }, fetchFn) => exchangeFacebookCode(app, { code, redirectUri }, fetchFn),
    profile: fetchFacebookProfile,
    accountKey: facebookAccountKey,
  },
  x: {
    authorizeUrl: xAuthorizeUrl,
    exchange: exchangeXCode,
    profile: (token, _appSecret, fetchFn) => fetchXProfile(token, fetchFn),
    accountKey: xAccountKey,
  },
} satisfies Record<string, SocialFlow>;

export type SocialKind = keyof typeof SOCIAL_FLOWS;

/** Whether a provider's kind is one of these, whose sign-in is {@link SOCIAL_FLOWS}'s. */
export const isSocialKind = (kind: string): kind is SocialKind => Object.hasOwn(SOCIAL_FLOWS, kind);
