// Sign-in providers, which admins configure while the server runs: Google, GitHub and generic OpenID Connect
// providers (the kind `oidc`, e.g. GitLab, Okta, Keycloak; see oidc.ts). They are kept in the store
// as one setting, `providers`, like the sign-in methods; each client secret is encrypted by the key service, so the
// store alone doesn't reveal it. See "Providers" in docs/server.md.
import type { KeyService } from './key-service.js';
import { isIssuer } from './oidc.js';
import type { Settings } from './settings.js';

/** The id of the setting that holds the providers. */
export const PROVIDERS_SETTING = 'providers';
/**
 * Each OpenID Connect provider's id with its issuer, kept when the provider is removed: the id's accounts
 * (`oidc:<id>:<sub>`) are that issuer's users, so the id comes back only with the same issuer.
 */
export const PROVIDER_ISSUERS_SETTING = 'provider-issuers';

/** The kinds of providers madAuth has. */
export const PROVIDER_KINDS = ['google', 'github', 'oidc'] as const;
export type ProviderKind = (typeof PROVIDER_KINDS)[number];
/** The kinds that exist once, with the kind as their id. */
export const BUILT_IN_KINDS = ['google', 'github'] as const;
export type BuiltInKind = (typeof BUILT_IN_KINDS)[number];

const isProviderKind = (value: unknown): value is ProviderKind => (PROVIDER_KINDS as readonly unknown[]).includes(value);
const isBuiltInKind = (value: unknown): value is BuiltInKind => (BUILT_IN_KINDS as readonly unknown[]).includes(value);

/** What a built-in provider's button says when the admin gives it no name. */
const DEFAULT_NAMES: Record<BuiltInKind, string> = { google: 'Google', github: 'GitHub' };

/** What an OpenID Connect provider's id looks like: it names its method, routes and accounts. */
const PROVIDER_ID = /^[a-z][a-z0-9-]{1,31}$/;
/** Ids an OpenID Connect provider can't have: madAuth's own methods and kinds, and `totp`, the authenticator app's id before 0.6. */
export const RESERVED_IDS = ['password', 'authenticator', 'email-link', 'passkey', 'sms', 'google', 'github', 'microsoft', 'totp'];

/** Whether `value` can be an OpenID Connect provider's id, and so its method's id in the settings. */
export const isProviderId = (value: unknown): value is string => typeof value === 'string' && PROVIDER_ID.test(value) && !RESERVED_IDS.includes(value);

/** The scopes every OpenID Connect sign-in asks for; an admin may add more. */
export const OIDC_SCOPES = ['openid', 'email', 'profile'];
const SCOPE = /^[\x21\x23-\x5B\x5D-\x7E]{1,128}$/;
const MAX_SCOPES = 20;

/** A provider as the setting holds it. Times are milliseconds since 1970. */
export interface StoredProvider {
  /** How the sign-in methods, routes and accounts name it: its kind, for the built-in kinds. */
  id: string;
  kind: ProviderKind;
  /** What the sign-in dialog's button says, e.g. "Google". */
  name: string;
  clientId: string;
  /** The client secret, encrypted by the key service; null without one (Google's One Tap needs none). */
  secret: string | null;
  createdAt: number;
  updatedAt: number;
  /** OpenID Connect: the issuer, exactly as the provider names it; its discovery document says where the rest is. */
  issuer?: string;
  /** OpenID Connect: the scopes asked for beyond {@link OIDC_SCOPES}. */
  scopes?: string[];
  /** OpenID Connect: whether its addresses count as verified without `email_verified` (the operator's own provider). */
  trustEmail?: boolean;
}

/**
 * What an admin sets of a provider: `clientSecret` in plain text, null to remove it, absent to keep it. Every
 * field is checked by {@link parseProviderFields}.
 */
export interface ProviderFields {
  name?: string;
  clientId?: string;
  clientSecret?: string | null;
  /** OpenID Connect only, and only when it is added. */
  issuer?: string;
  /** OpenID Connect only: the scopes beyond {@link OIDC_SCOPES}. */
  scopes?: string[];
  /** OpenID Connect only. */
  trustEmail?: boolean;
}

export type ProviderProblem = { error: 'invalid_provider'; message: string };

const MAX_NAME = 64;
const MAX_SECRET = 512;
const FIELDS = ['kind', 'id', 'name', 'clientId', 'clientSecret', 'issuer', 'scopes', 'trustEmail'];
const OIDC_FIELDS = ['issuer', 'scopes', 'trustEmail'];
const CLIENT_ID_PATTERNS: Record<ProviderKind, RegExp> = {
  google: /^[\w.-]+\.apps\.googleusercontent\.com$/,
  github: /^[A-Za-z0-9._-]{1,100}$/,
  oidc: /^[\x21-\x7E]{1,255}$/,
};

const problem = (message: string): ProviderProblem => ({ error: 'invalid_provider', message });

/**
 * The kind and id of a provider to add, from an admin's request: a built-in kind has its kind as its id, an
 * OpenID Connect provider the id the admin gives it.
 */
export function parseProviderKind(data: Record<string, unknown>): { kind: ProviderKind; id: string } | ProviderProblem {
  if (!isProviderKind(data.kind)) return problem(`kind must be one of ${PROVIDER_KINDS.join(', ')}.`);
  if (isBuiltInKind(data.kind)) {
    if (data.id !== undefined && data.id !== data.kind) return problem(`A ${DEFAULT_NAMES[data.kind]} provider has the id "${data.kind}".`);
    return { kind: data.kind, id: data.kind };
  }
  if (typeof data.id !== 'string' || !PROVIDER_ID.test(data.id)) {
    return problem('An OpenID Connect provider needs an id of 2 to 32 lower-case letters, digits and "-", starting with a letter, e.g. "gitlab".');
  }
  if (RESERVED_IDS.includes(data.id)) return problem(`"${data.id}" is one of madAuth's own methods: give the provider another id.`);
  return { kind: data.kind, id: data.id };
}

/** Scopes as an admin sends them, space-separated, without those every sign-in asks for; null if they are none. */
function parseScopes(value: unknown): string[] | null {
  if (typeof value !== 'string') return null;
  const scopes = [...new Set(value.split(' ').filter(Boolean))].filter((scope) => !OIDC_SCOPES.includes(scope));
  return scopes.length <= MAX_SCOPES && scopes.every((scope) => SCOPE.test(scope)) ? scopes : null;
}

/**
 * The fields an admin sends for a provider of `kind`, checked. `adding` asks for what a new provider needs:
 * a client ID, and GitHub's secret, without which its sign-in can't work.
 */
export function parseProviderFields(kind: ProviderKind, data: Record<string, unknown>, adding: boolean): ProviderFields | ProviderProblem {
  // A field madAuth doesn't have would otherwise be dropped without a word.
  const unknown = Object.keys(data).find((key) => !FIELDS.includes(key));
  if (unknown) return problem(`"${unknown}" is not a field of a provider: it has ${FIELDS.join(', ')}.`);
  const { name, clientId, clientSecret, issuer, scopes, trustEmail } = data;
  const oidc = kind === 'oidc';
  const notHere = OIDC_FIELDS.find((field) => !oidc && data[field] !== undefined);
  if (notHere) return problem(`"${notHere}" is a field of OpenID Connect providers only.`);
  if (name === undefined ? adding && oidc : typeof name !== 'string' || !name.trim() || name.trim().length > MAX_NAME) {
    return problem(`name must be text of 1 to ${MAX_NAME} characters: the sign-in button says "Continue with <name>".`);
  }
  if (clientId === undefined ? adding : typeof clientId !== 'string' || !CLIENT_ID_PATTERNS[kind].test(clientId)) {
    return problem(
      kind === 'google'
        ? 'clientId must be the client ID of a Google OAuth client, ending with ".apps.googleusercontent.com".'
        : kind === 'github'
          ? 'clientId must be the client ID of a GitHub OAuth App.'
          : 'clientId must be the client ID the provider gave madAuth: up to 255 characters, no spaces.',
    );
  }
  const secretGiven = clientSecret !== undefined && clientSecret !== null;
  if (secretGiven && (typeof clientSecret !== 'string' || !clientSecret || clientSecret.length > MAX_SECRET)) {
    return problem(`clientSecret must be text of 1 to ${MAX_SECRET} characters${kind === 'google' ? ', or null to remove it' : ''}.`);
  }
  // GitHub only has the redirect flow, in which the server exchanges the code with the secret; madAuth is a
  // confidential client of every OpenID Connect provider.
  if (kind !== 'google' && (clientSecret === null || (adding && !secretGiven))) return problem(`A ${kind === 'github' ? 'GitHub' : 'OpenID Connect'} provider needs its clientSecret.`);
  if (oidc && (issuer === undefined ? adding : !adding)) {
    return problem(adding ? 'An OpenID Connect provider needs its issuer, e.g. "https://gitlab.com".' : "An OpenID Connect provider's issuer can't change: its accounts belong to it. Add a new provider instead.");
  }
  if (issuer !== undefined && !isIssuer(issuer)) return problem('issuer must be an https URL without a query, e.g. "https://gitlab.com" (http only on localhost).');
  const extraScopes = scopes === undefined ? undefined : parseScopes(scopes);
  if (extraScopes === null) return problem(`scopes must be up to ${MAX_SCOPES} scope names, separated by spaces; ${OIDC_SCOPES.join(', ')} are always asked for.`);
  if (trustEmail !== undefined && typeof trustEmail !== 'boolean') return problem('trustEmail must be true or false.');
  return {
    ...(typeof name === 'string' ? { name: name.trim() } : {}),
    ...(typeof clientId === 'string' ? { clientId } : {}),
    ...(clientSecret === undefined ? {} : { clientSecret: clientSecret as string | null }),
    ...(typeof issuer === 'string' ? { issuer } : {}),
    ...(extraScopes === undefined ? {} : { scopes: extraScopes }),
    ...(trustEmail === undefined ? {} : { trustEmail }),
  };
}

/** The provider with the id `id` among `providers` (e.g. a request's, see `MethodsNow`), or undefined; a built-in kind's id is its kind. */
export const providerOf = (from: { providers: StoredProvider[] }, id: string): StoredProvider | undefined =>
  from.providers.find((provider) => provider.id === id);

/** Whether a stored value is a provider this version knows; others are left out. */
function isStoredProvider(value: unknown): value is StoredProvider {
  const p = value as StoredProvider;
  return (
    !!p &&
    typeof p === 'object' &&
    isProviderKind(p.kind) &&
    (isBuiltInKind(p.kind) ? p.id === p.kind : PROVIDER_ID.test(p.id) && !RESERVED_IDS.includes(p.id)) &&
    typeof p.name === 'string' &&
    typeof p.clientId === 'string' &&
    (p.secret === null || typeof p.secret === 'string') &&
    typeof p.createdAt === 'number' &&
    typeof p.updatedAt === 'number' &&
    (p.kind !== 'oidc' ||
      (isIssuer(p.issuer) && Array.isArray(p.scopes) && p.scopes.every((scope) => typeof scope === 'string') && typeof p.trustEmail === 'boolean'))
  );
}

export class Providers {
  private warned = false;

  constructor(
    private readonly settings: Settings,
    private readonly keys: KeyService,
  ) {}

  /** The providers in the store, in the order they were added. One in a form this version doesn't know is left out, with a warning once. */
  async list(): Promise<StoredProvider[]> {
    return this.parse(await this.settings.get<unknown>(PROVIDERS_SETTING));
  }

  private parse(value: unknown): StoredProvider[] {
    const stored = Array.isArray(value) ? value : [];
    const known = stored.filter(isStoredProvider);
    if ((known.length !== stored.length || (value !== undefined && !Array.isArray(value))) && !this.warned) {
      this.warned = true;
      console.warn('[madauth] Some stored sign-in providers are not in the form this version expects and are left out. An admin adds them again.');
    }
    return known;
  }

  /**
   * Adds a provider of `kind` under `id` (both from {@link parseProviderKind}), with `fields` checked by
   * {@link parseProviderFields}; refused if one with the id exists, or if the id of an OpenID Connect provider
   * was another issuer's (`issuer_bound`, with that issuer).
   */
  async add(
    kind: ProviderKind,
    id: string,
    fields: ProviderFields,
    by: string | null,
  ): Promise<{ provider: StoredProvider } | { error: 'provider_exists' } | { error: 'issuer_bound'; issuer: string }> {
    if (kind === 'oidc') {
      const bound = await this.bindIssuer(id, fields.issuer!, by);
      if (bound !== fields.issuer) return { error: 'issuer_bound', issuer: bound };
    }
    const now = Date.now();
    const provider: StoredProvider = {
      id,
      kind,
      name: fields.name ?? (isBuiltInKind(kind) ? DEFAULT_NAMES[kind] : id),
      clientId: fields.clientId!,
      secret: fields.clientSecret ? await this.encrypt(fields.clientSecret) : null,
      createdAt: now,
      updatedAt: now,
      ...(kind === 'oidc' ? { issuer: fields.issuer!, scopes: fields.scopes ?? [], trustEmail: fields.trustEmail ?? false } : {}),
    };
    const added = await this.settings.change<unknown>(
      PROVIDERS_SETTING,
      (current) => {
        const providers = this.parse(current);
        return providers.some((p) => p.id === provider.id) ? null : [...providers, provider];
      },
      by,
    );
    return added ? { provider } : { error: 'provider_exists' };
  }

  /** Changes the given fields of a provider (see {@link ProviderFields}). */
  async update(id: string, fields: ProviderFields, by: string | null): Promise<{ provider: StoredProvider } | { error: 'provider_not_found' }> {
    const secret = fields.clientSecret === undefined ? undefined : fields.clientSecret === null ? null : await this.encrypt(fields.clientSecret);
    let updated: StoredProvider | undefined;
    await this.settings.change<unknown>(
      PROVIDERS_SETTING,
      (current) => {
        const providers = this.parse(current);
        const found = providers.find((p) => p.id === id);
        // Set on every attempt: a retry may find the provider gone.
        updated = undefined;
        if (!found) return null;
        updated = {
          ...found,
          ...(fields.name === undefined ? {} : { name: fields.name }),
          ...(fields.clientId === undefined ? {} : { clientId: fields.clientId }),
          ...(secret === undefined ? {} : { secret }),
          ...(fields.scopes === undefined ? {} : { scopes: fields.scopes }),
          ...(fields.trustEmail === undefined ? {} : { trustEmail: fields.trustEmail }),
          updatedAt: Date.now(),
        };
        return providers.map((p) => (p.id === id ? updated! : p));
      },
      by,
    );
    return updated ? { provider: updated } : { error: 'provider_not_found' };
  }

  /**
   * Binds the id of an OpenID Connect provider to its issuer for good (see {@link PROVIDER_ISSUERS_SETTING}),
   * unless it is bound already. Resolves to the issuer the id is bound to.
   */
  private async bindIssuer(id: string, issuer: string, by: string | null): Promise<string> {
    let bound = issuer;
    await this.settings.change<unknown>(
      PROVIDER_ISSUERS_SETTING,
      (current) => {
        const known: Record<string, unknown> = current && typeof current === 'object' && !Array.isArray(current) ? (current as Record<string, unknown>) : {};
        const earlier = known[id];
        bound = typeof earlier === 'string' ? earlier : issuer;
        return typeof earlier === 'string' ? null : { ...known, [id]: issuer };
      },
      by,
    );
    return bound;
  }

  /**
   * Removes a provider. Its users' accounts stay, so adding it again brings their sign-ins back; an OpenID
   * Connect provider's id comes back only with its issuer.
   */
  async remove(id: string, by: string | null): Promise<{ provider: StoredProvider } | { error: 'provider_not_found' }> {
    let removed: StoredProvider | undefined;
    await this.settings.change<unknown>(
      PROVIDERS_SETTING,
      (current) => {
        const providers = this.parse(current);
        removed = providers.find((p) => p.id === id);
        return removed ? providers.filter((p) => p.id !== id) : null;
      },
      by,
    );
    return removed ? { provider: removed } : { error: 'provider_not_found' };
  }

  /**
   * The provider's client secret in plain text; null without one, or when no key of the key service opens it
   * any more (it was encrypted with a key that is gone: an admin sets it again).
   */
  async clientSecret(provider: StoredProvider): Promise<string | null> {
    if (!provider.secret) return null;
    const opened = await this.keys.decrypt('provider-secret', provider.secret);
    if (!opened) {
      console.error(`[madauth] The client secret of the provider "${provider.id}" can't be decrypted (was its key removed?): an admin sets it again.`);
      return null;
    }
    const plaintext = Buffer.from(opened.plaintext).toString();
    // Encrypted with an older key: moved to the newest, if nobody changed it meanwhile.
    if (!opened.current) await this.reencrypt(provider, plaintext);
    return plaintext;
  }

  private async encrypt(secret: string): Promise<string> {
    return this.keys.encrypt('provider-secret', Buffer.from(secret));
  }

  private async reencrypt(provider: StoredProvider, plaintext: string): Promise<void> {
    const secret = await this.encrypt(plaintext);
    await this.settings.change<unknown>(
      PROVIDERS_SETTING,
      (current) => {
        const providers = this.parse(current);
        return providers.some((p) => p.id === provider.id && p.secret === provider.secret)
          ? providers.map((p) => (p.id === provider.id ? { ...p, secret } : p))
          : null;
      },
      null,
    );
  }
}

/** Where a provider of madAuth before 0.7 came from: its environment variables. */
const VARIABLES: Record<BuiltInKind, string> = {
  google: 'GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET',
  github: 'GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET',
};

/**
 * Google and GitHub as madAuth before 0.7 had them, from environment variables (MadauthConfig's `google` and
 * `github`): each becomes a provider in the store once, when the store has none of its kind, and is ignored
 * when it has one, which admins manage. Either way the log says to remove the variables.
 */
export async function importProviders(
  providers: Providers,
  configured: { google?: { clientId: string; clientSecret?: string }; github?: { clientId: string; clientSecret: string } },
): Promise<void> {
  const stored = await providers.list();
  for (const kind of BUILT_IN_KINDS) {
    const from = configured[kind];
    if (!from) continue;
    const name = DEFAULT_NAMES[kind];
    if (stored.some((p) => p.id === kind)) {
      console.warn(`[madauth] ${VARIABLES[kind]} are ignored: the store has a ${name} provider, which admins manage (see "Providers" in docs/server.md). Remove the variables.`);
      continue;
    }
    // Another instance may import it at the same moment: then it is there, and nothing is to say.
    const added = await providers.add(kind, kind, { clientId: from.clientId, ...(from.clientSecret ? { clientSecret: from.clientSecret } : {}) }, null);
    if ('provider' in added) {
      console.warn(`[madauth] ${VARIABLES[kind]} are now the ${name} provider in the store, which admins manage (see "Providers" in docs/server.md): remove the variables.`);
    }
  }
}
