// Sign-in providers, which admins configure while the server runs: Google and GitHub. They are kept in the store
// as one setting, `providers`, like the sign-in methods; each client secret is encrypted by the key service, so the
// store alone doesn't reveal it. See "Providers" in docs/server.md.
import type { KeyService } from './key-service.js';
import type { Settings } from './settings.js';

/** The id of the setting that holds the providers. */
export const PROVIDERS_SETTING = 'providers';

/** The kinds of providers madAuth has. Each exists once, with its kind as its id. */
export const PROVIDER_KINDS = ['google', 'github'] as const;
export type ProviderKind = (typeof PROVIDER_KINDS)[number];

const isProviderKind = (value: unknown): value is ProviderKind => (PROVIDER_KINDS as readonly unknown[]).includes(value);

/** What a provider's button says when the admin gives it no name. */
const DEFAULT_NAMES: Record<ProviderKind, string> = { google: 'Google', github: 'GitHub' };

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
}

/**
 * What an admin sets of a provider: `clientSecret` in plain text, null to remove it, absent to keep it. Every
 * field is checked by {@link parseProviderFields}.
 */
export interface ProviderFields {
  name?: string;
  clientId?: string;
  clientSecret?: string | null;
}

export type ProviderProblem = { error: 'invalid_provider'; message: string };

const MAX_NAME = 64;
const MAX_SECRET = 512;
const FIELDS = ['kind', 'id', 'name', 'clientId', 'clientSecret'];
const GOOGLE_CLIENT_ID = /^[\w.-]+\.apps\.googleusercontent\.com$/;
const GITHUB_CLIENT_ID = /^[A-Za-z0-9._-]{1,100}$/;

const problem = (message: string): ProviderProblem => ({ error: 'invalid_provider', message });

/** The kind of a provider to add, from an admin's request; its id must be the kind. */
export function parseProviderKind(data: Record<string, unknown>): ProviderKind | ProviderProblem {
  if (!isProviderKind(data.kind)) return problem(`kind must be one of ${PROVIDER_KINDS.join(', ')}.`);
  if (data.id !== undefined && data.id !== data.kind) return problem(`A ${DEFAULT_NAMES[data.kind]} provider has the id "${data.kind}".`);
  return data.kind;
}

/**
 * The fields an admin sends for a provider of `kind`, checked. `adding` asks for what a new provider needs:
 * a client ID, and GitHub's secret, without which its sign-in can't work.
 */
export function parseProviderFields(kind: ProviderKind, data: Record<string, unknown>, adding: boolean): ProviderFields | ProviderProblem {
  // A field madAuth doesn't have would otherwise be dropped without a word.
  const unknown = Object.keys(data).find((key) => !FIELDS.includes(key));
  if (unknown) return problem(`"${unknown}" is not a field of a provider: it has ${FIELDS.join(', ')}.`);
  const { name, clientId, clientSecret } = data;
  if (name !== undefined && (typeof name !== 'string' || !name.trim() || name.trim().length > MAX_NAME)) {
    return problem(`name must be text of 1 to ${MAX_NAME} characters.`);
  }
  const clientIdPattern = kind === 'google' ? GOOGLE_CLIENT_ID : GITHUB_CLIENT_ID;
  if (clientId === undefined ? adding : typeof clientId !== 'string' || !clientIdPattern.test(clientId)) {
    return problem(
      kind === 'google'
        ? 'clientId must be the client ID of a Google OAuth client, ending with ".apps.googleusercontent.com".'
        : 'clientId must be the client ID of a GitHub OAuth App.',
    );
  }
  const secretGiven = clientSecret !== undefined && clientSecret !== null;
  if (secretGiven && (typeof clientSecret !== 'string' || !clientSecret || clientSecret.length > MAX_SECRET)) {
    return problem(`clientSecret must be text of 1 to ${MAX_SECRET} characters${kind === 'google' ? ', or null to remove it' : ''}.`);
  }
  // GitHub only has the redirect flow, in which the server exchanges the code with the secret.
  if (kind === 'github' && (clientSecret === null || (adding && !secretGiven))) return problem('A GitHub provider needs its clientSecret.');
  return {
    ...(name === undefined ? {} : { name: name.trim() }),
    ...(typeof clientId === 'string' ? { clientId } : {}),
    ...(clientSecret === undefined ? {} : { clientSecret: clientSecret as string | null }),
  };
}

/** The provider of `kind` among `providers` (e.g. a request's, see `MethodsNow`), or undefined. */
export const providerOf = (from: { providers: StoredProvider[] }, kind: ProviderKind): StoredProvider | undefined =>
  from.providers.find((provider) => provider.id === kind);

/** Whether a stored value is a provider this version knows; others are left out. */
function isStoredProvider(value: unknown): value is StoredProvider {
  const p = value as StoredProvider;
  return (
    !!p &&
    typeof p === 'object' &&
    isProviderKind(p.kind) &&
    p.id === p.kind &&
    typeof p.name === 'string' &&
    typeof p.clientId === 'string' &&
    (p.secret === null || typeof p.secret === 'string') &&
    typeof p.createdAt === 'number' &&
    typeof p.updatedAt === 'number'
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

  /** Adds a provider of `kind`, with `fields` checked by {@link parseProviderFields}; refused if it exists. */
  async add(kind: ProviderKind, fields: ProviderFields, by: string | null): Promise<{ provider: StoredProvider } | { error: 'provider_exists' }> {
    const now = Date.now();
    const provider: StoredProvider = {
      id: kind,
      kind,
      name: fields.name ?? DEFAULT_NAMES[kind],
      clientId: fields.clientId!,
      secret: fields.clientSecret ? await this.encrypt(fields.clientSecret) : null,
      createdAt: now,
      updatedAt: now,
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
          updatedAt: Date.now(),
        };
        return providers.map((p) => (p.id === id ? updated! : p));
      },
      by,
    );
    return updated ? { provider: updated } : { error: 'provider_not_found' };
  }

  /** Removes a provider. Its users' accounts stay, so adding it again brings their sign-ins back. */
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
const VARIABLES: Record<ProviderKind, string> = {
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
  for (const kind of PROVIDER_KINDS) {
    const from = configured[kind];
    if (!from) continue;
    const name = DEFAULT_NAMES[kind];
    if (stored.some((p) => p.id === kind)) {
      console.warn(`[madauth] ${VARIABLES[kind]} are ignored: the store has a ${name} provider, which admins manage (see "Providers" in docs/server.md). Remove the variables.`);
      continue;
    }
    // Another instance may import it at the same moment: then it is there, and nothing is to say.
    const added = await providers.add(kind, { clientId: from.clientId, ...(from.clientSecret ? { clientSecret: from.clientSecret } : {}) }, null);
    if ('provider' in added) {
      console.warn(`[madauth] ${VARIABLES[kind]} are now the ${name} provider in the store, which admins manage (see "Providers" in docs/server.md): remove the variables.`);
    }
  }
}
