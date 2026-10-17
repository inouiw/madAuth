// The first setup. Providers are configured through the admin API, but a new deployment has no admin yet, and
// nobody could sign in to add the first provider. So while no admin exists, a setup token works on the provider and
// settings calls of the admin API; it closes for good once the first admin exists. See "First setup" in
// docs/server.md.
import { timingSafeEqual } from 'node:crypto';
import { INITIAL_ADMIN_SETTING } from './admins.js';
import { claimsFromJson, isAdmin } from './claims.js';
import type { MadauthConfig } from './config.js';
import type { KeyService } from './key-service.js';
import { Settings } from './settings.js';
import { Users } from './users.js';

/** The setting that records that the setup is closed: an admin exists. */
export const SETUP_SETTING = 'setup';

/** How a setup token starts, so a log line or a leaked token is recognisable. */
export const SETUP_TOKEN_PREFIX = 'madauth_setup_';

const LABEL = 'madauth setup token';
/** While the setup is open, how long an instance trusts its search for an admin among the users before it searches again. */
const RECHECK_MS = 60_000;
/** The users read at once while looking for an admin. */
const PAGE = 100;

/**
 * The deployment's setup token: the key service's keyed hash of a fixed label and the issuer. Every instance
 * computes the same one, and nothing is stored; it changes when the hash key is rotated.
 */
export async function setupToken(keys: KeyService, issuer: string): Promise<string> {
  const mac = await keys.mac(new TextEncoder().encode(`${LABEL} ${issuer}`));
  return SETUP_TOKEN_PREFIX + Buffer.from(mac).toString('base64url');
}

export class Setup {
  private closed = false;
  /** When this instance last searched the users and found no admin. */
  private searchedAt = 0;
  /** The token, computed once per instance: it changes only with the key service's hash key. */
  private token: Promise<string> | undefined;

  constructor(
    private readonly settings: Settings,
    private readonly users: Users,
    private readonly keys: KeyService,
    private readonly issuer: string,
  ) {}

  /**
   * Whether the setup is still open: no admin exists. A closed setup stays closed (the setting says so); one
   * that was never closed is closed here as soon as an admin is found, e.g. on a deployment from before 0.7.
   */
  async isOpen(): Promise<boolean> {
    if (this.closed) return false;
    // Read every time, so a setup another instance closed is closed here too.
    const [done, applied] = await Promise.all([this.settings.get<unknown>(SETUP_SETTING), this.settings.get<unknown>(INITIAL_ADMIN_SETTING)]);
    if (done !== undefined) {
      this.closed = true;
      return false;
    }
    // Searching the users is the costly part, so it is done at most once a minute.
    const searched = Date.now() - this.searchedAt < RECHECK_MS;
    if ((Array.isArray(applied) && applied.length) || (!searched && (await this.anyAdmin()))) {
      await this.close();
      return false;
    }
    if (!searched) this.searchedAt = Date.now();
    return true;
  }

  /** The deployment's setup token (see {@link setupToken}), computed once per instance. */
  async expectedToken(): Promise<string> {
    this.token ??= setupToken(this.keys, this.issuer).catch((e: unknown) => {
      this.token = undefined;
      throw e;
    });
    return this.token;
  }

  /** Closes the setup for good: an admin exists. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.settings.change<unknown>(SETUP_SETTING, (current) => current ?? { closedAt: Date.now() }, null);
  }

  /** Whether `token` is this deployment's setup token, while the setup is open. */
  async accepts(token: string): Promise<boolean> {
    const expected = Buffer.from(await this.expectedToken());
    const given = Buffer.from(token);
    return given.length === expected.length && timingSafeEqual(given, expected) && (await this.isOpen());
  }

  /** Whether any user has the role `admin`: read page by page, until one is found. */
  private async anyAdmin(): Promise<boolean> {
    let after: string | undefined;
    for (;;) {
      const page = await this.users.scan(after, PAGE);
      if (page.some((user) => isAdmin({ claims: claimsFromJson(user.claims) }))) return true;
      if (page.length < PAGE) return false;
      after = page.at(-1)!.id;
    }
  }
}

/**
 * Prints the setup token while the setup is open, for whoever starts the server: the entry points call it when
 * they load the configuration, so it is in the log of every start until the first admin exists.
 */
export async function announceSetup(setup: Setup, initialAdminEmail: string | undefined): Promise<void> {
  if (!(await setup.isOpen())) return;
  const admin = initialAdminEmail
    ? `then sign in as ${initialAdminEmail} (INITIAL_ADMIN_EMAIL), which makes you the first admin and ends the setup`
    : 'then set INITIAL_ADMIN_EMAIL to your address and sign in with it, which makes you the first admin and ends the setup';
  console.warn(
    `[madauth] No admin yet. This setup token configures the sign-in providers and settings until the first admin exists: ` +
      `send it as "Authorization: Bearer ${await setup.expectedToken()}" to POST /auth/admin/providers/* and /auth/admin/settings/*, ${admin}. ` +
      'See "First setup" in docs/server.md.',
  );
}

/**
 * {@link announceSetup} for a server's configuration, as the entry points load it. A failure is logged and
 * doesn't stop the server: the token is printed at the next start.
 */
export async function announceSetupOf(config: Pick<MadauthConfig, 'store' | 'keyService' | 'issuer' | 'initialAdminEmail'>): Promise<void> {
  const { store, keyService, issuer } = config;
  const setup = new Setup(new Settings(store), new Users(store, keyService), keyService, issuer);
  await announceSetup(setup, config.initialAdminEmail).catch((e: unknown) => {
    console.error(`[madauth] Could not check whether the setup is open: ${(e as Error).message}`);
  });
}
