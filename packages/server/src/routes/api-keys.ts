// The signed-in user's API keys: the scopes a key can have, making, listing and revoking keys; and the check an
// app's backend asks madAuth for when a request comes with a key. See docs/api-keys.md.
import type { Context, Hono } from 'hono';
import type { AppContext } from '../app.js';
import {
  MAX_API_KEYS,
  MAX_API_KEY_NAME,
  apiKeyInfo,
  grantedScopes,
  mayHold,
  type ApiKeys,
  type ScopeCatalog,
  type StoredApiKey,
} from '../api-keys.js';
import { claimsFromJson } from '../claims.js';
import { bearerTokenOf } from '../user.js';
import { toMadauthUser, type StoredUser } from '../users.js';
import { body, error, noSession, recentUser } from './helpers.js';

/** The key a request comes with (`Authorization: Bearer …`) and its user, if the key works now; null otherwise. */
export async function keyCaller(c: Context, ctx: AppContext, apiKeys: ApiKeys): Promise<{ key: StoredApiKey; user: StoredUser } | null> {
  const token = bearerTokenOf(c.req.header('authorization'));
  const key = token ? await apiKeys.find(token) : null;
  const user = key ? await ctx.users.findById(key.userId) : null;
  return key && user ? { key, user } : null;
}

export const invalidApiKey = (c: Context): Response => error(c, 401, 'invalid_api_key', 'The API key is unknown, revoked or expired.');

export const apiKeyNotFound = (c: Context): Response => error(c, 404, 'api_key_not_found', 'There is no such API key.');

const invalid = (c: Context, message: string) => error(c, 400, 'invalid_options', message);

export function apiKeyRoutes(app: Hono, ctx: AppContext, apiKeys: ApiKeys, catalog: ScopeCatalog): void {
  // Every scope a key can have, with what it allows and the role its user needs: for people choosing the scopes
  // of a key, and as the API's documentation. Public: it says nothing about anyone.
  app.get('/auth/api-keys/scopes', async (c) => c.json({ scopes: (await catalog.all()).scopes }));

  app.get('/auth/api-keys', async (c) => {
    const signIn = await ctx.currentSignIn(c);
    if (!signIn) return noSession(c);
    return c.json({ apiKeys: (await apiKeys.list(signIn.stored.id)).map(apiKeyInfo) });
  });

  app.post('/auth/api-keys/create', async (c) => {
    // A key is a way in that outlives the session: only within ten minutes of signing in, like a sign-in method.
    const user = await recentUser(c, ctx);
    if (user instanceof Response) return user;
    const data = await body(c);
    const name = typeof data.name === 'string' ? data.name.trim() : '';
    if (!name || name.length > MAX_API_KEY_NAME) return invalid(c, `name must be 1 to ${MAX_API_KEY_NAME} characters.`);
    const requested = data.scopes;
    if (!Array.isArray(requested) || !requested.length || !requested.every((s) => typeof s === 'string') || new Set(requested).size !== requested.length) {
      return invalid(c, 'scopes must list different scope names, at least one. GET /auth/api-keys/scopes lists them.');
    }
    const expiresAt = data.expiresAt ?? null;
    if (expiresAt !== null && (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || expiresAt <= Date.now())) {
      return invalid(c, 'expiresAt must be a time in the future (milliseconds since 1970), or left out for a key that does not expire.');
    }
    const { scopes, complete } = await catalog.all();
    const unknown = requested.filter((name) => !scopes.some((scope) => scope.name === name));
    if (unknown.length && !complete) {
      return error(c, 503, 'temporarily_unavailable', "The app's scopes can not be read right now. Please try again later.");
    }
    if (unknown.length) return error(c, 400, 'invalid_scopes', `There are no such scopes: ${unknown.join(', ')}. GET /auth/api-keys/scopes lists them.`);
    // A key never does more than its user may: a scope that needs a role is only for users with it.
    const claims = claimsFromJson(user.claims);
    const denied = requested.filter((name) => !mayHold(scopes.find((scope) => scope.name === name)!, claims));
    if (denied.length) return error(c, 403, 'scope_not_allowed', `A key can only have scopes you hold yourself, so not: ${denied.join(', ')}.`);
    if ((await apiKeys.list(user.id)).length >= MAX_API_KEYS) {
      return error(c, 409, 'too_many_api_keys', `You have ${MAX_API_KEYS} API keys, the most one can have: revoke one first.`);
    }
    const { key, stored } = await apiKeys.create(user.id, { name, scopes: requested, expiresAt });
    const info = apiKeyInfo(stored);
    await ctx.emit('user.api_key_created', { user: toMadauthUser(user), apiKey: info });
    // The only time the key is shown: madAuth keeps its hash.
    return c.json({ key, apiKey: info });
  });

  // Revoking takes no recent sign-in: it only takes access away.
  app.post('/auth/api-keys/revoke', async (c) => {
    const signIn = await ctx.currentSignIn(c);
    if (!signIn) return noSession(c);
    const data = await body(c);
    const key = typeof data.id === 'string' ? await apiKeys.revoke(signIn.stored.id, data.id) : null;
    if (!key) return apiKeyNotFound(c);
    await ctx.emit('user.api_key_revoked', { user: toMadauthUser(signIn.stored), apiKey: { id: key.id, name: key.name } });
    return c.json({});
  });

  // For app backends (createApiKeyVerifier): whom a request's key acts for, with the scopes that count now. A
  // scope counts while the app lists it and the user holds its role, whatever it was when the key was made.
  app.post('/auth/api-keys/verify', async (c) => {
    const caller = await keyCaller(c, ctx, apiKeys);
    if (!caller) return invalidApiKey(c);
    const { scopes } = await catalog.all();
    await apiKeys.markUsed(caller.key);
    const granted = grantedScopes(caller.key, scopes, claimsFromJson(caller.user.claims));
    return c.json({ user: toMadauthUser(caller.user), apiKey: { id: caller.key.id, name: caller.key.name, scopes: granted } });
  });
}
