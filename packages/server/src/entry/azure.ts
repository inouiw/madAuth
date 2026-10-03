import { app, type HttpRequest } from '@azure/functions';
import type { Hono } from 'hono';
import { createApp } from '../app.js';
import { loadConfig, resolveEnv, type EntryOptions } from '../config.js';
import { handleAzureRequest } from './azure-handler.js';

/**
 * Registers madAuth as an Azure Functions v4 HTTP function that handles every route. Pass `store` to use your
 * own store adapter, and `env` to load settings from elsewhere, e.g. secrets from Key Vault.
 * Set `"routePrefix": ""` in host.json so the routes are served at /auth/... (see docs/server.md).
 */
export function register(options: EntryOptions = {}): void {
  const { env, ...overrides } = options;
  let appPromise: Promise<Hono> | undefined;
  app.http('madauth', {
    route: '{*path}',
    methods: ['GET', 'POST', 'OPTIONS'],
    authLevel: 'anonymous',
    handler: async (request: HttpRequest) => {
      appPromise ??= resolveEnv(env)
        .then((loaded) => loadConfig(loaded, overrides))
        .then(createApp);
      appPromise.catch(() => (appPromise = undefined));
      return handleAzureRequest(await appPromise, request);
    },
  });
}
