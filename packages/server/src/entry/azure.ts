import { app, type HttpRequest } from '@azure/functions';
import type { Hono } from 'hono';
import { createApp } from '../app.js';
import { loadConfig, type ConfigOverrides } from '../config.js';
import { handleAzureRequest } from './azure-handler.js';

/**
 * Registers madAuth as an Azure Functions v4 HTTP function that handles every route. Pass `store` or
 * `mailer` to use your own store adapter or mail service.
 * Set `"routePrefix": ""` in host.json so the routes are served at /auth/... (see docs/server.md).
 */
export function register(overrides: ConfigOverrides = {}): void {
  let appPromise: Promise<Hono> | undefined;
  app.http('madauth', {
    route: '{*path}',
    methods: ['GET', 'POST', 'OPTIONS'],
    authLevel: 'anonymous',
    handler: async (request: HttpRequest) => {
      appPromise ??= loadConfig(process.env, overrides).then(createApp);
      appPromise.catch(() => (appPromise = undefined));
      return handleAzureRequest(await appPromise, request);
    },
  });
}
