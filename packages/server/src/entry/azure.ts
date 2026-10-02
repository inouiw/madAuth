import { app, type HttpRequest } from '@azure/functions';
import type { Hono } from 'hono';
import { createApp } from '../app.js';
import { loadConfig } from '../config.js';
import { handleAzureRequest } from './azure-handler.js';

let appPromise: Promise<Hono> | undefined;

/**
 * Registers madAuth as an Azure Functions v4 HTTP function that handles every route.
 * Set `"routePrefix": ""` in host.json so the routes are served at /auth/... (see docs/server.md).
 */
app.http('madauth', {
  route: '{*path}',
  methods: ['GET', 'POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request: HttpRequest) => {
    appPromise ??= loadConfig(process.env).then(createApp);
    appPromise.catch(() => (appPromise = undefined));
    return handleAzureRequest(await appPromise, request);
  },
});
