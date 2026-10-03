import { serve } from '@hono/node-server';
import { createApp } from '../app.js';
import { loadConfig, resolveEnv, type EntryOptions } from '../config.js';

export type StartOptions = EntryOptions;

/**
 * Starts the madAuth server on Node, listening on PORT (default 8787). Used by the Docker image.
 * Pass `store` to use your own store adapter, and `env` to load settings from elsewhere than `process.env`.
 */
export async function start(opts: StartOptions = {}): Promise<void> {
  const { env: source, ...overrides } = opts;
  const env = await resolveEnv(source);
  const config = await loadConfig(env, overrides);
  const port = Number(env.PORT?.trim() || 8787);
  serve({ fetch: createApp(config).fetch, port });
  console.log(`madAuth server listening on port ${port} (issuer ${config.issuer})`);
}
