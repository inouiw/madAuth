import { serve } from '@hono/node-server';
import { createApp } from '../app.js';
import { loadConfig, type ConfigOverrides } from '../config.js';

export interface StartOptions extends ConfigOverrides {
  /** Environment variables to read. Default: `process.env`. */
  env?: Record<string, string | undefined>;
}

/**
 * Starts the madAuth server on Node, listening on PORT (default 8787). Used by the Docker image.
 * Pass `store` or `mailer` to use your own store adapter or mail service.
 */
export async function start(opts: StartOptions = {}): Promise<void> {
  const { env = process.env, ...overrides } = opts;
  const config = await loadConfig(env, overrides);
  const port = Number(env.PORT?.trim() || 8787);
  serve({ fetch: createApp(config).fetch, port });
  console.log(`madAuth server listening on port ${port} (issuer ${config.issuer})`);
}
