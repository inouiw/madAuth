import { serve } from '@hono/node-server';
import { createApp } from '../app.js';
import { loadConfig } from '../config.js';

/** Starts the madAuth server on Node, listening on PORT (default 8787). Used by the Docker image. */
export async function start(env: Record<string, string | undefined> = process.env): Promise<void> {
  const config = await loadConfig(env);
  const port = Number(env.PORT ?? 8787);
  serve({ fetch: createApp(config).fetch, port });
  console.log(`madAuth server listening on port ${port} (issuer ${config.issuer})`);
}
