import { ConfigError } from './config.js';
import { start } from './entry/node.js';

start().catch((e: unknown) => {
  console.error(e instanceof ConfigError ? e.message : e);
  process.exit(1);
});
