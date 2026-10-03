import { handle, type LambdaContext, type LambdaEvent } from 'hono/aws-lambda';
import { createApp } from '../app.js';
import { loadConfig, resolveEnv, type EntryOptions } from '../config.js';

export type LambdaHandler = (event: LambdaEvent, context: LambdaContext) => ReturnType<ReturnType<typeof handle>>;

/**
 * Creates an AWS Lambda handler (Function URL, API Gateway v1/v2 or ALB). It reads the configuration from
 * the function's environment variables on the first invocation. Pass `store` to use your own store
 * adapter, and `env` to load settings from elsewhere, e.g. secrets from the Parameter Store.
 */
export function createHandler(options: EntryOptions = {}): LambdaHandler {
  const { env, ...overrides } = options;
  let handlerPromise: Promise<ReturnType<typeof handle>> | undefined;
  return async (event, context) => {
    handlerPromise ??= resolveEnv(env)
      .then((loaded) => loadConfig(loaded, overrides))
      .then((config) => handle(createApp(config)));
    handlerPromise.catch(() => (handlerPromise = undefined));
    return (await handlerPromise)(event, context);
  };
}

/** The handler configured only by environment variables (`lambda.handler` in the standalone bundle). */
export const handler: LambdaHandler = createHandler();
