import { handle, type LambdaContext, type LambdaEvent } from 'hono/aws-lambda';
import { createApp } from '../app.js';
import { loadConfig, type ConfigOverrides } from '../config.js';

export type LambdaHandler = (event: LambdaEvent, context: LambdaContext) => ReturnType<ReturnType<typeof handle>>;

/**
 * Creates an AWS Lambda handler (Function URL, API Gateway v1/v2 or ALB). It reads the configuration from
 * the function's environment variables on the first invocation. Pass `store` or `mailer` to use your own
 * store adapter or mail service.
 */
export function createHandler(overrides: ConfigOverrides = {}): LambdaHandler {
  let handlerPromise: Promise<ReturnType<typeof handle>> | undefined;
  return async (event, context) => {
    handlerPromise ??= loadConfig(process.env, overrides).then((config) => handle(createApp(config)));
    handlerPromise.catch(() => (handlerPromise = undefined));
    return (await handlerPromise)(event, context);
  };
}

/** The handler configured only by environment variables (`lambda.handler` in the standalone bundle). */
export const handler: LambdaHandler = createHandler();
