import { handle, type LambdaContext, type LambdaEvent } from 'hono/aws-lambda';
import { createApp } from '../app.js';
import { loadConfig } from '../config.js';

let handlerPromise: Promise<ReturnType<typeof handle>> | undefined;

/**
 * AWS Lambda handler (Function URL, API Gateway v1/v2 or ALB). Reads the configuration from the
 * function's environment variables on the first invocation.
 */
export async function handler(event: LambdaEvent, context: LambdaContext) {
  handlerPromise ??= loadConfig(process.env).then((config) => handle(createApp(config)));
  handlerPromise.catch(() => (handlerPromise = undefined));
  return (await handlerPromise)(event, context);
}
