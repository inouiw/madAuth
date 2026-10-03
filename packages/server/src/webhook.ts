// `@madauth/server/webhook`: for webhook receivers written in JavaScript. No dependencies.
export {
  WEBHOOK_TOLERANCE_SECONDS,
  WEBHOOK_TYPES,
  generateWebhookSecret,
  signWebhook,
  verifyWebhook,
  type WebhookType,
} from './webhooks.js';
