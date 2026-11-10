// `@madauth/server/webhook`: for webhook receivers written in JavaScript. No dependencies.
export {
  WEBHOOK_KEYS_PATH,
  WEBHOOK_TOLERANCE_SECONDS,
  WEBHOOK_TYPES,
  generateWebhookSecret,
  signWebhook,
  verifyWebhook,
  webhookKeys,
  type WebhookKeys,
  type WebhookType,
} from './webhooks.js';
