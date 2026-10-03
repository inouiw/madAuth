// Development receiver for madAuth's webhooks: prints the e-mails (with their links and codes) instead of
// sending them. Reads WEBHOOK_URL and WEBHOOK_SECRET from packages/server/.env and listens on WEBHOOK_URL's port.
import { createServer } from 'node:http';
import { createReceiver } from './receiver.js';

const url = process.env.WEBHOOK_URL;
const secret = process.env.WEBHOOK_SECRET;
if (!url || !secret) {
  console.error(
    'Set WEBHOOK_URL (e.g. http://localhost:8790/webhook) and WEBHOOK_SECRET in packages/server/.env.\n' +
      'Generate a secret with: npm run cli -w packages/server -- generate-webhook-secret',
  );
  process.exit(1);
}

const port = Number(new URL(url).port || 80);
const allowedDomains = process.env.ALLOWED_EMAIL_DOMAINS?.split(',').map((d) => d.trim().toLowerCase()).filter(Boolean);
const server = createServer(createReceiver({ secret, allowedDomains }));
server.on('error', (e) => {
  console.error(`Could not listen on port ${port}: ${e.message}`);
  process.exit(1);
});
server.listen(port, () => console.log(`madAuth webhook receiver listening on ${url}; e-mails appear here.`));
