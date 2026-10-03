import type { IncomingMessage, ServerResponse } from 'node:http';
import { verifyWebhook } from '@madauth/server/webhook';

export interface ReceiverOptions {
  /** The same WEBHOOK_SECRET madAuth uses. */
  secret: string;
  /** If set, only these e-mail domains may sign up (answers signup.before). */
  allowedDomains?: string[];
  /** Where to print; the terminal by default. */
  log?: (line: string) => void;
}

interface Call {
  type: string;
  data: Record<string, any>;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => (body += chunk));
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

/** Handles madAuth's webhook calls: prints e-mails and events, and answers the sign-up check. */
export function createReceiver(options: ReceiverOptions) {
  const log = options.log ?? ((line: string) => console.log(line));

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const reply = (status: number, body?: unknown) => {
      res.writeHead(status, body === undefined ? {} : { 'Content-Type': 'application/json' });
      res.end(body === undefined ? undefined : JSON.stringify(body));
    };
    if (req.method !== 'POST') return reply(405);

    // Verify the raw body exactly as it arrived: re-serialized JSON would not match the signature.
    const body = await readBody(req);
    if (!verifyWebhook(options.secret, req.headers, body)) {
      log('[webhook] Rejected a call with a wrong signature. Do madAuth and this receiver use the same WEBHOOK_SECRET?');
      return reply(401);
    }
    const { type, data } = JSON.parse(body) as Call;

    if (type === 'email.verify' || type === 'email.reset') {
      const what = type === 'email.verify' ? 'Confirm your e-mail address' : 'Reset your password';
      log(`\n[webhook] E-mail to ${data.to}: ${what} (${data.site})`);
      log(`  Link: ${data.link}`);
      log(`  Code: ${String(data.code).slice(0, 3)} ${String(data.code).slice(3)}\n`);
      return reply(200);
    }
    if (type === 'email.already_registered') {
      log(`\n[webhook] E-mail to ${data.to}: You already have an account (${data.site})`);
      log(`  Sign in: ${data.link}\n`);
      return reply(200);
    }
    if (type === 'signup.before') {
      const domain = String(data.email).split('@').pop()!.toLowerCase();
      const allowed = !options.allowedDomains?.length || options.allowedDomains.includes(domain);
      log(`[webhook] Sign-up check for ${data.email}: ${allowed ? 'allowed' : 'refused'}`);
      return reply(200, allowed ? { allow: true } : { allow: false, message: `Only addresses at ${options.allowedDomains!.join(', ')} can sign up.` });
    }
    const detail = data.method ?? data.via ?? '';
    log(`[webhook] ${type}: ${data.user?.email ?? data.user?.id ?? ''}${detail ? ` (${detail})` : ''}`);
    return reply(204);
  };
}
