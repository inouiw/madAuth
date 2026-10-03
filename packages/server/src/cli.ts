import { createInterface } from 'node:readline';
import { ConfigError, loadUserStoreConfig } from './config.js';
import { generateSigningKey } from './keys.js';
import { checkPasswordPolicy, hashPassword, isValidEmail, normalizeEmail } from './password.js';
import { createTablesSql, type SqlDialect } from './store/schema.js';
import { Users } from './users.js';
import { generateWebhookSecret } from './webhooks.js';

const usage = `Usage: npx @madauth/server <command>

Commands:
  generate-key                 Print a new private ES256 key to use as MADAUTH_SIGNING_KEY
  generate-webhook-secret      Print a new secret to use as WEBHOOK_SECRET (madAuth and your receiver)
  create-user <email>          Create a user with a password (asks for it), already verified.
                               Uses DATABASE_URL and PASSWORD_MIN_LENGTH from the environment.
  schema [--dialect <name>]    Print the SQL that creates madAuth's tables for a custom store adapter.
                               Dialects: postgres (default), mysql, sqlite`;

export interface CliIo {
  /** Asks for a secret without echoing it. */
  askSecret(question: string): Promise<string>;
}

const terminalIo: CliIo = {
  async askSecret(question) {
    process.stdout.write(question);
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      // Piped input (e.g. from a script): read the first line. Nothing is echoed.
      const rl = createInterface({ input: stdin, terminal: false });
      for await (const line of rl) {
        rl.close();
        process.stdout.write('\n');
        return line;
      }
      return '';
    }
    // A terminal: read key by key without echoing.
    stdin.setRawMode(true);
    stdin.setEncoding('utf8');
    stdin.resume();
    return new Promise((resolve, reject) => {
      let value = '';
      const finish = () => {
        stdin.off('data', onData);
        stdin.setRawMode(false);
        stdin.pause();
        process.stdout.write('\n');
      };
      const onData = (chunk: string) => {
        for (const ch of chunk) {
          if (ch === '\r' || ch === '\n') {
            finish();
            resolve(value);
            return;
          }
          if (ch === '\u0003') {
            finish();
            reject(new Error('Cancelled.'));
            return;
          }
          value = ch === '\u007f' || ch === '\b' ? [...value].slice(0, -1).join('') : value + ch;
        }
      };
      stdin.on('data', onData);
    });
  },
};

/** Runs a CLI command and returns what it prints. */
export async function runCli(
  args: string[],
  io: CliIo = terminalIo,
  env: Record<string, string | undefined> = process.env,
): Promise<{ output: string; exitCode: number }> {
  const [command, ...rest] = args;
  try {
    if (command === 'generate-key') {
      return { output: JSON.stringify(await generateSigningKey()), exitCode: 0 };
    }
    if (command === 'generate-webhook-secret') {
      return { output: generateWebhookSecret(), exitCode: 0 };
    }
    if (command === 'schema') {
      const i = rest.indexOf('--dialect');
      const dialect = (i >= 0 ? rest[i + 1] : 'postgres') as SqlDialect;
      if (!['postgres', 'mysql', 'sqlite'].includes(dialect)) return { output: usage, exitCode: 1 };
      return { output: createTablesSql(dialect), exitCode: 0 };
    }
    if (command === 'create-user') {
      return await createUser(rest[0], io, env);
    }
  } catch (e) {
    return { output: e instanceof ConfigError ? e.message : String(e), exitCode: 1 };
  }
  return { output: usage, exitCode: command ? 1 : 0 };
}

async function createUser(email: string | undefined, io: CliIo, env: Record<string, string | undefined>) {
  if (!isValidEmail(email)) return { output: `"${email ?? ''}" is not an e-mail address.\n\n${usage}`, exitCode: 1 };
  const { store, minLength } = await loadUserStoreConfig(env);
  const password = await io.askSecret(`Password for ${email}: `);
  const policy = checkPasswordPolicy(password, minLength);
  if (policy) return { output: policy, exitCode: 1 };
  const users = new Users(store);
  const user = await users.createPasswordUser({
    email: email.trim(),
    emailNormalized: normalizeEmail(email),
    name: null,
    passwordHash: await hashPassword(password),
    emailVerified: true,
  });
  if (!user) return { output: `A user with the e-mail address ${email} already exists.`, exitCode: 1 };
  return { output: `Created user ${user.id} (${user.email}).`, exitCode: 0 };
}
