import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createInterface, type Interface } from 'node:readline';
import { parseArgs, parseEnv } from 'node:util';
import { loadConfig, loadStore, loadUserStoreConfig } from './config.js';
import { generateSigningKey } from './keys.js';
import { checkPasswordPolicy, hashPassword, isValidEmail, normalizeEmail } from './password.js';
import { claimsFromJson, parseClaims, parseRoles, type Claims } from './claims.js';
import { SIGN_IN_METHODS, Settings, anyOn, isOn, type MethodSettings, type SignInMethod } from './settings.js';
import { madauthSchema, type StoreAdapter } from './store/schema.js';
import { createTablesSql, upgradeTablesSql, type SqlDialect } from './store/sql.js';
import { passwordAccountKey, Users } from './users.js';
import { DEV_WEBHOOK_RECEIVER_URL, generateWebhookSecret } from './webhooks.js';

/** The server's default port, which `init` writes as PORT. */
const PORT = 8787;

const usage = `Usage: npx @madauth/server <command> [--env-file <path>]

Commands:
  init                         Ask a few questions, write the configuration to .env and print the next steps.
                               An answer given as an option is not asked for: --app-url <url>,
                               --google-client-id <id>, --google-client-secret <secret>, --password or
                               --no-password, --database <url>, --webhook-url <url>. --yes takes the
                               default for the rest. --out <path> writes another file, --force overwrites.
  start                        Start the server on PORT (default ${PORT})
  generate-key                 Print a new private ES256 key to use as MADAUTH_SIGNING_KEY
  generate-webhook-secret      Print a new secret to use as WEBHOOK_SECRET (madAuth and your receiver)
  create-user <email>          Create a user with a password (asks for it), already verified.
                               Uses DATABASE_URL and PASSWORD_MIN_LENGTH from the environment.
  set-roles <email> [role...]  Set the roles of a user (the claim "roles"), e.g. to make the first admin:
                               set-roles you@example.com admin. Without roles, removes them all.
                               The user must exist: signed in once, or created with create-user.
  get-roles <email>            Print the roles of a user.
  set-claims <email> <json>    Replace the claims of a user, e.g. '{"roles":["admin"],"plan":"pro"}'.
  get-claims <email>           Print the claims of a user as JSON.
  set-methods [method...]      Switch sign-in methods on and off while the server runs: the listed ones
                               (google, password) are on, the others off. Without any, all are on.
  get-methods                  Print which sign-in methods are switched on.
                               The claims commands use DATABASE_URL from the environment; the methods
                               commands need the server's whole configuration (e.g. --env-file .env).
  schema [--dialect <name>] [--from <version>]
                               Print the SQL that creates madAuth's tables for a custom store adapter.
                               Dialects: postgres (default), mysql, sqlite. With --from, print only the
                               changes since that schema version, to upgrade existing tables.

Options:
  --env-file <path>            Read environment variables from this file, for any command. A variable
                               that is already set in the environment wins.`;

export interface CliIo {
  /** Asks a question; an empty answer means `defaultValue`. */
  ask(question: string, defaultValue?: string): Promise<string>;
  /** Asks for a secret without echoing it. */
  askSecret(question: string): Promise<string>;
}

type Env = Record<string, string | undefined>;
type CliResult = { output: string; exitCode: number };

/**
 * Piped input (e.g. from a script) is read by one reader for all questions: a reader per question would
 * swallow the lines after its own. It is paused between questions, so an open pipe does not keep the
 * process running.
 */
let piped: { reader: Interface; lines: AsyncIterator<string>; ended: boolean } | undefined;

async function readPipedLine(): Promise<string> {
  if (!piped) {
    const reader = createInterface({ input: process.stdin, terminal: false });
    const input = (piped = { reader, lines: reader[Symbol.asyncIterator](), ended: false as boolean });
    reader.once('close', () => (input.ended = true));
  }
  // A reader that has reached the end of the input is closed, and can be neither resumed nor paused.
  if (!piped.ended) piped.reader.resume();
  const next = await piped.lines.next();
  if (!piped.ended) piped.reader.pause();
  return next.done ? '' : next.value;
}

const terminalIo: CliIo = {
  async ask(question, defaultValue = '') {
    const prompt = `${question}${defaultValue ? ` [${defaultValue}]` : ''}: `;
    if (!process.stdin.isTTY) {
      process.stdout.write(prompt);
      const line = await readPipedLine();
      process.stdout.write('\n');
      return line.trim() || defaultValue;
    }
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve, reject) => {
      let answered = false;
      // Ctrl+C. Without a listener readline only pauses, and the question would stay open.
      rl.on('SIGINT', () => rl.close());
      rl.on('close', () => {
        if (answered) return;
        process.stdout.write('\n');
        reject(new Error('Cancelled.'));
      });
      rl.question(prompt, (answer) => {
        answered = true;
        rl.close();
        resolve(answer.trim() || defaultValue);
      });
    });
  },
  async askSecret(question) {
    process.stdout.write(question);
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      // Piped input (e.g. from a script): read the next line. Nothing is echoed.
      const line = await readPipedLine();
      process.stdout.write('\n');
      return line;
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

/** Options may come before or after the command, as `--name value` or `--name=value`. */
function parseCliArgs(args: string[]) {
  return parseArgs({
    args,
    options: {
      'env-file': { type: 'string' },
      dialect: { type: 'string' },
      // schema: print only the changes since this schema version.
      from: { type: 'string' },
      // init: an answer for each question, then where and how to write the file.
      'app-url': { type: 'string' },
      'google-client-id': { type: 'string' },
      'google-client-secret': { type: 'string' },
      password: { type: 'boolean' },
      database: { type: 'string' },
      'webhook-url': { type: 'string' },
      yes: { type: 'boolean' },
      out: { type: 'string' },
      force: { type: 'boolean' },
    },
    allowPositionals: true,
    // --no-password
    allowNegative: true,
  });
}

type CliOptions = ReturnType<typeof parseCliArgs>['values'];

/** Runs a CLI command and returns what it prints. */
export async function runCli(args: string[], io: CliIo = terminalIo, env: Env = process.env): Promise<CliResult> {
  let parsed: ReturnType<typeof parseCliArgs>;
  try {
    parsed = parseCliArgs(args);
  } catch (e) {
    // An unknown option, or one without its value.
    return { output: `${(e as Error).message}\n\n${usage}`, exitCode: 1 };
  }
  const { values: options, positionals } = parsed;
  const [command, ...rest] = positionals;
  // Few commands take arguments; anywhere else one is likely a mistyped option, e.g. `init .env.local`.
  const argumentLimits: Record<string, number> = { 'set-roles': Infinity, 'set-methods': Infinity, 'set-claims': 2, 'create-user': 1, 'get-roles': 1, 'get-claims': 1 };
  const maxArguments = command ? (argumentLimits[command] ?? 0) : 0;
  if (rest.length > maxArguments) {
    return { output: `Unexpected argument: ${rest.at(-1)}\n\n${usage}`, exitCode: 1 };
  }
  try {
    const envFile = options['env-file'];
    if (envFile !== undefined) {
      if (!existsSync(envFile)) return { output: `--env-file: ${envFile} does not exist.`, exitCode: 1 };
      env = withEnvFile(envFile, env);
    }
    if (command === 'init') {
      return await init(options, io);
    }
    if (command === 'start') {
      // Imported here, so the other commands do not load the HTTP server.
      const { start } = await import('./entry/node.js');
      await start({ env });
      // Nothing to print: the server has said where it listens, and it keeps the process running.
      return { output: '', exitCode: 0 };
    }
    if (command === 'generate-key') {
      return { output: JSON.stringify(await generateSigningKey()), exitCode: 0 };
    }
    if (command === 'generate-webhook-secret') {
      return { output: generateWebhookSecret(), exitCode: 0 };
    }
    if (command === 'schema') {
      const dialect = (options.dialect ?? 'postgres') as SqlDialect;
      if (!['postgres', 'mysql', 'sqlite'].includes(dialect)) return { output: usage, exitCode: 1 };
      if (options.from === undefined) return { output: createTablesSql(dialect), exitCode: 0 };
      const from = Number(options.from);
      if (!Number.isInteger(from) || from < 1 || from > madauthSchema.version) return { output: usage, exitCode: 1 };
      return { output: upgradeTablesSql(dialect, from) || '-- The tables are up to date.', exitCode: 0 };
    }
    if (command === 'create-user') {
      return await createUser(rest[0], io, env);
    }
    if (command === 'set-roles' || command === 'get-roles' || command === 'set-claims' || command === 'get-claims') {
      return await claims(command, rest[0], rest.slice(1), env);
    }
    if (command === 'set-methods' || command === 'get-methods') {
      return await methods(command, rest, env);
    }
  } catch (e) {
    return { output: e instanceof Error ? e.message : String(e), exitCode: 1 };
  }
  return { output: usage, exitCode: command ? 1 : 0 };
}

/** The variables of an env file, under those already set in the environment: like Node's own --env-file. */
function withEnvFile(path: string, env: Env): Env {
  const merged: Env = parseEnv(readFileSync(path, 'utf8'));
  for (const [name, value] of Object.entries(env)) {
    if (value !== undefined) merged[name] = value;
  }
  return merged;
}

/** The origin of an http(s) URL, or undefined. */
function httpOrigin(value: string): string | undefined {
  const url = URL.canParse(value) ? new URL(value) : undefined;
  return url && (url.protocol === 'http:' || url.protocol === 'https:') ? url.origin : undefined;
}

/** Asks for the settings, writes them to an env file with new secrets, and says what to do next. */
async function init(options: CliOptions, io: CliIo): Promise<CliResult> {
  const fail = (output: string) => ({ output, exitCode: 1 });
  const file = options.out ?? '.env';
  // Checked before the questions, so nobody answers them for nothing.
  if (existsSync(file) && !options.force) {
    return fail(`${file} already exists. Use --force to overwrite it, or --out <path> to write another file.`);
  }
  // An answer given as an option is not asked for; --yes takes the default for the rest.
  const answer = async (given: string | undefined, question: string, defaultValue = '') =>
    (given ?? (options.yes ? defaultValue : await io.ask(question, defaultValue))).trim();

  // madAuth is served on the app's own origin, through a proxy, so its cookies are first-party.
  const appUrl = await answer(options['app-url'], 'App URL, the address your users open', 'http://localhost:5173');
  const origin = httpOrigin(appUrl);
  if (!origin) return fail(`The app URL must be an http(s) URL, e.g. https://app.example.com, but is "${appUrl}".`);

  const clientId = await answer(options['google-client-id'], 'Google client ID (empty: no Google sign-in)');
  const askClientSecret = () => (options.yes ? '' : io.askSecret('Google client secret (empty: no redirect flow): '));
  if (!clientId && options['google-client-secret'] !== undefined) {
    return fail('--google-client-secret needs a Google client ID.');
  }
  const clientSecret = clientId ? (options['google-client-secret'] ?? (await askClientSecret())).trim() : '';

  const password = options.password ?? /^y/i.test(await answer(undefined, 'E-mail & password sign-in? (yes/no)', 'yes'));
  if (!password && options['webhook-url'] !== undefined) {
    return fail('--webhook-url is for e-mail & password sign-in, which is turned off.');
  }
  if (!clientId && !password) {
    return fail('No sign-in method is chosen. Give a Google client ID, turn on e-mail & password sign-in, or both.');
  }
  // Every user is stored, whichever way they sign in.
  const database = await answer(options.database, 'Database for the users', 'sqlite:./madauth.db');
  if (!/^(sqlite|dynamodb):./.test(database)) {
    return fail(`The database must be sqlite:<path> or dynamodb:<table> but is "${database}".`);
  }
  const webhookUrl = password
    ? await answer(options['webhook-url'], 'Webhook URL, where madAuth hands over its e-mails', 'http://localhost:8790/webhook')
    : '';

  // The comments have no quotes in them: some env file parsers trip over those.
  const variable = (name: string, value: string, comment: string) => `# ${comment}\n${name}=${value}\n`;
  const content = [
    '# Configuration of the madAuth server, written by npx @madauth/server init. It holds secrets: never commit it.\n',
    '# All settings: https://github.com/inouiw/madAuth/blob/main/docs/server.md#configuration\n\n',
    variable(
      'MADAUTH_ISSUER',
      origin,
      'Public address of the madAuth server: the origin of your app, which proxies /auth and /.well-known to it.',
    ),
    // In single quotes, as JSON is full of double quotes. Node's parser removes them; Docker's --env-file
    // keeps them, and the server removes them then.
    variable(
      'MADAUTH_SIGNING_KEY',
      `'${JSON.stringify(await generateSigningKey())}'`,
      'Private key that signs the sessions. Keep it secret, and use the same one on every instance.',
    ),
    variable('ALLOWED_ORIGINS', origin, 'Origins of your apps, comma-separated. Only these may call the server.'),
    clientId && variable('GOOGLE_CLIENT_ID', clientId, 'Google sign-in: your OAuth client ID, of the type Web application.'),
    clientSecret && variable('GOOGLE_CLIENT_SECRET', clientSecret, 'Client secret of the same client. It enables the redirect flow.'),
    variable('DATABASE_URL', database, 'Where the users are stored, whichever way they sign in.'),
    password && variable('WEBHOOK_URL', webhookUrl, 'Your webhook receiver. madAuth hands its e-mails to it.'),
    password && variable('WEBHOOK_SECRET', generateWebhookSecret(), 'Signs every webhook call. Your receiver needs the same one.'),
    password &&
      variable(
        'WEBHOOK_EVENTS',
        'email.verify,email.reset,email.already_registered,email.no_password',
        'The types your webhook receiver handles; only these are sent. Add e.g. signup.before or user.created.',
      ),
    variable('PORT', String(PORT), 'Port the server listens on.'),
  ]
    .filter(Boolean)
    .join('');

  // The server's own checks, on the file as it will be read, so that it is ready to use. The database is
  // not opened here: a placeholder stands in for DATABASE_URL.
  await loadConfig({ ...parseEnv(content), DATABASE_URL: undefined }, { store: {} as StoreAdapter });

  // Always a new file, readable by its owner only: it holds secrets, and an overwritten file would keep its mode.
  if (options.force) rmSync(file, { force: true });
  writeFileSync(file, content, { mode: 0o600, flag: 'wx' });

  const google = clientSecret ? 'GoogleRedirect' : clientId ? 'GoogleFedcm' : undefined;
  return { output: `Wrote ${file}.\n\nNext steps:\n\n${nextSteps(file, origin, google, password)}`, exitCode: 0 };
}

/** What to do after `init`, for the chosen sign-in methods: numbered steps with commands and snippets to copy. */
function nextSteps(file: string, origin: string, google: 'GoogleFedcm' | 'GoogleRedirect' | undefined, password: boolean): string {
  const server = `http://localhost:${PORT}`;
  // Quoted when needed, so the command can be pasted as it is.
  const envFile = /[^\w./-]/.test(file) ? `'${file.replaceAll("'", `'\\''`)}'` : file;
  const providers = [google, password && 'Password'].filter(Boolean);
  // For development, Google wants http://localhost next to the origin with its port.
  const googleOrigins = new Set([origin, ...(new URL(origin).hostname === 'localhost' ? ['http://localhost'] : [])]);
  const steps = [
    ['Start the madAuth server:', '', `  npx @madauth/server start --env-file ${envFile}`],
    password && [
      'madAuth hands its e-mails to your webhook receiver. For development, start the development receiver,',
      `which prints them, with the same WEBHOOK_URL and WEBHOOK_SECRET as in ${file}:`,
      '',
      `  ${DEV_WEBHOOK_RECEIVER_URL}`,
    ],
    [
      'Proxy /auth and /.well-known from your app to the server, so that its cookies are first-party.',
      'With Vite, in vite.config.ts:',
      '',
      '  server: {',
      '    proxy: {',
      `      '/auth': '${server}',`,
      `      '/.well-known': '${server}',`,
      '    },',
      '  },',
    ],
    [
      'Sign users in from your app (npm install @madauth/web):',
      '',
      `  import { Madauth, ${providers.join(', ')} } from '@madauth/web';`,
      '',
      `  Madauth.initialize({ providers: [${providers.map((provider) => `new ${provider}()`).join(', ')}] });`,
      '  Madauth.onAuthStateChanged((user) => console.log(user)); // the user, or null',
      '  signInButton.onclick = () => Madauth.signIn();',
    ],
    google && [
      'In the Google Cloud Console (https://console.cloud.google.com/apis/credentials), add to your OAuth client:',
      '',
      `  Authorized JavaScript origins: ${[...googleOrigins].join(' and ')}`,
      ...(google === 'GoogleRedirect' ? [`  Authorized redirect URIs: ${origin}/auth/google/callback`] : []),
    ],
    [
      `Never commit ${file}: it holds the signing key and your secrets. Production needs an https app URL`,
      'and a signing key of its own: run init again for it.',
    ],
  ].filter((step) => !!step);
  // The lines after the first are indented under the step's text.
  return steps.map((lines, i) => `${i + 1}. ${lines.map((line, j) => (j && line ? `   ${line}` : line)).join('\n')}`).join('\n\n');
}

async function claims(
  command: 'set-roles' | 'get-roles' | 'set-claims' | 'get-claims',
  email: string | undefined,
  args: string[],
  env: Env,
) {
  if (!isValidEmail(email)) return { output: `"${email ?? ''}" is not an e-mail address.\n\n${usage}`, exitCode: 1 };
  const users = new Users(await loadStore(env));
  const address = normalizeEmail(email);
  const user = await users.findByEmail(address);
  if (!user) return { output: `No user has the e-mail address ${address}. Users exist once they signed in, or with create-user.`, exitCode: 1 };
  let current = claimsFromJson(user.claims);
  if (command === 'set-roles' || command === 'set-claims') {
    let next: Claims | null;
    if (command === 'set-roles') {
      const roles = parseRoles(args);
      if (!roles) {
        return {
          output: 'Role names consist of lower-case letters, digits, "-" and "_", and start with a letter, e.g. admin.',
          exitCode: 1,
        };
      }
      const { roles: _, ...rest } = current;
      next = parseClaims(roles.length ? { ...rest, roles } : rest);
    } else {
      let parsed: unknown;
      try {
        parsed = JSON.parse(args[0] ?? '');
      } catch {
        return { output: `The claims must be JSON, e.g. '{"roles":["admin"]}'.\n\n${usage}`, exitCode: 1 };
      }
      next = parseClaims(parsed);
    }
    if (!next) {
      return {
        output:
          'Claims are a JSON object of at most 2048 characters whose keys are names (letters, digits and "_", starting ' +
          'with a letter); "roles" is a list of role names.',
        exitCode: 1,
      };
    }
    // Whoever can reach the database decides: this is how the first admin gets the role.
    await users.updateUser(user.id, { claims: Object.keys(next).length ? JSON.stringify(next) : null });
    current = next;
  }
  if (command === 'set-claims' || command === 'get-claims') {
    return { output: `${address}: ${JSON.stringify(current)}`, exitCode: 0 };
  }
  const roles = Array.isArray(current.roles) ? (current.roles as string[]) : [];
  return { output: roles.length ? `${address}: ${roles.join(' ')}` : `${address} has no roles.`, exitCode: 0 };
}

async function methods(command: 'set-methods' | 'get-methods', names: string[], env: Env) {
  // The whole configuration: only a method the server is configured for can be on, and one must stay on.
  const config = await loadConfig(env);
  const available = (method: SignInMethod) => (method === 'google' ? !!config.google : !!config.password);
  const settings = new Settings(config.store);
  if (command === 'set-methods') {
    const unknown = names.filter((name) => !(SIGN_IN_METHODS as readonly string[]).includes(name));
    if (unknown.length) {
      return { output: `Unknown sign-in method ${unknown.join(', ')}. Methods: ${SIGN_IN_METHODS.join(', ')}.`, exitCode: 1 };
    }
    const next: MethodSettings = {};
    for (const method of SIGN_IN_METHODS) next[method] = !names.length || names.includes(method);
    if (!anyOn(available, next)) {
      const configured = SIGN_IN_METHODS.filter(available);
      return { output: `That would switch off every sign-in method. The server is configured for: ${configured.join(', ')}.`, exitCode: 1 };
    }
    await settings.changeMethods(() => next, null);
  }
  const current = await settings.methods();
  const on = SIGN_IN_METHODS.filter((method) => isOn(method, available, current));
  const off = SIGN_IN_METHODS.filter((method) => available(method) && !isOn(method, available, current));
  return { output: `Switched on: ${on.join(', ')}.${off.length ? ` Switched off: ${off.join(', ')}.` : ''}`, exitCode: 0 };
}

async function createUser(email: string | undefined, io: CliIo, env: Env) {
  if (!isValidEmail(email)) return { output: `"${email ?? ''}" is not an e-mail address.\n\n${usage}`, exitCode: 1 };
  const { store, minLength } = await loadUserStoreConfig(env);
  const password = await io.askSecret(`Password for ${email}: `);
  const policy = checkPasswordPolicy(password, minLength);
  if (policy) return { output: policy, exitCode: 1 };
  const users = new Users(store);
  const passwordHash = await hashPassword(password);
  const user = await users.createUser({
    email: email.trim(),
    emailNormalized: normalizeEmail(email),
    name: null,
    emailVerified: true,
    account: (userId) => ({ key: passwordAccountKey(userId), secret: passwordHash }),
  });
  if (!user) return { output: `A user with the e-mail address ${email} already exists.`, exitCode: 1 };
  return { output: `Created user ${user.id} (${user.email}).`, exitCode: 0 };
}
