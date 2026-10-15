import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createInterface, type Interface } from 'node:readline';
import { parseArgs, parseEnv } from 'node:util';
import { loadConfig } from './config.js';
import { generateSigningKey } from './keys.js';
import { isValidEmail, normalizeEmail } from './password.js';
import { madauthSchema, type StoreAdapter } from './store/schema.js';
import { createTablesSql, upgradeTablesSql, type SqlDialect } from './store/sql.js';
import { DEV_WEBHOOK_RECEIVER_URL, generateWebhookSecret } from './webhooks.js';

/** The server's default port, which `init` writes as PORT. */
const PORT = 8787;

const usage = `Usage: npx @madauth/server <command> [--env-file <path>]

Commands:
  init                         Ask a few questions, write the configuration to .env and print the next steps.
                               An answer given as an option is not asked for: --app-url <url>,
                               --google-client-id <id>, --google-client-secret <secret>,
                               --github-client-id <id>, --github-client-secret <secret>, --password or
                               --no-password, --authenticator or --no-authenticator (sign-up with the
                               authenticator app), --email-link or --no-email-link (passwordless sign-in
                               by e-mail), --sms or --no-sms (SMS codes as a second factor),
                               --database <url>, --webhook-url <url>, --initial-admin-email <address> (who
                               becomes the first admin). --yes takes the default for the rest. --out <path>
                               writes another file, --force overwrites.
  start                        Start the server on PORT (default ${PORT})
  generate-key                 Print a new private ES256 key to use as MADAUTH_SIGNING_KEY
  generate-webhook-secret      Print a new secret to use as WEBHOOK_SECRET (madAuth and your receiver)
  schema [--dialect <name>] [--from <version>]
                               Print the SQL that creates madAuth's tables for a custom store adapter.
                               Dialects: postgres (default), mysql, sqlite. With --from, print only the
                               changes since that schema version, to upgrade existing tables.

Options:
  --env-file <path>            Read environment variables from this file, for any command. A variable
                               that is already set in the environment wins.`;

/** Commands of madAuth before 0.6, with what replaced them. */
const ADMIN_API = 'admins manage claims and settings with Madauth.admin from your app, and the first admin is who signs in with the address in INITIAL_ADMIN_EMAIL';
const RESET = 'an admin resets a user who lost every way in with Madauth.admin.resetSignIn(email) (POST /auth/admin/sign-in/reset)';
const REMOVED_COMMANDS: Record<string, string> = {
  'create-user': ADMIN_API,
  'set-roles': ADMIN_API,
  'get-roles': ADMIN_API,
  'set-claims': ADMIN_API,
  'get-claims': ADMIN_API,
  'set-methods': ADMIN_API,
  'get-methods': ADMIN_API,
  'set-password-rules': ADMIN_API,
  'get-password-rules': ADMIN_API,
  'remove-totp': RESET,
  'remove-sms': RESET,
  'remove-passkeys': RESET,
};

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
      'github-client-id': { type: 'string' },
      'github-client-secret': { type: 'string' },
      password: { type: 'boolean' },
      authenticator: { type: 'boolean' },
      'email-link': { type: 'boolean' },
      sms: { type: 'boolean' },
      database: { type: 'string' },
      'webhook-url': { type: 'string' },
      'initial-admin-email': { type: 'string' },
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
  const replacement = command && Object.hasOwn(REMOVED_COMMANDS, command) ? REMOVED_COMMANDS[command] : undefined;
  if (replacement) return { output: `${command} was removed in madAuth 0.6: ${replacement}. See docs/upgrading.md.`, exitCode: 1 };
  // No command takes arguments; one is likely a mistyped option, e.g. `init .env.local`.
  if (rest.length) {
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

  const githubClientId = await answer(options['github-client-id'], 'GitHub client ID (empty: no GitHub sign-in)');
  if (!githubClientId && options['github-client-secret'] !== undefined) {
    return fail('--github-client-secret needs a GitHub client ID.');
  }
  const githubClientSecret = githubClientId ? (options['github-client-secret'] ?? (options.yes ? '' : await io.askSecret('GitHub client secret: '))).trim() : '';
  // GitHub has no browser-only flow: the server exchanges the code itself, which takes the secret.
  if (githubClientId && !githubClientSecret) {
    return fail('GitHub sign-in needs the client secret of the OAuth App too (--github-client-secret).');
  }

  const password = options.password ?? /^y/i.test(await answer(undefined, 'E-mail & password sign-in? (yes/no)', 'yes'));
  // The app as a second factor needs no setting here; signing up with it alone needs the confirmation e-mails.
  const authenticator = options.authenticator ?? /^y/i.test(await answer(undefined, 'Sign-up with the authenticator app alone, without a password? (yes/no)', 'no'));
  const emailLink = options['email-link'] ?? /^y/i.test(await answer(undefined, 'Passwordless sign-in with an e-mail link? (yes/no)', 'no'));
  // SMS codes are a second factor only: they need a method that signs in, and a receiver that sends the SMS.
  const sms = options.sms ?? /^y/i.test(await answer(undefined, 'SMS codes as a second factor, sent by your webhook receiver? (yes/no)', 'no'));
  const emails = password || authenticator || emailLink;
  const webhook = emails || sms;
  if (!webhook && options['webhook-url'] !== undefined) {
    return fail('--webhook-url is for the e-mails of e-mail & password sign-in, of the e-mail link and of sign-up with the authenticator app, and for SMS codes, which are turned off.');
  }
  if (!clientId && !githubClientId && !emails) {
    return fail('No sign-in method is chosen. Give a Google or GitHub client ID, turn on e-mail & password sign-in, the e-mail link or sign-up with the authenticator app.');
  }
  // Every user is stored, whichever way they sign in.
  const database = await answer(options.database, 'Database for the users', 'sqlite:./madauth.db');
  if (!/^(sqlite|dynamodb):./.test(database)) {
    return fail(`The database must be sqlite:<path> or dynamodb:<table> but is "${database}".`);
  }
  const webhookUrl = webhook
    ? await answer(options['webhook-url'], `Webhook URL, where madAuth hands over its ${emails ? (sms ? 'e-mails and SMS' : 'e-mails') : 'SMS'}`, 'http://localhost:8790/webhook')
    : '';
  // Asked here, so that the file never needs the command line to make the first admin.
  const adminEmail = await answer(options['initial-admin-email'], 'Your e-mail address, to become the first admin (empty: none)');
  if (adminEmail && !isValidEmail(adminEmail)) return fail(`The admin's address must be an e-mail address, e.g. you@example.com, but is "${adminEmail}".`);
  // The types each chosen method needs, once each.
  const events = [
    ...(password ? ['email.send_verification', 'email.send_password_reset', 'email.send_already_registered', 'email.send_password_reset_no_password'] : []),
    ...(authenticator ? ['email.send_verification', 'email.send_already_registered'] : []),
    ...(emailLink ? ['email.send_signin_link', 'email.send_already_registered'] : []),
    ...(sms ? ['sms.send_code', 'user.second_factor_enabled', 'user.second_factor_disabled'] : []),
  ]
    .filter((type, i, all) => all.indexOf(type) === i)
    .join(',');

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
    githubClientId && variable('GITHUB_CLIENT_ID', githubClientId, 'GitHub sign-in: the client ID of your OAuth App.'),
    githubClientSecret && variable('GITHUB_CLIENT_SECRET', githubClientSecret, 'Client secret of the same OAuth App.'),
    variable('DATABASE_URL', database, 'Where the users are stored, whichever way they sign in.'),
    adminEmail &&
      variable(
        'INITIAL_ADMIN_EMAIL',
        adminEmail,
        'Who signs in with this address, once it is proven, gets the role admin. Once per value: a new one makes another admin.',
      ),
    webhook && variable('WEBHOOK_URL', webhookUrl, `Your webhook receiver. madAuth hands its ${sms ? 'e-mails and SMS' : 'e-mails'} to it.`),
    webhook && variable('WEBHOOK_SECRET', generateWebhookSecret(), 'Signs every webhook call. Your receiver needs the same one.'),
    webhook &&
      variable('WEBHOOK_EVENTS', events, 'The types your webhook receiver handles; only these are sent. Add e.g. user.signing_up or user.signed_up.'),
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
  const steps = nextSteps(file, origin, google, !!githubClientId, password, authenticator, emailLink, sms, normalizeEmail(adminEmail));
  return { output: `Wrote ${file}.\n\nNext steps:\n\n${steps}`, exitCode: 0 };
}

/** What to do after `init`, for the chosen sign-in methods: numbered steps with commands and snippets to copy. */
function nextSteps(
  file: string,
  origin: string,
  google: 'GoogleFedcm' | 'GoogleRedirect' | undefined,
  github: boolean,
  password: boolean,
  authenticator = false,
  emailLink = false,
  sms = false,
  adminEmail = '',
): string {
  const server = `http://localhost:${PORT}`;
  // Quoted when needed, so the command can be pasted as it is.
  const envFile = /[^\w./-]/.test(file) ? `'${file.replaceAll("'", `'\\''`)}'` : file;
  const providers = [google, github && 'GitHub', password && 'Password', authenticator && 'Authenticator', emailLink && 'EmailLink'].filter(Boolean);
  // The methods as the admin lists them to let the app sign in on its own; SMS codes stay a second factor.
  const methodList = [google && 'google', github && 'github', password && 'password', authenticator && 'authenticator', emailLink && "'email-link'"]
    .filter(Boolean)
    .map((method) => `${method}: signIn`)
    .concat(sms ? ['sms: secondFactorOnly'] : [])
    .join(', ');
  // For development, Google wants http://localhost next to the origin with its port.
  const googleOrigins = new Set([origin, ...(new URL(origin).hostname === 'localhost' ? ['http://localhost'] : [])]);
  const steps = [
    ['Start the madAuth server:', '', `  npx @madauth/server start --env-file ${envFile}`],
    (password || authenticator || emailLink || sms) && [
      `madAuth hands its ${sms ? 'e-mails and SMS' : 'e-mails'} to your webhook receiver. For development, start the development receiver,`,
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
    github && [
      'In your GitHub OAuth App (https://github.com/settings/developers), set:',
      '',
      `  Authorization callback URL: ${origin}/auth/github/callback`,
    ],
    adminEmail && [
      `Sign up with ${adminEmail} in your app: you get the role admin (INITIAL_ADMIN_EMAIL), and manage claims and`,
      'settings with Madauth.admin. Give a second user the role as well, so that one admin can help the other.',
    ],
    authenticator &&
      (google || github || password || emailLink) && [
        `Signing in with the authenticator app alone is off until an admin allows it. ${adminEmail ? 'Signed in as the admin' : 'As an admin (see INITIAL_ADMIN_EMAIL)'}, in your app:`,
        '',
        "  const signIn = { allowAsSignInMethod: true, secondFactor: 'none' } as const;",
        ...(sms ? ["  const secondFactorOnly = { allowAsSignInMethod: false, secondFactor: 'none' } as const;"] : []),
        `  await Madauth.admin.setSettings({ methods: { ${methodList} } });`,
      ],
    [
      `Never commit ${file}: it holds the signing key and your secrets. Production needs an https app URL`,
      'and a signing key of its own: run init again for it.',
    ],
  ].filter((step) => !!step);
  // The lines after the first are indented under the step's text.
  return steps.map((lines, i) => `${i + 1}. ${lines.map((line, j) => (j && line ? `   ${line}` : line)).join('\n')}`).join('\n\n');
}
