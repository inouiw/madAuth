import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseEnv } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEV_WEBHOOK_RECEIVER_URL, runCli, type CliIo } from './cli.js';
import { loadConfig } from './config.js';
import { checkWebhookSecret } from './webhooks.js';

const CLIENT_ID = '123-test.apps.googleusercontent.com';
const EMAIL_TYPES = 'email.verify,email.reset,email.already_registered';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** A file path in a new temp directory, which is removed after the test. */
function tempFile(name = '.env'): string {
  const dir = mkdtempSync(join(tmpdir(), 'madauth-'));
  dirs.push(dir);
  return join(dir, name);
}

/** For commands that must not ask anything. */
const noQuestions: CliIo = {
  ask: async (question) => Promise.reject(new Error(`Asked: ${question}`)),
  askSecret: async (question) => Promise.reject(new Error(`Asked: ${question}`)),
};

/** Answers the questions that contain a key of `answers`, takes the default for the others, and records them all. */
function answering(answers: Record<string, string> = {}): CliIo & { asked: string[] } {
  const asked: string[] = [];
  const answer = (question: string, defaultValue = '') => {
    asked.push(question);
    const key = Object.keys(answers).find((k) => question.includes(k));
    return key ? answers[key] : defaultValue;
  };
  return { asked, ask: async (question, defaultValue) => answer(question, defaultValue), askSecret: async (question) => answer(question) };
}

const readEnvFile = (file: string) => parseEnv(readFileSync(file, 'utf8'));

describe('--env-file', () => {
  it('gives any command the variables of the file, before or after the command; the environment wins', async () => {
    const envFile = tempFile();
    writeFileSync(envFile, `DATABASE_URL=sqlite:${tempFile('madauth.db')}\nPASSWORD_MIN_LENGTH=20\n`);
    const io = { ...noQuestions, askSecret: async () => 'correct horse' };

    const fromFile = await runCli(['create-user', 'ada@example.com', '--env-file', envFile], io, {});
    const environmentWins = await runCli([`--env-file=${envFile}`, 'create-user', 'ada@example.com'], io, {
      PASSWORD_MIN_LENGTH: '8',
    });

    expect(fromFile).toMatchObject({ exitCode: 1, output: expect.stringContaining('at least 20') });
    expect(environmentWins).toMatchObject({ exitCode: 0, output: expect.stringContaining('Created user') });
  });

  it('is an error when the file is missing or not named', async () => {
    const missing = tempFile('missing.env');

    const notThere = await runCli(['generate-key', '--env-file', missing]);
    const notNamed = await runCli(['generate-key', '--env-file']);

    expect(notThere).toEqual({ exitCode: 1, output: `--env-file: ${missing} does not exist.` });
    expect(notNamed).toEqual({ exitCode: 1, output: expect.stringMatching(/argument missing.*Usage:/s) });
  });
});

describe('init', () => {
  it('--yes writes the defaults with new secrets, a comment above each variable, readable by the owner only', async () => {
    const file = tempFile();

    const { exitCode } = await runCli(['init', '--yes', '--out', file], noQuestions);

    expect(exitCode).toBe(0);
    const env = readEnvFile(file);
    expect(env).toEqual({
      MADAUTH_ISSUER: 'http://localhost:5173',
      MADAUTH_SIGNING_KEY: expect.any(String),
      ALLOWED_ORIGINS: 'http://localhost:5173',
      DATABASE_URL: 'sqlite:./madauth.db',
      WEBHOOK_URL: 'http://localhost:8790/webhook',
      WEBHOOK_SECRET: expect.any(String),
      WEBHOOK_EVENTS: EMAIL_TYPES,
      PORT: '8787',
    });
    expect(JSON.parse(env.MADAUTH_SIGNING_KEY!)).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', d: expect.any(String) });
    expect(checkWebhookSecret(env.WEBHOOK_SECRET!)).toBeNull();
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const lines = readFileSync(file, 'utf8').trimEnd().split('\n');
    lines.forEach((line, i) => {
      if (line && !line.startsWith('#')) expect(lines[i - 1]).toMatch(/^# \S/);
    });
  });

  it('writes a file the server accepts, read by Node or passed on by Docker', async () => {
    const file = tempFile();
    await runCli(['init', '--yes', '--database', `sqlite:${tempFile('madauth.db')}`, '--out', file], noQuestions);
    const text = readFileSync(file, 'utf8');
    // Docker's --env-file passes on what follows the "=" as it is, with its quotes.
    const fromDocker = Object.fromEntries(
      text
        .split('\n')
        .filter((line) => line && !line.startsWith('#'))
        .map((line) => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]),
    );
    expect(fromDocker.MADAUTH_SIGNING_KEY).toMatch(/^'\{.*\}'$/);

    for (const env of [parseEnv(text), fromDocker]) {
      const config = await loadConfig(env);

      expect(config).toMatchObject({
        issuer: 'http://localhost:5173',
        signingKey: { kty: 'EC', crv: 'P-256', d: expect.any(String) },
        allowedOrigins: ['http://localhost:5173'],
        google: undefined,
        password: { minLength: 8 },
        webhook: { url: 'http://localhost:8790/webhook', events: new Set(EMAIL_TYPES.split(',')) },
      });
    }
  });

  it('takes the answers given as options instead of the defaults', async () => {
    const googleOnly = tempFile();
    const both = tempFile();
    const init = (...args: string[]) => runCli(['init', '--yes', '--google-client-id', CLIENT_ID, ...args], noQuestions);

    await init('--app-url', 'https://app.example.com/login', '--google-client-secret=shh', '--no-password', '--out', googleOnly);
    await init('--password', '--database', 'dynamodb:users', '--webhook-url', 'https://hooks.example.com/madauth', '--out', both);

    expect(readEnvFile(googleOnly)).toEqual({
      MADAUTH_ISSUER: 'https://app.example.com',
      MADAUTH_SIGNING_KEY: expect.any(String),
      ALLOWED_ORIGINS: 'https://app.example.com',
      GOOGLE_CLIENT_ID: CLIENT_ID,
      GOOGLE_CLIENT_SECRET: 'shh',
      PORT: '8787',
    });
    expect(readEnvFile(both)).toMatchObject({
      GOOGLE_CLIENT_ID: CLIENT_ID,
      DATABASE_URL: 'dynamodb:users',
      WEBHOOK_URL: 'https://hooks.example.com/madauth',
    });
    expect(readEnvFile(both)).not.toHaveProperty('GOOGLE_CLIENT_SECRET');
  });

  it('asks, in order, what no option answers, and takes the default for an empty answer', async () => {
    const file = tempFile();
    const io = answering({ 'App URL': 'http://localhost:3000/', 'Google client ID': CLIENT_ID, 'Google client secret': 'shh' });

    const { exitCode } = await runCli(['init', '--out', file, '--webhook-url', 'http://localhost:9999/hook'], io);

    expect(exitCode).toBe(0);
    expect(io.asked).toEqual([
      'App URL, the address your users open',
      'Google client ID (empty: no Google sign-in)',
      'Google client secret (empty: no redirect flow): ',
      'E-mail & password sign-in? (yes/no)',
      'Database for the users',
    ]);
    expect(readEnvFile(file)).toMatchObject({
      MADAUTH_ISSUER: 'http://localhost:3000',
      GOOGLE_CLIENT_ID: CLIENT_ID,
      GOOGLE_CLIENT_SECRET: 'shh',
      DATABASE_URL: 'sqlite:./madauth.db',
      WEBHOOK_URL: 'http://localhost:9999/hook',
    });
  });

  it('needs at least one sign-in method', async () => {
    const file = tempFile();
    const io = answering({ 'E-mail & password': 'no' });

    const answered = await runCli(['init', '--out', file], io);
    const withOptions = await runCli(['init', '--yes', '--no-password', '--out', file], noQuestions);

    // Without a client ID its secret is not asked for; without password sign-in, neither database nor webhook.
    expect(io.asked).toEqual([
      'App URL, the address your users open',
      'Google client ID (empty: no Google sign-in)',
      'E-mail & password sign-in? (yes/no)',
    ]);
    expect(answered).toEqual({ exitCode: 1, output: expect.stringContaining('No sign-in method is chosen') });
    expect(withOptions).toEqual(answered);
    expect(existsSync(file)).toBe(false);
  });

  it('does not overwrite a file without --force, and says so before it asks anything', async () => {
    const file = tempFile();
    writeFileSync(file, 'KEEP=1\n');

    const refused = await runCli(['init', '--out', file], noQuestions);

    expect(refused).toEqual({ exitCode: 1, output: expect.stringMatching(/\.env already exists\. Use --force/) });
    expect(readFileSync(file, 'utf8')).toBe('KEEP=1\n');

    const forced = await runCli(['init', '--yes', '--force', '--out', file], noQuestions);

    expect(forced.exitCode).toBe(0);
    expect(readEnvFile(file)).not.toHaveProperty('KEEP');
    expect(readEnvFile(file)).toHaveProperty('MADAUTH_SIGNING_KEY');
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('rejects answers the server would not start with, and writes nothing', async () => {
    const file = tempFile();
    const init = (...args: string[]) => runCli(['init', '--yes', '--out', file, ...args], noQuestions);
    const failsWith = (text: string) => ({ exitCode: 1, output: expect.stringContaining(text) });

    expect(await init('--app-url', 'localhost:5173')).toEqual(failsWith('The app URL must be an http(s) URL'));
    expect(await init('--database', 'postgres://db/madauth')).toEqual(failsWith('sqlite:<path> or dynamodb:<table>'));
    expect(await init('--google-client-id', 'abc')).toEqual(failsWith('GOOGLE_CLIENT_ID must end with'));
    expect(await init('--webhook-url', 'http://hooks.example.com/x')).toEqual(failsWith('WEBHOOK_URL must be an https URL'));
    expect(existsSync(file)).toBe(false);
  });

  it('prints the next steps for e-mail & password sign-in', async () => {
    const file = tempFile();

    const { output } = await runCli(['init', '--yes', '--out', file], noQuestions);

    expect(output).toBe(`Wrote ${file}.

Next steps:

1. Start the madAuth server:

     npx @madauth/server start --env-file ${file}

2. madAuth hands its e-mails to your webhook receiver. For development, start the example receiver,
   which prints them, with the same WEBHOOK_URL and WEBHOOK_SECRET as in ${file}:

     ${DEV_WEBHOOK_RECEIVER_URL}

3. Proxy /auth and /.well-known from your app to the server, so that its cookies are first-party.
   With Vite, in vite.config.ts:

     server: {
       proxy: {
         '/auth': 'http://localhost:8787',
         '/.well-known': 'http://localhost:8787',
       },
     },

4. Sign users in from your app (npm install @madauth/web):

     import { Madauth, Password } from '@madauth/web';

     Madauth.initialize({ providers: [new Password()] });
     Madauth.onAuthStateChanged((user) => console.log(user)); // the user, or null
     signInButton.onclick = () => Madauth.signIn();

5. Never commit ${file}: it holds the signing key and your secrets. Production needs an https app URL
   and a signing key of its own: run init again for it.`);
  });

  it('prints the next steps for Google sign-in in the browser (FedCM / One Tap)', async () => {
    const args = ['init', '--yes', '--google-client-id', CLIENT_ID, '--no-password', '--out', tempFile()];

    const { output } = await runCli(args, noQuestions);

    expect(output).toContain("import { Madauth, GoogleFedcm } from '@madauth/web';");
    expect(output).toContain('Madauth.initialize({ providers: [new GoogleFedcm()] });');
    expect(output).toContain('4. In the Google Cloud Console');
    expect(output).toContain('Authorized JavaScript origins: http://localhost:5173 and http://localhost\n');
    expect(output).toContain('5. Never commit');
    expect(output).not.toContain('redirect URIs');
    expect(output).not.toContain('webhook receiver');
  });

  it('prints the next steps for the Google redirect flow with e-mail & password sign-in', async () => {
    const google = ['--google-client-id', CLIENT_ID, '--google-client-secret', 'shh'];

    const { output } = await runCli(['init', '--yes', '--app-url', 'https://app.example.com', ...google, '--out', tempFile()], noQuestions);

    expect(output).toContain(`2. madAuth hands its e-mails to your webhook receiver.`);
    expect(output).toContain("import { Madauth, GoogleRedirect, Password } from '@madauth/web';");
    expect(output).toContain('Madauth.initialize({ providers: [new GoogleRedirect(), new Password()] });');
    expect(output).toContain('Authorized JavaScript origins: https://app.example.com\n');
    expect(output).toContain('Authorized redirect URIs: https://app.example.com/auth/google/callback');
    expect(output).toContain('6. Never commit');
  });
});

describe('start', () => {
  it('returns the configuration error instead of starting', async () => {
    const result = await runCli(['start'], noQuestions, {});

    expect(result).toEqual({ exitCode: 1, output: 'MADAUTH_ISSUER is not set. See docs/server.md.' });
  });

  it('reads the configuration from --env-file, under the environment', async () => {
    const envFile = tempFile();
    writeFileSync(envFile, 'MADAUTH_ISSUER=not a url\n');

    const fromFile = await runCli(['start', '--env-file', envFile], noQuestions, {});
    const environmentWins = await runCli(['start', '--env-file', envFile], noQuestions, { MADAUTH_ISSUER: 'https://app.example.com' });

    expect(fromFile).toEqual({ exitCode: 1, output: 'MADAUTH_ISSUER: "not a url" is not a URL.' });
    expect(environmentWins).toEqual({ exitCode: 1, output: expect.stringContaining('MADAUTH_SIGNING_KEY is not set') });
  });

  it('starts the server with that environment and prints nothing itself', async () => {
    const start = vi.fn(async () => {});
    vi.doMock('./entry/node.js', () => ({ start }));
    const envFile = tempFile();
    writeFileSync(envFile, 'MADAUTH_ISSUER=http://localhost:5173\nPORT=8787\n');

    const result = await runCli(['start', '--env-file', envFile], noQuestions, { PORT: '9000' });

    expect(result).toEqual({ output: '', exitCode: 0 });
    expect(start).toHaveBeenCalledWith({ env: { MADAUTH_ISSUER: 'http://localhost:5173', PORT: '9000' } });
    vi.doUnmock('./entry/node.js');
  });
});

describe('usage', () => {
  it('lists the commands and --env-file, with exit code 0 when no command is given', async () => {
    const { output, exitCode } = await runCli([]);

    expect(exitCode).toBe(0);
    for (const text of ['  init  ', '  start  ', '  generate-key  ', '  --env-file <path>  ']) expect(output).toContain(text);
  });

  it('is printed with an unknown option', async () => {
    const result = await runCli(['init', '--nope'], noQuestions);

    expect(result).toEqual({ exitCode: 1, output: expect.stringMatching(/^Unknown option '--nope'.*Usage:/s) });
  });
});
