import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseEnv } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runCli, type CliIo } from './cli.js';
import { loadConfig } from './config.js';
import { DEV_WEBHOOK_RECEIVER_URL, checkWebhookSecret } from './webhooks.js';
import { fakeKms } from './test/kms.js';

const CLIENT_ID = '123-test.apps.googleusercontent.com';
const EMAIL_TYPES = 'email.send_verification,email.send_password_reset,email.send_already_registered,email.send_password_reset_no_password';

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
    writeFileSync(envFile, 'MADAUTH_ISSUER=not a url\n');

    const after = await runCli(['start', '--env-file', envFile], noQuestions, {});
    const before = await runCli([`--env-file=${envFile}`, 'start'], noQuestions, {});
    const environmentWins = await runCli(['start', '--env-file', envFile], noQuestions, { MADAUTH_ISSUER: 'https://app.example.com' });

    expect(after).toEqual({ exitCode: 1, output: 'MADAUTH_ISSUER: "not a url" is not a URL.' });
    expect(before).toEqual(after);
    expect(environmentWins).toEqual({ exitCode: 1, output: expect.stringContaining('MADAUTH_KEY_SERVICE is not set') });
  });

  it('is an error when the file is missing or not named', async () => {
    const missing = tempFile('missing.env');

    const notThere = await runCli(['generate-key', '--env-file', missing]);
    const notNamed = await runCli(['generate-key', '--env-file']);

    expect(notThere).toEqual({ exitCode: 1, output: `--env-file: ${missing} does not exist.` });
    expect(notNamed).toEqual({ exitCode: 1, output: expect.stringMatching(/argument missing.*Usage:/s) });
  });
});

describe('generate-key', () => {
  it('prints a private ES256 JWK, or with --rs256 an RS256 one to add to MADAUTH_SIGNING_KEY', async () => {
    const ec = await runCli(['generate-key']);
    expect(ec.exitCode).toBe(0);
    expect(JSON.parse(ec.output)).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', d: expect.any(String), kid: expect.any(String) });
    const rsa = await runCli(['generate-key', '--rs256']);
    expect(rsa.exitCode).toBe(0);
    expect(JSON.parse(rsa.output)).toMatchObject({ kty: 'RSA', alg: 'RS256', n: expect.any(String), e: 'AQAB', d: expect.any(String), kid: expect.any(String) });
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
      MADAUTH_KEY_SERVICE: 'local',
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
        allowedOrigins: ['http://localhost:5173'],
        google: undefined,
        password: {},
        webhook: { url: 'http://localhost:8790/webhook', events: new Set(EMAIL_TYPES.split(',')) },
      });
      // The generated key, as the local key service.
      expect(await config.keyService.verificationKeys()).toEqual([expect.objectContaining({ kty: 'EC', crv: 'P-256', alg: 'ES256' })]);
    }
  });

  it('--email-link adds the sign-in e-mail to the types, once each, and EmailLink to the next steps', async () => {
    const link = tempFile();
    const alone = tempFile();

    const withPassword = await runCli(['init', '--yes', '--email-link', '--out', link], noQuestions);
    const linkOnly = await runCli(['init', '--yes', '--no-password', '--email-link', '--out', alone], noQuestions);

    expect(readEnvFile(link).WEBHOOK_EVENTS).toBe(`${EMAIL_TYPES},email.send_signin_link`);
    expect(withPassword.output).toContain('providers: [new Password(), new EmailLink()]');
    expect(readEnvFile(alone).WEBHOOK_EVENTS).toBe('email.send_signin_link,email.send_already_registered');
    expect(linkOnly).toMatchObject({ exitCode: 0, output: expect.stringContaining('providers: [new EmailLink()]') });
    // The webhook that sends the e-mails is still needed.
    expect(await loadConfig({ ...readEnvFile(alone), DATABASE_URL: `sqlite:${tempFile('madauth.db')}` })).toMatchObject({ password: undefined });
  });

  it('takes the answers given as options instead of the defaults', async () => {
    const minimal = tempFile();
    const both = tempFile();
    const init = (...args: string[]) => runCli(['init', '--yes', ...args], noQuestions);

    await init('--app-url', 'https://app.example.com/login', '--no-password', '--out', minimal);
    await init('--password', '--database', 'dynamodb:users', '--webhook-url', 'https://hooks.example.com/madauth', '--out', both);

    // No sign-in method yet (providers come with the setup token), and still a database, where every user is stored.
    expect(readEnvFile(minimal)).toEqual({
      MADAUTH_ISSUER: 'https://app.example.com',
      MADAUTH_KEY_SERVICE: 'local',
      MADAUTH_SIGNING_KEY: expect.any(String),
      ALLOWED_ORIGINS: 'https://app.example.com',
      DATABASE_URL: 'sqlite:./madauth.db',
      PORT: '8787',
    });
    expect(readEnvFile(both)).toMatchObject({ DATABASE_URL: 'dynamodb:users', WEBHOOK_URL: 'https://hooks.example.com/madauth' });
  });

  it('takes a Postgres URL as the database, in either form', async () => {
    for (const url of ['postgres://madauth:pw@db:5432/madauth', 'postgresql://app:pw@db-rw.ns:5432/app']) {
      const file = tempFile();
      await runCli(['init', '--yes', '--database', url, '--out', file], noQuestions);

      expect(readEnvFile(file)).toMatchObject({ DATABASE_URL: url });
    }
  });

  it('asks, in order, what no option answers, and takes the default for an empty answer', async () => {
    const file = tempFile();
    const io = answering({ 'App URL': 'http://localhost:3000/' });

    const { exitCode } = await runCli(['init', '--out', file, '--webhook-url', 'http://localhost:9999/hook'], io);

    expect(exitCode).toBe(0);
    expect(io.asked).toEqual([
      'App URL, the address your users open',
      'E-mail & password sign-in? (yes/no)',
      'Sign-up with the authenticator app alone, without a password? (yes/no)',
      'Passwordless sign-in with an e-mail link? (yes/no)',
      'SMS codes as a second factor, sent by your webhook receiver? (yes/no)',
      'Database for the users',
      'Your e-mail address, to become the first admin (empty: none)',
    ]);
    expect(readEnvFile(file)).not.toHaveProperty('INITIAL_ADMIN_EMAIL');
    expect(readEnvFile(file)).toMatchObject({
      MADAUTH_ISSUER: 'http://localhost:3000',
      DATABASE_URL: 'sqlite:./madauth.db',
      WEBHOOK_URL: 'http://localhost:9999/hook',
    });
  });

  it('writes the address of the first admin, and tells them to sign up with it', async () => {
    const file = tempFile();
    const io = answering({ 'first admin': ' Grace@Example.com ' });

    const { output, exitCode } = await runCli(['init', '--out', file], io);

    expect(exitCode).toBe(0);
    expect(readEnvFile(file).INITIAL_ADMIN_EMAIL).toBe('Grace@Example.com');
    expect(output).toContain('6. Sign up with grace@example.com in your app: you get the role admin (INITIAL_ADMIN_EMAIL)');
    expect(output).toContain('7. Never commit');
    // As an option, and refused when it is no address.
    const given = tempFile();
    expect(await runCli(['init', '--yes', '--initial-admin-email', 'ada@example.com', '--out', given], noQuestions)).toMatchObject({ exitCode: 0 });
    expect(readEnvFile(given).INITIAL_ADMIN_EMAIL).toBe('ada@example.com');
    const wrong = tempFile();
    expect(await runCli(['init', '--yes', '--initial-admin-email', 'ada', '--out', wrong], noQuestions)).toEqual({
      exitCode: 1,
      output: 'The admin\'s address must be an e-mail address, e.g. you@example.com, but is "ada".',
    });
    expect(existsSync(wrong)).toBe(false);
  });

  it('tells the admin how to let the authenticator app sign in on its own next to other methods', async () => {
    const args = ['init', '--yes', '--authenticator', '--sms', '--initial-admin-email', 'grace@example.com', '--out', tempFile()];

    const { output } = await runCli(args, noQuestions);

    expect(output).toContain('Signing in with the authenticator app alone is off until an admin allows it. Signed in as the admin, in your app:');
    expect(output).toContain(
      "await Madauth.admin.setSettings({ methods: { password: signIn, authenticator: signIn, sms: secondFactorOnly } });",
    );
    expect(output).not.toContain('set-methods');
  });

  it('writes a server without any sign-in method, whose providers come with the setup token', async () => {
    const file = tempFile();
    const io = answering({ 'E-mail & password': 'no' });

    const answered = await runCli(['init', '--out', file], io);

    expect(answered.exitCode).toBe(0);
    expect(readEnvFile(file)).not.toHaveProperty('WEBHOOK_URL');
    expect(answered.output).toContain('Madauth.initialize({ providers: [] });');
    expect(answered.output).toContain('the server prints a setup token when it starts');
    expect(answered.output).not.toContain('webhook receiver');
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
    expect(await init('--database', 'mysql://db/madauth')).toEqual(failsWith('sqlite:<path>, postgres://'));
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

2. madAuth hands its e-mails to your webhook receiver. For development, start the development receiver,
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
     signInButton.onclick = () => Madauth.showSignInDialog();

5. Google and GitHub sign-in are providers in the store; the sign-in dialog shows a button for each one that is on.
   Until the first admin exists, the server prints a setup token when it starts. Add a provider with it, e.g.:

     curl -X POST http://localhost:8787/auth/admin/providers/add -H 'Authorization: Bearer <setup token>' \\
       -H 'Content-Type: application/json' -d '{"kind":"google","clientId":"<client ID>","clientSecret":"<client secret>"}'

   Register what it answers as callbackUrl in your Google OAuth client (Authorized redirect URIs; JavaScript origins: http://localhost:5173 and http://localhost)
   or GitHub OAuth App (Authorization callback URL), and switch the provider on with /auth/admin/settings/set.
   Later an admin does this with Madauth.admin.addProvider. See "Providers" in docs/server.md.

6. Never commit ${file}: it holds the signing key and your secrets. Production needs an https app URL
   and a signing key of its own: run init again for it.`);
  });

  it('O14: Google and GitHub are no options any more: they are providers in the store', async () => {
    const https = await runCli(['init', '--yes', '--app-url', 'https://app.example.com', '--out', tempFile()], noQuestions);
    // Google wants http://localhost next to the origin with its port only for development.
    expect(https.output).toContain('JavaScript origins: https://app.example.com)');

    const old = await runCli(['init', '--yes', '--google-client-id', CLIENT_ID, '--out', tempFile()], noQuestions);
    expect(old).toEqual({ exitCode: 1, output: expect.stringContaining("Unknown option '--google-client-id'") });
  });
});

describe('start', () => {
  it('returns the configuration error instead of starting', async () => {
    const result = await runCli(['start'], noQuestions, {});

    expect(result).toEqual({ exitCode: 1, output: 'MADAUTH_ISSUER is not set. See docs/server.md.' });
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
    for (const text of ['  init  ', '  start  ', '  generate-key [--rs256]  ', '  --env-file <path>  ']) expect(output).toContain(text);
  });

  it('names what replaced a command madAuth before 0.6 had', async () => {
    const result = await runCli(['set-roles', 'you@example.com', 'admin'], noQuestions, {});

    expect(result).toEqual({ exitCode: 1, output: expect.stringMatching(/^set-roles was removed in madAuth 0\.6: .*Madauth\.admin.*INITIAL_ADMIN_EMAIL/) });
    expect(await runCli(['remove-totp', 'you@example.com'], noQuestions, {})).toEqual({
      exitCode: 1,
      output: expect.stringMatching(/^remove-totp was removed in madAuth 0\.6: .*Madauth\.admin\.resetSignIn\(email\) \(POST \/auth\/admin\/sign-in\/reset\)/),
    });
  });

  it('is printed with an unknown option', async () => {
    const result = await runCli(['init', '--nope'], noQuestions);

    expect(result).toEqual({ exitCode: 1, output: expect.stringMatching(/^Unknown option '--nope'.*Usage:/s) });
  });
});

describe('kms-setup and kms-rotate', () => {
  it('K1: create the keys of the deployment named by MADAUTH_ISSUER, print the policy of the server role, and rotate', async () => {
    const { kms, aliases } = fakeKms();
    const env = { MADAUTH_ISSUER: 'https://auth.example.com' };

    expect(await runCli(['kms-setup'], noQuestions, {}, kms)).toMatchObject({ exitCode: 1, output: expect.stringContaining('needs MADAUTH_ISSUER') });
    const setUp = await runCli(['kms-setup'], noQuestions, env, kms);
    expect(setUp.exitCode).toBe(0);
    expect(setUp.output).toContain('Created the signing key');
    expect(setUp.output).not.toContain('signing-rsa');
    expect(setUp.output).toContain('"kms:ResourceAliases": "alias/madauth/auth-example-com/*"');
    expect(setUp.output).toContain('set MADAUTH_KEY_SERVICE=aws-kms and remove MADAUTH_SIGNING_KEY');
    expect(aliases.has('alias/madauth/auth-example-com/encryption')).toBe(true);
    expect((await runCli(['kms-setup'], noQuestions, env, kms)).output).toMatch(/^The keys under alias\/madauth\/auth-example-com exist already\./);
    // --rs256 adds the RS256 key to a deployment that has the others.
    expect((await runCli(['kms-setup', '--rs256'], noQuestions, env, kms)).output).toMatch(/^Created the signing-rsa key/);
    expect(aliases.has('alias/madauth/auth-example-com/signing-rsa')).toBe(true);

    expect(await runCli(['kms-rotate'], noQuestions, env, kms)).toEqual({ exitCode: 0, output: 'Nothing to rotate under alias/madauth/auth-example-com.' });
    // Missing keys fail the run, so a scheduled rotator's failure is noticed.
    aliases.delete('alias/madauth/auth-example-com/signing');
    expect(await runCli(['kms-rotate'], noQuestions, env, kms)).toMatchObject({ exitCode: 1, output: expect.stringContaining('There is no signing key') });
  });
});
