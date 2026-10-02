import { generateSigningKey } from './keys.js';

const usage = `Usage: npx @madauth/server <command>

Commands:
  generate-key   Print a new private ES256 key to use as MADAUTH_SIGNING_KEY`;

/** Runs a CLI command and returns what it prints. */
export async function runCli(args: string[]): Promise<{ output: string; exitCode: number }> {
  if (args[0] === 'generate-key') {
    return { output: JSON.stringify(await generateSigningKey()), exitCode: 0 };
  }
  return { output: usage, exitCode: args.length ? 1 : 0 };
}
