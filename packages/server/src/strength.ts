// How hard a password is to guess, rated by zxcvbn-ts. The web library's strength meter rates it with the same
// dictionaries and options (packages/web/src/strength.ts), so the two agree: change both together.
import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import { adjacencyGraphs, dictionary } from '@zxcvbn-ts/language-common';
import type { PasswordScore } from './settings.js';

let zxcvbn: ZxcvbnFactory | undefined;

/**
 * The password's score, 0 (guessed at once) to 4 (very hard to guess). It knows about 49,000 common passwords,
 * keyboard patterns, repeats, dates and l33t, and `userInputs`: words of the user (e.g. the e-mail address
 * and name) that make a password easy to guess for whoever knows them.
 */
export function passwordScore(password: string, userInputs: string[] = []): PasswordScore {
  // Built on first use, so a server that never sees a new password doesn't pay for the dictionaries.
  zxcvbn ??= new ZxcvbnFactory({ dictionary, graphs: adjacencyGraphs, useLevenshteinDistance: true });
  return zxcvbn.check(password, userInputs).score as PasswordScore;
}
