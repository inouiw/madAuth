// How hard a password is to guess, rated by zxcvbn-ts. The web library's strength meter rates it with the same
// dictionaries and options (packages/web/src/strength.ts), so the two agree: strength.test.ts checks that
// both give the same scores, and both package.json files pin the same zxcvbn-ts versions.
import type { ZxcvbnFactory } from '@zxcvbn-ts/core';
import type { PasswordScore } from './settings.js';

/**
 * Only the first 64 characters are rated: a longer password is strong anyway, and the rating runs on the main
 * thread, where 256 characters took up to 0.7 s, against about 0.1 s for 64.
 */
export const RATED_LENGTH = 64;

let loading: Promise<ZxcvbnFactory> | undefined;

/**
 * The password's score, 0 (guessed at once) to 4 (very hard to guess). It knows about 49,000 common passwords,
 * keyboard patterns, repeats, dates and l33t, and `userInputs`: words of the user (e.g. the e-mail address
 * and name) that make a password easy to guess for whoever knows them.
 */
export async function passwordScore(password: string, userInputs: string[] = []): Promise<PasswordScore> {
  // Loaded on first use, so a server (or a Lambda cold start) that never sees a new password doesn't pay for
  // the dictionaries.
  loading ??= Promise.all([import('@zxcvbn-ts/core'), import('@zxcvbn-ts/language-common')]).then(
    ([core, common]) =>
      new core.ZxcvbnFactory({
        dictionary: common.dictionary,
        graphs: common.adjacencyGraphs,
        useLevenshteinDistance: true,
        maxLength: RATED_LENGTH,
      }),
  );
  return (await loading).check(password, userInputs).score as PasswordScore;
}
