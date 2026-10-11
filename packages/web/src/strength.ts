// How hard a password is to guess, rated by zxcvbn-ts with the same dictionaries and options as the server
// (packages/server/src/strength.ts), so the strength meter and the server's check agree. The server's
// strength.test.ts checks that both give the same scores; both package.json files pin the same versions.

/** Rates a password from 0 (guessed at once) to 4 (very hard to guess); `userInputs` are the user's own words. */
export type RatePassword = (password: string, userInputs?: string[]) => number;

/** Only the first 64 characters are rated, as on the server: longer ones are strong anyway, and it keeps typing smooth. */
const RATED_LENGTH = 64;

let loading: Promise<RatePassword> | undefined;

/**
 * Loads zxcvbn-ts and its list of common passwords (about 220 kB compressed) on first use, so pages that never
 * ask for a new password don't download it.
 */
export function loadPasswordRating(): Promise<RatePassword> {
  loading ??= Promise.all([import('@zxcvbn-ts/core'), import('@zxcvbn-ts/language-common')]).then(([core, common]) => {
    const zxcvbn = new core.ZxcvbnFactory({
      dictionary: common.dictionary,
      graphs: common.adjacencyGraphs,
      useLevenshteinDistance: true,
      maxLength: RATED_LENGTH,
    });
    return (password, userInputs = []) => zxcvbn.check(password, userInputs).score;
  });
  // A failed download (e.g. offline) is tried again next time.
  loading.catch(() => (loading = undefined));
  return loading;
}
