import { describe, expect, it } from 'vitest';
import { de, en, languageOf, stringsFor } from './strings.js';

/** The keys of a string table, with the type of each text. */
function shape(value: unknown): unknown {
  return value !== null && typeof value === 'object'
    ? Object.fromEntries(Object.entries(value).map(([key, text]) => [key, shape(text)]))
    : typeof value;
}

/** Every text of a string table; the ones with details get sample values. */
function texts(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (typeof value === 'function') return [String(value('x', 8))];
  return Object.values(value as object).flatMap(texts);
}

describe('strings', () => {
  it('picks the language by the primary subtag of the locale', () => {
    expect(stringsFor('de')).toBe(de);
    expect(stringsFor('de-CH')).toBe(de);
    expect(stringsFor('DE_at')).toBe(de);
    expect(stringsFor('en')).toBe(en);
    expect(stringsFor('en-GB')).toBe(en);
  });

  it('falls back to English for other languages and without a locale', () => {
    for (const locale of ['fr', 'fr-DE', 'deu', 'toString', '', undefined]) {
      expect(languageOf(locale)).toBe('en');
      expect(stringsFor(locale)).toBe(en);
    }
  });

  it('has every text in both languages', () => {
    expect(shape(de)).toEqual(shape(en));
    expect(texts(de).filter((text) => !text.trim())).toEqual([]);
  });

  it('addresses the user formally in German', () => {
    const informal = texts(de).filter((text) => /\b(du|dich|dir|dein\w*|euch|euer\w*)\b/i.test(text));

    expect(informal).toEqual([]);
    expect(texts(de).join(' ')).toMatch(/\bSie\b/);
  });
});
