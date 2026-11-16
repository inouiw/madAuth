import { describe, expect, it } from 'vitest';
import { coreDe, coreEn, coreStringsFor, languageOf, methodTexts } from './strings-core.js';
import { codeOnlyDe, codeOnlyEn, de, en, stringsFor } from './strings.js';

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
    expect(coreStringsFor('de-CH')).toBe(coreDe);
    expect(coreStringsFor('en-GB')).toBe(coreEn);
  });

  it('falls back to English for other languages and without a locale', () => {
    for (const locale of ['fr', 'fr-DE', 'deu', 'toString', '', undefined]) {
      expect(languageOf(locale)).toBe('en');
      expect(stringsFor(locale)).toBe(en);
      expect(coreStringsFor(locale)).toBe(coreEn);
    }
  });

  it('has every text in both languages', () => {
    expect(shape(de)).toEqual(shape(en));
    expect(shape(coreDe)).toEqual(shape(coreEn));
    expect(texts(de).filter((text) => !text.trim())).toEqual([]);
  });

  it("the dialog's tables extend the client's, so both show the same texts", () => {
    expect(en).toMatchObject(coreEn);
    expect(de).toMatchObject(coreDe);
    expect(en.methods).toBe(methodTexts);
  });

  it("has the code-only texts in both languages, and none of them mentions a link", () => {
    expect(shape(codeOnlyDe)).toEqual(shape(codeOnlyEn));
    for (const table of [codeOnlyEn, codeOnlyDe]) expect(texts(table).filter((text) => /link/i.test(text) || !text.trim())).toEqual([]);
  });

  it("swaps only the texts about the confirmation and sign-in e-mails with emailTexts: 'code-only'", () => {
    for (const [locale, base] of [['en', en], ['de', de]] as const) {
      const codeOnly = stringsFor(locale, 'code-only');
      expect(shape(codeOnly)).toEqual(shape(base));
      expect(stringsFor(locale, 'link-and-code')).toBe(base);
      // The password reset's e-mail keeps its link, and so do its texts.
      expect(codeOnly.resetInboxLead).toBe(base.resetInboxLead);
      expect(codeOnly.forgotLead).toBe(base.forgotLead);
      expect(codeOnly.resetCodesLocked).toBe(base.resetCodesLocked);
      expect(codeOnly.errors.link_invalid).toBe(base.errors.link_invalid);
      const baseTexts = texts(base);
      const changed = texts(codeOnly).filter((text, i) => text !== baseTexts[i]);
      expect(changed.filter((text) => /link/i.test(text))).toEqual([]);
    }
    expect(stringsFor('de-CH', 'code-only').inboxLead).toEqual(codeOnlyDe.inboxLead);
  });

  it('addresses the user formally in German', () => {
    const informal = [...texts(de), ...texts(codeOnlyDe)].filter((text) => /\b(du|dich|dir|dein\w*|euch|euer\w*)\b/i.test(text));

    expect(informal).toEqual([]);
    expect(texts(de).join(' ')).toMatch(/\bSie\b/);
  });
});
