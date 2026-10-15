import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import { OG_HEIGHT, OG_WIDTH, renderOgImage } from './og-image';

const font = (weight: number) =>
  readFileSync(createRequire(import.meta.url).resolve(`@fontsource/public-sans/files/public-sans-latin-${weight}-normal.woff`));

describe('renderOgImage', () => {
  it('draws a 1200×630 PNG', async () => {
    const png = await renderOgImage(
      { kicker: 'Blog', title: 'Passkeys erklärt: So funktioniert WebAuthn', byline: 'David Neuy · 15. Oktober 2026' },
      { regular: font(400), bold: font(700) },
    );
    expect(png.subarray(1, 4).toString('latin1')).toBe('PNG');
    // The IHDR chunk: width and height as big-endian 32-bit integers.
    expect([png.readUInt32BE(16), png.readUInt32BE(20)]).toEqual([OG_WIDTH, OG_HEIGHT]);
  });
});
