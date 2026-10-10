import { describe, expect, it } from 'vitest';
import { encode } from 'uqr';
import { qrModules, qrSvg, qrViewBox } from './qr.js';

const uri = 'otpauth://totp/app.example.com:grace%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=app.example.com&algorithm=SHA1&digits=6&period=30';

describe('the QR code', () => {
  it('Q1: draws every dark module of the code, with the finder patterns in the corners', () => {
    const { size, d } = qrModules(uri);

    // A QR code of version v has 17 + 4v modules per side.
    expect((size - 17) % 4).toBe(0);
    expect(size).toBeGreaterThanOrEqual(25);
    // The finder patterns: a dark 7×7 frame in three corners, with a light ring inside it.
    for (const [x, y] of [
      [0, 0],
      [6, 0],
      [0, 6],
      [3, 3],
      [size - 7, 0],
      [0, size - 7],
    ]) {
      expect(d).toContain(`M${x} ${y}h1v1h-1z`);
    }
    expect(d).not.toContain('M1 1h1v1h-1z');
    // The dark module next to the bottom-left finder pattern, which every code has.
    expect(d).toContain(`M8 ${size - 8}h1v1h-1z`);
  });

  it('Q2: matches the encoder module by module', () => {
    const { size, d } = qrModules(uri);
    const { data } = encode(uri, { ecc: 'M', border: 0 });
    const drawn = new Set([...d.matchAll(/M(\d+) (\d+)h1v1h-1z/g)].map(([, x, y]) => `${x},${y}`));

    let dark = 0;
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        expect(drawn.has(`${x},${y}`)).toBe(data[y][x]);
        if (data[y][x]) dark++;
      }
    }
    expect(drawn.size).toBe(dark);
  });

  it('Q3: the SVG has one path in the current color, and a quiet zone around the code', () => {
    const svg = new DOMParser().parseFromString(qrSvg(uri), 'image/svg+xml').documentElement;
    const { size } = qrModules(uri);

    expect(svg.tagName).toBe('svg');
    expect(svg.getAttribute('viewBox')).toBe(qrViewBox(size));
    expect(svg.getAttribute('role')).toBe('img');
    expect(svg.querySelectorAll('path')).toHaveLength(1);
    expect(svg.querySelector('path')!.getAttribute('fill')).toBe('currentColor');
    expect(svg.querySelector('rect')).toBeNull();
    expect(qrViewBox(21)).toBe('-4 -4 29 29');
  });
});
